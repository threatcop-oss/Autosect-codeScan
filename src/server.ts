/**
 * Code-scanner server with ZIP support.
 * Copy this logic into your code-scanner repo's server.
 * When path points to a .zip file (or body.isZip === true), the zip is extracted
 * to a temp dir and the scan runs on the extracted folder.
 *
 * Dependencies: add "adm-zip" in the code-scanner project:  npm install adm-zip
 */
import 'dotenv/config';
import http from 'http';
import path from 'path';
import os from 'os';
import fs from 'fs-extra';
import AdmZip from 'adm-zip';
import { loadConfig, applyCliOptions } from './config/index.js';
import { runScan } from './orchestrator.js';
import { writeReport, formatReport } from './reporters/index.js';
import { createLogger } from './logger.js';
import { isS3UploadEnabled, uploadReportToS3 } from './s3reports.js';
import { resolveScanTarget } from './utils/paths.js';
import type { ScanOptions, ScanReport, OutputFormat } from './types.js';

const PORT = Number(process.env.PORT) || 3042;

const parseBody = (req: http.IncomingMessage): Promise<Record<string, unknown>> => {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) {
        return resolve({});
      }
      try {
        resolve(JSON.parse(raw) as Record<string, unknown>);
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
};

const send = (res: http.ServerResponse, status: number, body: string, contentType: string) => {
  res.writeHead(status, { 'Content-Type': contentType });
  res.end(body);
};

const sendJson = (res: http.ServerResponse, status: number, data: object) => {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
};

/** Extract a zip file to a temp directory. Returns the temp dir path. Caller must clean up. */
const extractZipToTemp = (zipPath: string): string => {
  const resolvedZip = path.resolve(zipPath);
  if (!fs.pathExistsSync(resolvedZip)) {
    throw new Error(`Zip file does not exist: ${resolvedZip}`);
  }
  const tempDir = path.join(os.tmpdir(), `sca-scan-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`);
  fs.ensureDirSync(tempDir);
  const zip = new AdmZip(resolvedZip);
  zip.extractAllTo(tempDir, true);
  return tempDir;
};

/** Find first manifest/lock file in dir or subdirs; if none, return dir (any file type is scanned). */
const findManifestInDir = (dir: string): string => {
  const names = [
    'pom.xml', 'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'requirements.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock',
    'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock',
    'build.gradle', 'build.gradle.kts', 'Gemfile', 'Gemfile.lock'
  ];
  const tryFind = (d: string, depth: number): string | null => {
    if (depth > 3) return null;
    for (const name of names) {
      const full = path.join(d, name);
      if (fs.pathExistsSync(full)) return full;
    }
    const entries = fs.readdirSync(d, { withFileTypes: true });
    for (const e of entries) {
      if (e.isDirectory() && !e.name.startsWith('.')) {
        const found = tryFind(path.join(d, e.name), depth + 1);
        if (found) return found;
      }
    }
    return null;
  };
  return tryFind(dir, 0) ?? dir;
};

const runScanForPath = async (
  filePath: string,
  format: OutputFormat = 'json'
): Promise<{ report: ScanReport; rendered: string }> => {
  const resolved = path.resolve(filePath);
  const target = resolveScanTarget(resolved);
  const isNonManifestFile =
    (await fs.pathExists(resolved)) &&
    (await fs.stat(resolved).then((s) => s.isFile())) &&
    target.manifestPath === undefined;

  const options: ScanOptions = {
    targetPath: target.targetPath,
    manifestPath: isNonManifestFile ? null : target.manifestPath,
    manifestType: isNonManifestFile && !target.lockFilePath ? undefined : target.manifestType,
    lockFilePath: target.lockFilePath,
    format,
    parallel: true,
    quiet: true,
    noCache: true
  };

  if (!(await fs.pathExists(options.targetPath))) {
    throw new Error(`Path does not exist: ${options.targetPath}`);
  }
  if (options.manifestPath != null && options.manifestPath && !(await fs.pathExists(options.manifestPath))) {
    throw new Error(`Manifest does not exist: ${options.manifestPath}`);
  }

  const baseConfig = await loadConfig(undefined, options.targetPath);
  const config = applyCliOptions(baseConfig, options);
  const logger = createLogger({ verbose: true, quiet: false });
  const report = await runScan(config, options, logger);
  const rendered = await formatReport(report, format);
  return { report, rendered };
};

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) {
    sendJson(res, 200, { ok: true, service: 'code-scanner', version: '0.1.0' });
    return;
  }

  if (req.method === 'POST' && req.url === '/scan') {
    let body: Record<string, unknown>;
    try {
      body = await parseBody(req);
    } catch (e) {
      sendJson(res, 400, { error: e instanceof Error ? e.message : 'Invalid JSON body' });
      return;
    }

    const filePath = body.path ?? body.file;
    if (typeof filePath !== 'string' || !filePath.trim()) {
      sendJson(res, 400, { error: 'Missing or invalid "path" (file path to scan)' });
      return;
    }

    const pathToScan = filePath.trim();
    const isZip = body.isZip === true || pathToScan.toLowerCase().endsWith('.zip');
    let scanPath = pathToScan;
    let tempDir: string | null = null;

    if (isZip) {
      console.log(`[scan] zip detected, extracting: ${pathToScan}`);
      try {
        tempDir = extractZipToTemp(pathToScan);
        scanPath = findManifestInDir(tempDir);
        console.log(`[scan] extracted to ${tempDir}, scanning: ${scanPath}`);
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        sendJson(res, 400, { error: 'Failed to extract zip', details: message });
        if (tempDir) fs.removeSync(tempDir);
        return;
      }
    } else {
      console.log(`[scan] received path (any file/dir): ${pathToScan}`);
    }

    const scanId = body.scanId != null ? String(body.scanId) : undefined;
    const format = 'json' as OutputFormat;

    try {
      const { report, rendered } = await runScanForPath(scanPath, format);
      const htmlRendered = await formatReport(report, 'html');

      const consoleReport = await formatReport(report, 'console');
      console.log('\n' + consoleReport + '\n');

      let s3KeyJson: string | undefined;
      let s3KeyHtml: string | undefined;
      if (isS3UploadEnabled()) {
        try {
          console.log('[scan] S3 upload starting (JSON + HTML)...');
          s3KeyJson = await uploadReportToS3(rendered, scanId, 'json');
          s3KeyHtml = await uploadReportToS3(htmlRendered, scanId, 'html');
          console.log(`[scan] S3 upload success: ${s3KeyJson}, ${s3KeyHtml}`);
        } catch (e) {
          const err = e instanceof Error ? e : new Error(String(e));
          console.error('[scan] S3 upload failed:', err.message);
          if (err.stack) console.error('[scan] S3 error stack:', err.stack);
        }
      } else {
        console.log('[scan] S3 upload skipped (BUCKET_NAME, BUCKET_REGION, ACCESS_KEY, SECRET_ACCESS_KEY not set or .env not loaded)');
      }

      console.log(scanId ? `[scan] scanId ${scanId} scan completed` : '[scan] scan completed');

      if (s3KeyJson) res.setHeader('X-S3-Key', s3KeyJson);
      if (s3KeyHtml) res.setHeader('X-S3-Key-Html', s3KeyHtml);
      sendJson(res, 200, {
        ok: true,
        summary: report.summary,
        findingsCount: report.findings.length,
        s3Key: s3KeyJson ?? undefined,
        s3KeyHtml: s3KeyHtml ?? undefined,
        report
      });
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      sendJson(res, 500, { error: 'Scan failed', details: message });
    } finally {
      if (tempDir) {
        try {
          fs.removeSync(tempDir);
        } catch (_) {
          console.warn('[scan] could not remove temp dir:', tempDir);
        }
      }
    }
    return;
  }

  sendJson(res, 404, {
    error: 'Not found. Use POST /scan with body: { "path": "/path/to/file-or-dir-or.zip" }. Accepts any file type or zip.'
  });
});

server.listen(PORT, () => {
  console.log(`Code-scanner API listening on http://localhost:${PORT}`);
  console.log('  POST /scan  body: { "path": "...", "scanId": "optional" }');
  console.log('  Accepts any file type or .zip: single file, directory, or zip (extracted then scanned).');
  console.log('  JSON report uploaded to S3 (no local saving). With scanId: report/security-report-{scanId}.json');
});
