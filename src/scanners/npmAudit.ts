import crypto from 'crypto';
import os from 'os';
import path from 'path';
import fs from 'fs-extra';
import { Scanner, ScannerContext, ScannerResult } from './types.js';
import { runCommand } from './runner.js';
import { normalizeSeverity } from '../utils/severity.js';
import { extractCvesFromSources } from '../utils/cve.js';
import { getPrefixedPackageLockPath } from '../utils/paths.js';
import { Finding } from '../types.js';

const collectVia = (advisory: Record<string, any>): Array<string | string[]> => {
  const via = advisory.via ?? [];
  if (!Array.isArray(via)) {
    return [];
  }
  const sources: Array<string | string[]> = [];
  for (const entry of via) {
    if (typeof entry === 'string') {
      sources.push(entry);
    } else if (entry && typeof entry === 'object') {
      sources.push(entry.cve, entry.cves, entry.title, entry.url, JSON.stringify(entry));
    }
  }
  return sources;
};

const mapAdvisory = (name: string, advisory: Record<string, any>, targetPath: string): Finding => {
  const idSource = `${name}-${advisory.source ?? advisory.title}`;
  const id = crypto.createHash('sha256').update(idSource).digest('hex');
  const cves = extractCvesFromSources(
    advisory.cve,
    advisory.cves,
    advisory.title,
    advisory.url,
    advisory.id,
    advisory.references,
    JSON.stringify(advisory),
    ...collectVia(advisory)
  );

  return {
    id,
    tool: 'npm-audit',
    severity: normalizeSeverity(advisory.severity ?? 'medium'),
    category: 'vulnerability',
    title: advisory.title || name,
    description: advisory.url || advisory.title || 'npm audit vulnerability',
    file: path.join(targetPath, 'package.json'),
    cve: cves.length ? cves.join(',') : undefined,
    remediation: advisory.fixAvailable
      ? `Upgrade to ${advisory.fixAvailable.name ?? name}`
      : undefined,
    references: advisory.url ? [advisory.url] : undefined,
    metadata: advisory
  };
};

export const npmAuditScanner: Scanner = {
  name: 'npm-audit',
  async run(context: ScannerContext): Promise<ScannerResult> {
    if (context.options.manifestType === 'maven') {
      return { tool: 'npm-audit', findings: [] };
    }
    const defaultManifest = path.join(context.targetPath, 'package.json');
    const manifestPath = context.options.manifestPath ?? defaultManifest;
    const manifestExists = await fs.pathExists(manifestPath);
    const lockOnly = context.options.lockFilePath && (await fs.pathExists(context.options.lockFilePath));

    if (!manifestExists && !lockOnly) {
      return {
        tool: 'npm-audit',
        findings: [],
        errors: [
          {
            tool: 'npm-audit',
            message: `package.json not found at ${manifestPath} and no lock file path provided`
          }
        ]
      };
    }

    let cwd = context.targetPath;
    let tempDir: string | undefined;
    const manifestBase = manifestExists ? path.basename(manifestPath) : '';

    if (lockOnly) {
      tempDir = path.join(os.tmpdir(), `npm-audit-${Date.now()}-${process.pid}`);
      await fs.ensureDir(tempDir);
      await fs.copy(context.options.lockFilePath!, path.join(tempDir, 'package-lock.json'));
      let pkg: { name?: string; version?: string } = { name: 'sca-scan', version: '0.0.0' };
      try {
        const lockContent = await fs.readJson(context.options.lockFilePath!);
        if (lockContent.name || lockContent.version) {
          pkg = { name: lockContent.name ?? pkg.name, version: lockContent.version ?? pkg.version };
        }
      } catch {
        // use default
      }
      await fs.writeJson(path.join(tempDir, 'package.json'), pkg, { spaces: 2 });
      cwd = tempDir;
      console.log('[npm-audit] Using lock file only: ' + path.basename(context.options.lockFilePath!));
    } else if (
      manifestBase !== 'package.json' &&
      (manifestBase.toLowerCase().includes('package') || manifestBase === 'package.json')
    ) {
      tempDir = path.join(os.tmpdir(), `npm-audit-${Date.now()}-${process.pid}`);
      await fs.ensureDir(tempDir);
      await fs.copy(manifestPath, path.join(tempDir, 'package.json'));
      let hasLock = false;
      if (context.options.lockFilePath && (await fs.pathExists(context.options.lockFilePath))) {
        await fs.copy(context.options.lockFilePath, path.join(tempDir, 'package-lock.json'));
        hasLock = true;
        console.log('[npm-audit] Using lock file: ' + path.basename(context.options.lockFilePath));
      }
      if (!hasLock) {
        const lockNames = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json'];
        for (const name of lockNames) {
          const src = path.join(context.targetPath, name);
          if (await fs.pathExists(src)) {
            await fs.copy(src, path.join(tempDir, name));
            hasLock = true;
          }
        }
      }
      if (!hasLock) {
        const prefixedLock = getPrefixedPackageLockPath(manifestPath, context.targetPath);
        if (await fs.pathExists(prefixedLock)) {
          await fs.copy(prefixedLock, path.join(tempDir, 'package-lock.json'));
          hasLock = true;
          console.log('[npm-audit] Using lock file: ' + path.basename(prefixedLock));
        }
      }
      if (!hasLock) {
        const prefixedName = path.basename(getPrefixedPackageLockPath(manifestPath, context.targetPath));
        console.log(
          '[npm-audit] No lock file (looked for package-lock.json and ' +
            prefixedName +
            '). Generating from package.json — add ' +
            prefixedName +
            ' for accurate vulns.'
        );
        console.log('[npm-audit] Generating package-lock.json (can take 1–2 min)...');
        const installResult = await runCommand('npm', ['install', '--package-lock-only', '--no-audit'], {
          cwd: tempDir,
          logger: context.logger,
          verbose: context.options.verbose
        });
        if (installResult.exitCode !== 0 && context.options.verbose) {
          context.logger.debug({ stderr: installResult.stderr }, 'npm install --package-lock-only (non-fatal for audit)');
        }
      }
      cwd = tempDir;
    }

    const args = ['audit', '--json'];
    if (context.config.scanners.npmAudit.auditLevel) {
      args.push('--audit-level', context.config.scanners.npmAudit.auditLevel);
    }

    if (context.config.scanners.npmAudit.args) {
      args.push(...context.config.scanners.npmAudit.args);
    }

    const result = await runCommand('npm', args, {
      cwd,
      logger: context.logger,
      verbose: context.options.verbose
    });

    if (tempDir) {
      await fs.remove(tempDir).catch(() => {});
    }

    if (result.exitCode > 1) {
      return {
        tool: 'npm-audit',
        findings: [],
        errors: [
          {
            tool: 'npm-audit',
            message: 'npm audit execution failed',
            details: result.stderr || result.stdout
          }
        ]
      };
    }

    let auditJson: Record<string, any> = {};
    try {
      auditJson = JSON.parse(result.stdout || '{}');
    } catch {
      return {
        tool: 'npm-audit',
        findings: [],
        errors: [
          {
            tool: 'npm-audit',
            message: 'Failed to parse npm audit output'
          }
        ]
      };
    }

    const findings: Finding[] = [];
    const vulnerabilities = auditJson.vulnerabilities ?? {};
    for (const [name, advisory] of Object.entries(vulnerabilities)) {
      findings.push(mapAdvisory(name, advisory as Record<string, any>, context.targetPath));
    }

    const advisories = auditJson.advisories ?? {};
    for (const advisory of Object.values(advisories)) {
      const record = advisory as Record<string, any>;
      findings.push(mapAdvisory(record.module_name ?? 'dependency', record, context.targetPath));
    }

    return {
      tool: 'npm-audit',
      findings
    };
  }
};
