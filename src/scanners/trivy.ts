import os from 'os';
import path from 'path';
import fs from 'fs-extra';
import crypto from 'crypto';
import { Scanner, ScannerContext, ScannerResult } from './types.js';
import { runCommand } from './runner.js';
import { normalizeSeverity } from '../utils/severity.js';
import { extractCvesFromSources } from '../utils/cve.js';
import { isExcluded, getPrefixedPackageLockPath } from '../utils/paths.js';
import { Finding } from '../types.js';

const mapVulnerability = (item: Record<string, any>, target: string): Finding => {
  const idSource = `${item.VulnerabilityID}-${target}-${item.PkgName}`;
  const id = crypto.createHash('sha256').update(idSource).digest('hex');
  const cvssEntry = item.CVSS ? (Object.values(item.CVSS)[0] as { V3Score?: number }) : undefined;
  const cvss = cvssEntry?.V3Score;

  const cves = extractCvesFromSources(item.VulnerabilityID, item.Title, item.PrimaryURL);

  return {
    id,
    tool: 'trivy',
    severity: normalizeSeverity(item.Severity),
    category: 'vulnerability',
    title: item.Title || item.VulnerabilityID,
    description: item.Description || 'Trivy vulnerability',
    file: target,
    cve: cves.length ? cves.join(',') : undefined,
    cvss,
    installedVersion: item.InstalledVersion,
    fixedVersion: item.FixedVersion,
    remediation: item.FixedVersion ? `Upgrade to ${item.FixedVersion}` : undefined,
    references: item.PrimaryURL ? [item.PrimaryURL] : undefined,
    metadata: {
      package: item.PkgName,
      installedVersion: item.InstalledVersion,
      fixedVersion: item.FixedVersion
    }
  };
};

const mapMisconfiguration = (item: Record<string, any>, target: string): Finding => {
  const idSource = `${item.ID}-${target}-${item.Title}`;
  const id = crypto.createHash('sha256').update(idSource).digest('hex');

  return {
    id,
    tool: 'trivy',
    severity: normalizeSeverity(item.Severity),
    category: 'config',
    title: item.Title || item.ID,
    description: item.Description || 'Trivy configuration issue',
    file: item.CauseMetadata?.Resource || target,
    line: item.CauseMetadata?.StartLine,
    remediation: item.Recommendation || item.PrimaryURL,
    references: item.PrimaryURL ? [item.PrimaryURL] : undefined,
    metadata: item
  };
};

export const trivyScanner: Scanner = {
  name: 'trivy',
  async run(context: ScannerContext): Promise<ScannerResult> {
    const reportPath = path.join(os.tmpdir(), `trivy-report-${Date.now()}.json`);
    const useOutputFile = !context.options.manifestType;
    const args = ['fs', '--format', 'json'];
    if (useOutputFile) {
      args.push('--output', reportPath);
    }

    if (context.config.scanners.trivy.severity) {
      args.push('--severity', context.config.scanners.trivy.severity);
    }

    if (context.options.manifestType) {
      args.push('--scanners', 'vuln');
    }

    if (context.options.verbose) {
      args.push('--debug');
    }

    if (context.config.scanners.trivy.vulnType) {
      args.push('--vuln-type', context.config.scanners.trivy.vulnType);
    }

    if (context.config.scanners.trivy.config) {
      args.push('--config', context.config.scanners.trivy.config);
    }

    if (context.config.scanners.trivy.args) {
      args.push(...context.config.scanners.trivy.args);
    }

    let scanTarget = context.options.manifestPath ?? context.targetPath;
    let cwd = context.targetPath;
    let tempDir: string | undefined;

    if (context.options.manifestType === 'maven' && context.options.manifestPath) {
      // Maven resolution can be slow/intermittent; use a longer timeout to reduce false zero-result scans.
      if (!args.includes('--timeout')) {
        args.push('--timeout', process.env.TRIVY_TIMEOUT ?? '10m');
      }
      const manifestBase = path.basename(context.options.manifestPath);
      if (manifestBase !== 'pom.xml') {
        tempDir = path.join(os.tmpdir(), `trivy-maven-${Date.now()}-${process.pid}`);
        await fs.ensureDir(tempDir);
        await fs.copy(context.options.manifestPath, path.join(tempDir, 'pom.xml'));
        scanTarget = tempDir;
        cwd = tempDir;
      } else {
        scanTarget = context.options.manifestPath;
        cwd = path.dirname(context.options.manifestPath);
      }
    } else if (context.options.manifestType === 'npm') {
      const lockOnly =
        context.options.lockFilePath &&
        (await fs.pathExists(context.options.lockFilePath)) &&
        !context.options.manifestPath;
      if (lockOnly) {
        tempDir = path.join(os.tmpdir(), `trivy-npm-${Date.now()}-${process.pid}`);
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
        scanTarget = tempDir;
        cwd = tempDir;
      } else if (context.options.manifestPath) {
        const manifestBase = path.basename(context.options.manifestPath);
        if (manifestBase !== 'package.json') {
          tempDir = path.join(os.tmpdir(), `trivy-npm-${Date.now()}-${process.pid}`);
          await fs.ensureDir(tempDir);
          await fs.copy(context.options.manifestPath, path.join(tempDir, 'package.json'));
          if (context.options.lockFilePath && (await fs.pathExists(context.options.lockFilePath))) {
            await fs.copy(context.options.lockFilePath, path.join(tempDir, 'package-lock.json'));
          } else {
            const prefixedLock = getPrefixedPackageLockPath(context.options.manifestPath, context.targetPath);
            if (await fs.pathExists(prefixedLock)) {
              await fs.copy(prefixedLock, path.join(tempDir, 'package-lock.json'));
            }
          }
          scanTarget = tempDir;
          cwd = tempDir;
        } else {
          scanTarget = context.options.manifestPath;
          cwd = path.dirname(context.options.manifestPath);
        }
      } else {
        scanTarget = context.targetPath;
      }
    }

    // trivy fs requires PATH; pass scan target explicitly
    args.push(scanTarget);

    const result = await runCommand('trivy', args, {
      cwd,
      logger: context.logger,
      verbose: context.options.verbose
    });

    if (tempDir) {
      await fs.remove(tempDir).catch(() => {});
    }

    if (context.options.verbose && result.stderr) {
      context.logger.debug({ stderr: result.stderr }, 'Trivy stderr output');
    }

    if (result.exitCode !== 0) {
      return {
        tool: 'trivy',
        findings: [],
        errors: [
          {
            tool: 'trivy',
            message: `Trivy execution failed (exit code ${result.exitCode})`,
            details: result.stderr || result.stdout
          }
        ]
      };
    }

    let raw: Record<string, any> | Record<string, any>[] = { Results: [] };
    if (useOutputFile && (await fs.pathExists(reportPath))) {
      raw = await fs.readJson(reportPath);
    } else if (result.stdout) {
      try {
        raw = JSON.parse(result.stdout) as Record<string, any> | Record<string, any>[];
      } catch {
        raw = { Results: [] };
      }
    }
    const findings: Finding[] = [];

    let results = Array.isArray(raw)
      ? raw
      : raw.Results ?? raw.results ?? raw.Report?.Results ?? raw.report?.results ?? [];
    if (results.length === 0 && result.stdout) {
      try {
        const parsed = JSON.parse(result.stdout) as Record<string, any> | Record<string, any>[];
        results = Array.isArray(parsed)
          ? parsed
          : parsed.Results ?? parsed.results ?? parsed.Report?.Results ?? parsed.report?.results ?? results;
      } catch {
        // ignore JSON parse fallback
      }
    }
    if (results.length === 0 && result.stderr?.trim().startsWith('{')) {
      try {
        const parsed = JSON.parse(result.stderr) as Record<string, any> | Record<string, any>[];
        results = Array.isArray(parsed)
          ? parsed
          : parsed.Results ?? parsed.results ?? parsed.Report?.Results ?? parsed.report?.results ?? results;
      } catch {
        // ignore JSON parse fallback
      }
    }
    for (const resultItem of results) {
      const target = resultItem.Target ?? resultItem.target ?? scanTarget;
      const vulnerabilities = resultItem.Vulnerabilities ?? resultItem.vulnerabilities ?? [];
      const misconfigurations =
        resultItem.Misconfigurations ?? resultItem.misconfigurations ?? [];
      for (const vuln of vulnerabilities) {
        findings.push(mapVulnerability(vuln, target));
      }
      const packages = resultItem.Packages ?? resultItem.packages ?? [];
      for (const pkg of packages) {
        const pkgVulns = pkg.Vulnerabilities ?? pkg.vulnerabilities ?? [];
        for (const vuln of pkgVulns) {
          findings.push(mapVulnerability(vuln, target));
        }
      }
      for (const misconfig of misconfigurations) {
        findings.push(mapMisconfiguration(misconfig, target));
      }
    }

    if (context.options.verbose) {
      const rawKeys = raw && !Array.isArray(raw) ? Object.keys(raw) : undefined;
      const reportExists = useOutputFile ? await fs.pathExists(reportPath) : false;
      context.logger.info(
        {
          resultCount: results.length,
          findingCount: findings.length,
          rawKeys,
          reportPath,
          reportExists,
          useOutputFile
        },
        'Parsed Trivy results'
      );
    }

    const incrementalSet = context.incrementalFiles
      ? new Set(context.incrementalFiles.map((file) => path.resolve(file)))
      : undefined;
    const filtered = findings.filter((finding) => {
      if (isExcluded(finding.file, context.excludePaths, context.targetPath)) {
        return false;
      }
      if (incrementalSet) {
        return incrementalSet.has(path.resolve(finding.file));
      }
      return true;
    });

    if (useOutputFile) {
      await fs.remove(reportPath);
    }

    return {
      tool: 'trivy',
      findings: filtered
    };
  },
  async update(context: ScannerContext): Promise<void> {
    await runCommand('trivy', ['--download-db-only'], {
      logger: context.logger,
      verbose: context.options.verbose
    });
  }
};
