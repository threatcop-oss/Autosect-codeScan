import os from 'os';
import path from 'path';
import fs from 'fs-extra';
import crypto from 'crypto';
import { Scanner, ScannerContext, ScannerResult } from './types.js';
import { runCommand } from './runner.js';
import { normalizeSeverity } from '../utils/severity.js';
import { extractCvesFromSources } from '../utils/cve.js';
import { isExcluded } from '../utils/paths.js';
import { Finding } from '../types.js';

const mapFinding = (item: Record<string, any>): Finding => {
  const idSource = item.Fingerprint ?? `${item.RuleID}-${item.File}-${item.StartLine}`;
  const id = crypto.createHash('sha256').update(idSource).digest('hex');

  const cves = extractCvesFromSources(item.RuleID, item.Description, item.Tags);

  return {
    id,
    tool: 'gitleaks',
    severity: normalizeSeverity(item.Severity ?? 'high'),
    category: 'secret',
    title: item.RuleID || 'Gitleaks finding',
    description: item.Description || 'Potential secret detected',
    file: item.File ?? 'unknown',
    line: item.StartLine,
    column: undefined,
    cve: cves.length ? cves.join(',') : undefined,
    remediation: 'Remove the secret and rotate affected credentials.',
    references: item.Commit ? [`commit:${item.Commit}`] : undefined,
    metadata: {
      match: item.Match,
      secret: item.Secret
    }
  };
};

const parseFindingsArray = (data: unknown): Record<string, any>[] => {
  if (Array.isArray(data)) {
    return data;
  }
  if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>;
    const arr = obj.findings ?? obj.results ?? obj.Findings ?? obj.Results;
    return Array.isArray(arr) ? arr : [];
  }
  return [];
};

const isGitRepo = (dir: string): boolean => {
  try {
    const gitDir = path.join(path.resolve(dir), '.git');
    return fs.existsSync(gitDir) && fs.statSync(gitDir).isDirectory();
  } catch {
    return false;
  }
};

export const gitleaksScanner: Scanner = {
  name: 'gitleaks',
  async run(context: ScannerContext): Promise<ScannerResult> {
    // Skip when target is not a git repo (e.g. Downloads, single manifest dir) to avoid scanning huge folders
    if (!isGitRepo(context.targetPath)) {
      return {
        tool: 'gitleaks',
        findings: [],
        errors: [{ tool: 'gitleaks', message: 'Skipped (target is not a git repository)' }]
      };
    }

    const reportPath = path.join(os.tmpdir(), `gitleaks-report-${Date.now()}-${process.pid}.json`);
    // --no-git: scan files in the directory (not just git history); --source . with cwd = targetPath
    const args = ['detect', '--no-git', '--source', '.', '--report-format', 'json', '--report-path', reportPath];

    if (context.config.scanners.gitleaks.config) {
      args.push('--config', context.config.scanners.gitleaks.config);
    }

    if (context.config.scanners.gitleaks.args) {
      args.push(...context.config.scanners.gitleaks.args);
    }

    const result = await runCommand('gitleaks', args, {
      cwd: context.targetPath,
      logger: context.logger,
      verbose: context.options.verbose
    });

    if (result.exitCode > 1) {
      return {
        tool: 'gitleaks',
        findings: [],
        errors: [
          {
            tool: 'gitleaks',
            message: 'Gitleaks execution failed',
            details: result.stderr || result.stdout
          }
        ]
      };
    }

    let rawList: Record<string, any>[] = [];
    const reportExisted = await fs.pathExists(reportPath);
    if (reportExisted) {
      try {
        const content = await fs.readJson(reportPath);
        rawList = parseFindingsArray(content);
      } catch {
        rawList = [];
      }
      await fs.remove(reportPath).catch(() => {});
    }
    if (rawList.length === 0 && result.stdout?.trim()) {
      try {
        rawList = parseFindingsArray(JSON.parse(result.stdout) as unknown);
      } catch {
        // ignore
      }
    }
    const stderrTrim = result.stderr?.trim() ?? '';
    if (rawList.length === 0 && stderrTrim && (stderrTrim.startsWith('[') || stderrTrim.startsWith('{'))) {
      try {
        rawList = parseFindingsArray(JSON.parse(result.stderr!) as unknown);
      } catch {
        // ignore
      }
    }

    if (context.options.verbose && context.logger) {
      context.logger.debug(
        {
          exitCode: result.exitCode,
          reportPath,
          reportExisted,
          stdoutLength: result.stdout?.length ?? 0,
          stderrLength: result.stderr?.length ?? 0,
          rawFindings: rawList.length
        },
        'Gitleaks output'
      );
    }

    const findings = rawList.map(mapFinding);
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

    return {
      tool: 'gitleaks',
      findings: filtered
    };
  },
  async update(context: ScannerContext): Promise<void> {
    await runCommand('gitleaks', ['version'], {
      logger: context.logger,
      verbose: context.options.verbose
    });
  }
};
