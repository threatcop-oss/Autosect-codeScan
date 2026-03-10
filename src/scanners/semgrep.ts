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
  const idSource = `${item.check_id}-${item.path}-${item.start?.line}`;
  const id = crypto.createHash('sha256').update(idSource).digest('hex');
  const metadata = item.extra?.metadata ?? {};

  const references = Array.isArray(metadata.references)
    ? metadata.references
    : metadata.references
      ? [metadata.references]
      : [];
  const cves = extractCvesFromSources(metadata.cve, metadata.cves, references, item.extra?.message);

  return {
    id,
    tool: 'semgrep',
    severity: normalizeSeverity(item.extra?.severity ?? 'medium'),
    category: 'code-quality',
    title: item.check_id || 'Semgrep finding',
    description: item.extra?.message || 'Semgrep finding',
    file: item.path,
    line: item.start?.line,
    column: item.start?.col,
    cwe: metadata.cwe,
    cve: cves.length ? cves.join(',') : undefined,
    confidence: metadata.confidence,
    remediation: metadata.fix,
    references: metadata.references,
    metadata
  };
};

export const semgrepScanner: Scanner = {
  name: 'semgrep',
  async run(context: ScannerContext): Promise<ScannerResult> {
    const reportPath = path.join(os.tmpdir(), `semgrep-report-${Date.now()}.json`);
    const args = ['--json', '--output', reportPath, '--metrics', 'off'];

    const config = context.config.scanners.semgrep.config ?? 'auto';
    args.push('--config', config);

    if (context.config.scanners.semgrep.rules?.length) {
      for (const rule of context.config.scanners.semgrep.rules) {
        args.push('--config', rule);
      }
    }

    for (const pattern of context.excludePatterns) {
      args.push('--exclude', pattern);
    }

    if (context.config.scanners.semgrep.args) {
      args.push(...context.config.scanners.semgrep.args);
    }

    const scanTargets = context.options.incremental && context.incrementalFiles?.length
      ? context.incrementalFiles
      : [context.targetPath];
    args.push(...scanTargets);

    const result = await runCommand('semgrep', args, {
      cwd: context.targetPath,
      logger: context.logger,
      verbose: context.options.verbose
    });

    if (result.exitCode > 1) {
      return {
        tool: 'semgrep',
        findings: [],
      };
    }

    const raw = (await fs.pathExists(reportPath))
      ? await fs.readJson(reportPath)
      : { results: [] };
    const findings: Finding[] = (raw.results ?? []).map(mapFinding);
    const filtered = findings.filter(
      (finding) => !isExcluded(finding.file, context.excludePaths, context.targetPath)
    );

    await fs.remove(reportPath);

    return {
      tool: 'semgrep',
      findings: filtered
    };
  },
  async update(context: ScannerContext): Promise<void> {
    await runCommand('semgrep', ['--version'], {
      logger: context.logger,
      verbose: context.options.verbose
    });
  }
};
