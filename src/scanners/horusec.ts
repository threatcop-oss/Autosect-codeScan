/**
 * Horusec SCR (Source Code Review) scanner.
 * Runs horusec start -p <path> --disable-docker and parses text output into findings.
 */
import path from 'path';
import crypto from 'crypto';
import { Scanner, ScannerContext, ScannerResult } from './types.js';
import { runCommand } from './runner.js';
import { normalizeSeverity } from '../utils/severity.js';
import { isExcluded } from '../utils/paths.js';
import { Finding } from '../types.js';

const EXPECTED_KEYS = [
  'Language',
  'Severity',
  'Line',
  'Column',
  'SecurityTool',
  'Confidence',
  'File',
  'Code',
  'RuleID',
  'Type',
  'ReferenceHash',
  'Details'
];
const KEY_REGEX = new RegExp(`^(${EXPECTED_KEYS.join('|')}): `);
const STOP_DETAIL_REGEX = /Possible vulnerability detected:/;

interface HorusecVuln {
  Language?: string;
  Severity?: string;
  Line?: string;
  Column?: string;
  SecurityTool?: string;
  Confidence?: string;
  File?: string;
  Code?: string;
  RuleID?: string;
  Type?: string;
  ReferenceHash?: string;
  Details?: string;
}

function processAndAssignDetails(detailLines: string[], vulnerability: HorusecVuln): void {
  let details = detailLines.join('\n');
  const lastIndex = details.lastIndexOf('Possible vulnerability detected:');
  if (lastIndex > -1) {
    const newlineBefore = details.lastIndexOf('\n', lastIndex);
    details = newlineBefore > -1 ? details.substring(0, newlineBefore) : details.substring(0, lastIndex);
  }
  vulnerability.Details = details;
}

function parseHorusecOutput(output: string): HorusecVuln[] {
  const vulnerabilities: HorusecVuln[] = [];
  const sections = output.split('==================================================================================');

  for (const section of sections) {
    const vulnerability: HorusecVuln = {};
    const lines = section.trim().split('\n');
    let detailLines: string[] = [];
    let collectingDetails = false;

    for (const line of lines) {
      const match = line.match(KEY_REGEX);
      if (match) {
        const key = match[1] as keyof HorusecVuln;
        const value = line.substring(match[0].length).trim();

        if (key === 'Details') {
          collectingDetails = true;
          detailLines.push(value.replace(/^\(\d+\/\d+\) \* Possible vulnerability detected: /, ''));
        } else {
          if (collectingDetails) {
            processAndAssignDetails(detailLines, vulnerability);
            detailLines = [];
            collectingDetails = false;
          }
          (vulnerability as Record<string, string>)[key] = value;
        }
      } else if (collectingDetails) {
        if (STOP_DETAIL_REGEX.test(line)) {
          processAndAssignDetails(detailLines, vulnerability);
          collectingDetails = false;
        } else {
          detailLines.push(line.trim());
        }
      }
    }

    if (collectingDetails && detailLines.length > 0) {
      processAndAssignDetails(detailLines, vulnerability);
    }

    if (Object.keys(vulnerability).length > 0) {
      vulnerabilities.push(vulnerability);
    }
  }

  return vulnerabilities;
}

function mapFinding(item: HorusecVuln, targetPath: string): Finding {
  const idSource = `${item.RuleID ?? ''}-${item.File ?? ''}-${item.Line ?? ''}-${item.Type ?? ''}`;
  const id = crypto.createHash('sha256').update(idSource).digest('hex');

  const lineNum = item.Line != null && item.Line !== '' ? parseInt(item.Line, 10) : undefined;
  const colNum = item.Column != null && item.Column !== '' ? parseInt(item.Column, 10) : undefined;

  const title = item.Type && item.RuleID ? `${item.Type}+${item.RuleID}` : item.RuleID ?? item.Type ?? 'Horusec finding';
  const filePath = item.File ?? 'unknown';

  return {
    id,
    tool: 'horusec',
    severity: normalizeSeverity(item.Severity ?? 'medium'),
    category: 'code-quality',
    title,
    description: item.Details ?? item.Type ?? 'Horusec security finding',
    file: path.isAbsolute(filePath) ? filePath : path.join(targetPath, filePath),
    line: Number.isFinite(lineNum) ? lineNum : undefined,
    column: Number.isFinite(colNum) ? colNum : undefined,
    confidence: item.Confidence as 'high' | 'medium' | 'low' | undefined,
    remediation: item.Details ?? undefined,
    references: item.ReferenceHash ? [item.ReferenceHash] : undefined,
    metadata: {
      language: item.Language,
      securityTool: item.SecurityTool,
      code: item.Code
    }
  };
}

export const horusecScanner: Scanner = {
  name: 'horusec',
  async run(context: ScannerContext): Promise<ScannerResult> {
    const args = ['start', '-p', '.', '--disable-docker'];

    if (context.config.scanners.horusec.args?.length) {
      args.push(...context.config.scanners.horusec.args);
    }

    const result = await runCommand('horusec', args, {
      cwd: context.targetPath,
      logger: context.logger,
      verbose: context.options.verbose
    });

    if (result.exitCode > 1) {
      return {
        tool: 'horusec',
        findings: [],
        errors: [
          {
            tool: 'horusec',
            message: 'Horusec execution failed',
            details: result.stderr || result.stdout
          }
        ]
      };
    }

    const raw = (result.stdout || result.stderr || '').trim();
    const parsed = parseHorusecOutput(raw);
    const findings: Finding[] = parsed.map((item) => mapFinding(item, context.targetPath));

    const incrementalSet = context.incrementalFiles
      ? new Set(context.incrementalFiles.map((f) => path.resolve(f)))
      : undefined;

    const filtered = findings.filter((finding) => {
      if (isExcluded(finding.file, context.excludePaths, context.targetPath)) return false;
      if (incrementalSet) return incrementalSet.has(path.resolve(finding.file));
      return true;
    });

    return {
      tool: 'horusec',
      findings: filtered
    };
  }
};
