/**
 * CodeQL SCR scanner.
 * For each detected language:
 *   1. codeql database create  <dbDir> --language=<lang> [--command=<build>] --source-root <target>
 *   2. codeql database analyze <dbDir> --format=sarifv2.1.0 --output=<sarifFile>
 *        codeql/<lang>-queries:codeql-suites/<lang>-security-extended.qls
 * Parses the SARIF output into Finding[], then cleans up all temp files.
 */

import os from 'os';
import path from 'path';
import fs from 'fs-extra';
import crypto from 'crypto';
import { Scanner, ScannerContext, ScannerResult } from './types.js';
import { runCommand } from './runner.js';
import { normalizeSeverity } from '../utils/severity.js';
import { isExcluded } from '../utils/paths.js';
import { detectLanguages, DetectedLanguage } from '../utils/detectLanguages.js';
import { Finding, Severity, ScanError } from '../types.js';

// ---------------------------------------------------------------------------
// SARIF types (minimal subset for type safety)
// ---------------------------------------------------------------------------

interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  properties?: {
    'security-severity'?: string;
    tags?: string[];
    [key: string]: unknown;
  };
}

interface SarifResult {
  ruleId?: string;
  level?: string; // "error" | "warning" | "note" | "none"
  message: { text?: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: {
        startLine?: number;
        startColumn?: number;
      };
    };
  }>;
}

interface SarifRun {
  tool: {
    driver: {
      rules?: SarifRule[];
    };
  };
  results?: SarifResult[];
}

interface SarifLog {
  runs?: SarifRun[];
}

// ---------------------------------------------------------------------------
// SARIF helpers
// ---------------------------------------------------------------------------

function securitySeverityToLevel(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'info';
}

function extractCweFromTags(tags?: string[]): string[] | undefined {
  if (!tags || tags.length === 0) return undefined;
  const cwes: string[] = [];
  for (const tag of tags) {
    const match = tag.match(/^external\/cwe\/cwe-(\d+)$/);
    if (match) {
      cwes.push(`CWE-${match[1]}`);
    }
  }
  return cwes.length > 0 ? cwes : undefined;
}

// ---------------------------------------------------------------------------
// Finding mapper
// ---------------------------------------------------------------------------

function mapSarifResultToFinding(
  result: SarifResult,
  rule: SarifRule | undefined,
  targetPath: string,
  language: string
): Finding | null {
  const ruleId = result.ruleId || rule?.id || '';
  const location = result.locations?.[0]?.physicalLocation;
  const uri = location?.artifactLocation?.uri;
  const startLine = location?.region?.startLine;
  const startCol = location?.region?.startColumn;

  const idSource = `codeql-${ruleId}-${uri ?? ''}-${startLine ?? ''}`;
  const id = crypto.createHash('sha256').update(idSource).digest('hex');

  // Severity: prefer security-severity score, fallback to result.level
  const secSeverityStr = rule?.properties?.['security-severity'];
  const secSeverityScore = secSeverityStr != null ? parseFloat(secSeverityStr) : NaN;
  const hasSecuritySeverity = !isNaN(secSeverityScore);

  let severity: Severity;
  if (hasSecuritySeverity) {
    severity = securitySeverityToLevel(secSeverityScore);
  } else {
    // Fallback: map result.level via normalizeSeverity
    const level = result.level?.toLowerCase() ?? '';
    const mappedLevel =
      level === 'warning' ? 'medium' :
      level === 'note' ? 'low' :
      level; // "error" passes through to normalizeSeverity → "high"
    severity = normalizeSeverity(mappedLevel);
  }

  const category = hasSecuritySeverity ? 'vulnerability' : 'code-quality';

  const title =
    rule?.shortDescription?.text ||
    rule?.name ||
    rule?.id ||
    'CodeQL finding';

  const description =
    result.message?.text ||
    rule?.fullDescription?.text ||
    'CodeQL security finding';

  const resolvedFile = uri
    ? path.isAbsolute(uri)
      ? uri
      : path.join(targetPath, uri)
    : 'unknown';

  return {
    id,
    tool: 'codeql',
    severity,
    category,
    title,
    description,
    file: resolvedFile,
    line: Number.isFinite(startLine) ? startLine : undefined,
    column: Number.isFinite(startCol) ? startCol : undefined,
    cwe: extractCweFromTags(rule?.properties?.tags),
    cvss: hasSecuritySeverity ? secSeverityScore : undefined,
    metadata: {
      language,
      queryId: ruleId
    }
  };
}

// ---------------------------------------------------------------------------
// SARIF parser
// ---------------------------------------------------------------------------

function parseSarifResults(sarif: SarifLog, targetPath: string, language: string): Finding[] {
  const findings: Finding[] = [];

  for (const run of sarif.runs ?? []) {
    // Build rule lookup map
    const ruleById = new Map<string, SarifRule>();
    for (const rule of run.tool?.driver?.rules ?? []) {
      ruleById.set(rule.id, rule);
    }

    for (const result of run.results ?? []) {
      const rule = result.ruleId ? ruleById.get(result.ruleId) : undefined;
      const finding = mapSarifResultToFinding(result, rule, targetPath, language);
      if (finding) {
        findings.push(finding);
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Per-language scan
// ---------------------------------------------------------------------------

async function scanLanguage(
  lang: DetectedLanguage,
  targetPath: string,
  workDir: string,
  context: ScannerContext
): Promise<{ findings: Finding[]; errors: ScanError[] }> {
  const findings: Finding[] = [];
  const errors: ScanError[] = [];
  const { codeqlName, isCompiled, buildCommand } = lang;

  const dbDir = path.join(workDir, `codeql-db-${codeqlName}`);
  const sarifFile = path.join(workDir, `codeql-results-${codeqlName}.sarif`);

  // -- Step 1: database create --
  const createArgs = [
    'database', 'create', dbDir,
    `--language=${codeqlName}`,
    '--source-root', targetPath,
    '--overwrite'
  ];

  if (isCompiled && buildCommand) {
    createArgs.push(`--command=${buildCommand}`);
  }

  if (context.options.verbose) {
    context.logger.info({ codeqlName, createArgs }, 'CodeQL database create');
  }

  const createResult = await runCommand('codeql', createArgs, {
    cwd: targetPath,
    logger: context.logger,
    verbose: context.options.verbose
  });

  if (createResult.exitCode !== 0) {
    errors.push({
      tool: 'codeql',
      message: `Database creation failed for language: ${codeqlName}`,
      details: createResult.stderr || createResult.stdout
    });
    return { findings, errors };
  }

  // -- Step 2: database analyze --
  const querySuite = `codeql/${codeqlName}-queries:codeql-suites/${codeqlName}-security-extended.qls`;
  const analyzeArgs = [
    'database', 'analyze', dbDir,
    '--format=sarifv2.1.0',
    `--output=${sarifFile}`,
    querySuite
  ];

  if (context.options.verbose) {
    context.logger.info({ codeqlName, analyzeArgs }, 'CodeQL database analyze');
  }

  const analyzeResult = await runCommand('codeql', analyzeArgs, {
    cwd: targetPath,
    logger: context.logger,
    verbose: context.options.verbose
  });

  if (analyzeResult.exitCode !== 0) {
    errors.push({
      tool: 'codeql',
      message: `Database analysis failed for language: ${codeqlName}`,
      details: analyzeResult.stderr || analyzeResult.stdout
    });
    return { findings, errors };
  }

  // -- Step 3: parse SARIF --
  if (!(await fs.pathExists(sarifFile))) {
    // No findings is valid; codeql may not write the file if empty
    return { findings, errors };
  }

  const sarif: SarifLog = await fs.readJson(sarifFile);
  const parsed = parseSarifResults(sarif, targetPath, codeqlName);

  for (const finding of parsed) {
    if (isExcluded(finding.file, context.excludePaths, targetPath)) continue;
    findings.push(finding);
  }

  return { findings, errors };
}

// ---------------------------------------------------------------------------
// Scanner export
// ---------------------------------------------------------------------------

export const codeqlScanner: Scanner = {
  name: 'codeql',

  async run(context: ScannerContext): Promise<ScannerResult> {
    const allFindings: Finding[] = [];
    const allErrors: ScanError[] = [];

    // Detect languages in the target directory
    const languages = await detectLanguages(context.targetPath);

    if (languages.length === 0) {
      return {
        tool: 'codeql',
        findings: [],
        errors: [
          {
            tool: 'codeql',
            message: 'No supported languages detected in target path.'
          }
        ]
      };
    }

    // Create a single temp working directory for all DBs and SARIF files
    const workDir = await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-scan-'));

    try {
      for (const lang of languages) {
        if (lang.isCompiled && !lang.buildCommand) {
          allErrors.push({
            tool: 'codeql',
            message: `Skipping ${lang.codeqlName}: compiled language but no build file detected.`
          });
          continue;
        }

        const { findings, errors } = await scanLanguage(
          lang,
          context.targetPath,
          workDir,
          context
        );

        allFindings.push(...findings);
        allErrors.push(...errors);
      }
    } finally {
      // Always clean up — DBs and SARIF files regardless of success/failure
      await fs.remove(workDir);
    }

    // Apply incremental filter if applicable
    const incrementalSet = context.incrementalFiles
      ? new Set(context.incrementalFiles.map((f) => path.resolve(f)))
      : undefined;

    const filtered = allFindings.filter((finding) => {
      if (incrementalSet) return incrementalSet.has(path.resolve(finding.file));
      return true;
    });

    return {
      tool: 'codeql',
      findings: filtered,
      errors: allErrors.length ? allErrors : undefined
    };
  }
};
