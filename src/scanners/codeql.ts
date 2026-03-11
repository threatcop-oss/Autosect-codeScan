import crypto from 'crypto';
import os from 'os';
import path from 'path';
import fs from 'fs-extra';
import { glob } from 'glob';
import { fileURLToPath } from 'url';
import { Finding } from '../types.js';
import { normalizeSeverity } from '../utils/severity.js';
import { isExcluded } from '../utils/paths.js';
import { Scanner, ScannerContext, ScannerResult } from './types.js';
import { runCommand } from './runner.js';

const DEFAULT_LANGUAGE = 'javascript';
const DEFAULT_QUERY_PACKS: Record<string, string> = {
  cpp: 'codeql/cpp-queries',
  csharp: 'codeql/csharp-queries',
  go: 'codeql/go-queries',
  java: 'codeql/java-queries',
  javascript: 'codeql/javascript-queries',
  python: 'codeql/python-queries',
  ruby: 'codeql/ruby-queries',
  swift: 'codeql/swift-queries',
  rust: 'codeql/rust-queries'
};

const LANGUAGE_ALIASES: Record<string, string> = {
  c: 'cpp',
  'c++': 'cpp',
  'c/c++': 'cpp',
  'c-cpp': 'cpp',
  cpp: 'cpp',
  csharp: 'csharp',
  'c#': 'csharp',
  dotnet: 'csharp',
  go: 'go',
  java: 'java',
  kotlin: 'java',
  'java-kotlin': 'java',
  javascript: 'javascript',
  js: 'javascript',
  typescript: 'javascript',
  ts: 'javascript',
  'javascript-typescript': 'javascript',
  python: 'python',
  py: 'python',
  ruby: 'ruby',
  rb: 'ruby',
  swift: 'swift',
  rust: 'rust',
  rs: 'rust'
};

const LANGUAGE_FILE_PATTERNS: Record<string, string[]> = {
  cpp: ['**/*.{c,cc,cpp,cxx,h,hh,hpp,hxx}'],
  csharp: ['**/*.cs'],
  go: ['**/*.go'],
  java: ['**/*.{java,kt,kts}'],
  javascript: ['**/*.{js,jsx,mjs,cjs,ts,tsx}'],
  python: ['**/*.py'],
  ruby: ['**/*.rb'],
  swift: ['**/*.swift'],
  rust: ['**/*.rs']
};

const BUILD_REQUIRED_LANGUAGES = new Set(['cpp', 'csharp', 'go', 'java', 'swift', 'rust']);

interface ResolvedLanguageConfig {
  language: string;
  queryPack: string;
  buildCommand?: string;
}

const normalizeCodeqlLanguage = (value?: string): string | undefined => {
  if (!value) return undefined;
  const normalized = value.trim().toLowerCase();
  return LANGUAGE_ALIASES[normalized];
};

const resolveExplicitLanguages = (config: ScannerContext['config']['scanners']['codeql']): string[] => {
  const configured = config.languages?.length ? config.languages : config.language ? [config.language] : [];
  return configured
    .map((language) => normalizeCodeqlLanguage(language))
    .filter((language): language is string => Boolean(language));
};

const getManifestPreferredLanguages = (options: ScannerContext['options']): string[] => {
  if (options.manifestType === 'maven') return ['java'];
  if (options.manifestType === 'npm') return ['javascript'];
  return [];
};

const detectRepoLanguages = async (
  targetPath: string,
  options: ScannerContext['options']
): Promise<string[]> => {
  const detected: string[] = [];
  const preferred = getManifestPreferredLanguages(options);

  for (const language of preferred) {
    if (await hasMatchingSourceFiles(targetPath, language)) {
      detected.push(language);
    }
  }

  for (const language of Object.keys(LANGUAGE_FILE_PATTERNS)) {
    if (detected.includes(language)) continue;
    if (await hasMatchingSourceFiles(targetPath, language)) {
      detected.push(language);
    }
  }

  return detected;
};

const resolveLanguageConfigs = async (
  config: ScannerContext['config']['scanners']['codeql'],
  targetPath: string,
  options: ScannerContext['options']
): Promise<{ resolved: ResolvedLanguageConfig[]; invalid: string[]; autoDetected: boolean }> => {
  const rawLanguages = config.languages?.length ? config.languages : config.language ? [config.language] : [];
  const invalid = rawLanguages.filter((language) => !normalizeCodeqlLanguage(language));
  const explicitLanguages = Array.from(new Set(rawLanguages.map((language) => normalizeCodeqlLanguage(language)).filter(Boolean) as string[]));
  const autoDetected = explicitLanguages.length === 0;
  const selectedLanguages = autoDetected
    ? await detectRepoLanguages(targetPath, options)
    : explicitLanguages;
  const resolved = Array.from(new Set(selectedLanguages))
    .map((language) => ({
      language,
      queryPack:
        config.queryPacks?.[language] ??
        (language === DEFAULT_LANGUAGE ? config.queryPack : undefined) ??
        DEFAULT_QUERY_PACKS[language],
      buildCommand: config.buildCommands?.[language]
    }))
    .filter((entry) => Boolean(entry.queryPack));

  return { resolved, invalid, autoDetected };
};

const hasMatchingSourceFiles = async (targetPath: string, language: string): Promise<boolean> => {
  const patterns = LANGUAGE_FILE_PATTERNS[language] ?? [];
  for (const pattern of patterns) {
    const matches = await glob(pattern, { cwd: targetPath, dot: true });
    if (matches.length > 0) {
      return true;
    }
  }
  return false;
};

const buildCreateArgs = (databasePath: string, targetPath: string, config: ResolvedLanguageConfig): string[] => {
  const args = ['database', 'create', databasePath, `--language=${config.language}`, '--source-root', targetPath];
  if (BUILD_REQUIRED_LANGUAGES.has(config.language)) {
    if (config.buildCommand) {
      args.push('--command', config.buildCommand);
    } else {
      args.push('--build-mode=autobuild');
    }
  } else {
    args.push('--build-mode=none');
  }
  return args;
};

const mapSarifSeverity = (level?: string, ruleLevel?: string) => {
  const candidate = (level ?? ruleLevel ?? 'warning').toLowerCase();
  if (candidate === 'error') return 'high' as const;
  if (candidate === 'warning') return 'medium' as const;
  if (candidate === 'note' || candidate === 'recommendation') return 'low' as const;
  return normalizeSeverity(candidate);
};

const extractCwes = (tags: unknown): string[] | undefined => {
  if (!Array.isArray(tags)) return undefined;
  const cwes = tags
    .filter((tag): tag is string => typeof tag === 'string')
    .map((tag) => {
      const match = tag.match(/cwe-(\d+)/i);
      return match ? `CWE-${match[1]}` : undefined;
    })
    .filter((value): value is string => Boolean(value));
  return cwes.length ? Array.from(new Set(cwes)) : undefined;
};

const mapPrecisionToConfidence = (precision?: string): Finding['confidence'] | undefined => {
  if (!precision) return undefined;
  const normalized = precision.toLowerCase();
  if (normalized === 'very-high' || normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  return undefined;
};

const extractPrimarySnippet = (location: Record<string, any>): string | undefined => {
  const regionSnippet = location.region?.snippet?.text;
  if (typeof regionSnippet === 'string' && regionSnippet.trim()) {
    return regionSnippet;
  }

  const contextSnippet = location.contextRegion?.snippet?.text;
  if (typeof contextSnippet === 'string' && contextSnippet.trim()) {
    return contextSnippet;
  }

  return undefined;
};

const resolveArtifactPath = (targetPath: string, uri?: string): string => {
  if (!uri) return targetPath;
  if (uri.startsWith('file://')) {
    try {
      return fileURLToPath(uri);
    } catch {
      return targetPath;
    }
  }
  return path.isAbsolute(uri) ? uri : path.resolve(targetPath, decodeURIComponent(uri));
};

const buildRuleMap = (run: Record<string, any>): Map<string, Record<string, any>> => {
  const ruleMap = new Map<string, Record<string, any>>();
  const addRules = (rules: unknown) => {
    if (!Array.isArray(rules)) return;
    for (const rule of rules) {
      if (rule && typeof rule === 'object' && typeof (rule as Record<string, any>).id === 'string') {
        ruleMap.set((rule as Record<string, any>).id, rule as Record<string, any>);
      }
    }
  };

  addRules(run.tool?.driver?.rules);
  if (Array.isArray(run.tool?.extensions)) {
    for (const extension of run.tool.extensions) {
      addRules(extension?.rules);
    }
  }
  return ruleMap;
};

const mapSarifResult = (
  result: Record<string, any>,
  ruleMap: Map<string, Record<string, any>>,
  targetPath: string,
  language: string
): Finding => {
  const ruleId = result.ruleId ?? 'codeql-result';
  const rule = ruleMap.get(ruleId) ?? {};
  const location = result.locations?.[0]?.physicalLocation ?? {};
  const artifactUri = location.artifactLocation?.uri;
  const region = location.region ?? {};
  const message =
    result.message?.text ??
    result.message?.markdown ??
    rule.fullDescription?.text ??
    rule.shortDescription?.text ??
    rule.name ??
    ruleId;
  const title = rule.name ?? rule.shortDescription?.text ?? ruleId;
  const severity = mapSarifSeverity(result.level, rule.defaultConfiguration?.level);
  const tags = rule.properties?.tags;
  const precision = rule.properties?.precision;
  const snippet = extractPrimarySnippet(location);
  const idSource = [
    ruleId,
    artifactUri ?? '',
    region.startLine ?? '',
    region.startColumn ?? '',
    message
  ].join('|');

  return {
    id: crypto.createHash('sha256').update(idSource).digest('hex'),
    tool: 'codeql',
    severity,
    category: 'vulnerability',
    title,
    description: message,
    file: resolveArtifactPath(targetPath, artifactUri),
    line: region.startLine,
    column: region.startColumn,
    cwe: extractCwes(tags),
    confidence: mapPrecisionToConfidence(precision),
    references: rule.helpUri ? [rule.helpUri] : undefined,
    metadata: {
      language,
      ruleId,
      ruleName: rule.name,
      ruleDescription: rule.fullDescription?.text,
      code: snippet,
      securityTool: 'codeql',
      tags,
      precision,
      securitySeverity: rule.properties?.['security-severity'],
      relatedLocations: result.relatedLocations,
      codeFlows: result.codeFlows,
      partialFingerprints: result.partialFingerprints
    }
  };
};

const parseSarifFindings = (
  sarif: Record<string, any>,
  targetPath: string,
  language: string
): Finding[] => {
  const findings: Finding[] = [];
  const runs = Array.isArray(sarif.runs) ? sarif.runs : [];

  for (const run of runs) {
    const ruleMap = buildRuleMap(run);
    const results = Array.isArray(run.results) ? run.results : [];
    for (const result of results) {
      findings.push(mapSarifResult(result, ruleMap, targetPath, language));
    }
  }

  return findings;
};

const buildScannerError = (stage: string, message: string, details?: string) => ({
  tool: 'codeql',
  message: `[${stage}] ${message}`,
  details
});

export const codeqlScanner: Scanner = {
  name: 'codeql',
  async run(context: ScannerContext): Promise<ScannerResult> {
    const { resolved: languageConfigs, invalid, autoDetected } = await resolveLanguageConfigs(
      context.config.scanners.codeql,
      context.targetPath,
      context.options
    );
    if (invalid.length) {
      return {
        tool: 'codeql',
        findings: [],
        errors: [
          buildScannerError(
            'config',
            `Unsupported CodeQL language(s): ${invalid.join(', ')}`,
            'Supported groups: cpp, csharp, go, java, javascript, python, ruby, swift, rust.'
          )
        ]
      };
    }
    if (!languageConfigs.length) {
      const details = autoDetected
        ? `No supported CodeQL source languages were detected under ${context.targetPath}.`
        : 'No valid CodeQL languages were configured.';
      return {
        tool: 'codeql',
        findings: [],
        errors: [buildScannerError('config', 'No CodeQL languages selected for analysis.', details)]
      };
    }

    if (context.options.verbose) {
      context.logger.info(
        {
          autoDetected,
          languages: languageConfigs.map((entry) => entry.language),
          manifestType: context.options.manifestType
        },
        'Resolved CodeQL languages'
      );
    }

    const findings: Finding[] = [];
    const errors = [];

    for (const languageConfig of languageConfigs) {
      if (!(await hasMatchingSourceFiles(context.targetPath, languageConfig.language))) {
        if (context.options.verbose) {
          context.logger.info({ language: languageConfig.language }, 'Skipping CodeQL language with no matching source files');
        }
        continue;
      }

      const runId = `${languageConfig.language}-${Date.now()}-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
      const workDir = path.join(os.tmpdir(), `codeql-${runId}`);
      const databasePath = path.join(workDir, 'db');
      const sarifPath = path.join(workDir, 'results.sarif');

      await fs.ensureDir(workDir);
      try {
        const createArgs = buildCreateArgs(databasePath, context.targetPath, languageConfig);
        const createResult = await runCommand('codeql', createArgs, {
          cwd: context.targetPath,
          logger: context.logger,
          verbose: context.options.verbose
        });
        if (createResult.exitCode !== 0) {
          errors.push(
            buildScannerError(
              'database-create',
              `CodeQL database creation failed for ${languageConfig.language} (exit code ${createResult.exitCode})`,
              createResult.stderr || createResult.stdout
            )
          );
          if (context.options.failFast || context.config.execution.continueOnError === false) break;
          continue;
        }

        const analyzeArgs = [
          'database',
          'analyze',
          databasePath,
          languageConfig.queryPack,
          '--format=sarif-latest',
          '--output',
          sarifPath,
          '--download',
          '--sarif-add-snippets'
        ];
        if (context.config.scanners.codeql.args?.length) {
          analyzeArgs.push(...context.config.scanners.codeql.args);
        }
        const analyzeResult = await runCommand('codeql', analyzeArgs, {
          cwd: context.targetPath,
          logger: context.logger,
          verbose: context.options.verbose
        });
        if (analyzeResult.exitCode !== 0) {
          errors.push(
            buildScannerError(
              'database-analyze',
              `CodeQL analysis failed for ${languageConfig.language} (exit code ${analyzeResult.exitCode})`,
              analyzeResult.stderr || analyzeResult.stdout
            )
          );
          if (context.options.failFast || context.config.execution.continueOnError === false) break;
          continue;
        }

        if (!(await fs.pathExists(sarifPath))) {
          errors.push(
            buildScannerError(
              'sarif-parse',
              `CodeQL analysis for ${languageConfig.language} completed but SARIF output was not generated.`
            )
          );
          if (context.options.failFast || context.config.execution.continueOnError === false) break;
          continue;
        }

        let sarif: Record<string, any>;
        try {
          sarif = await fs.readJson(sarifPath);
        } catch (error) {
          errors.push(
            buildScannerError(
              'sarif-parse',
              `Failed to parse CodeQL SARIF output for ${languageConfig.language}.`,
              error instanceof Error ? error.message : String(error)
            )
          );
          if (context.options.failFast || context.config.execution.continueOnError === false) break;
          continue;
        }

        findings.push(...parseSarifFindings(sarif, context.targetPath, languageConfig.language));
      } finally {
        await fs.remove(workDir).catch(() => {});
      }
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

    return {
      tool: 'codeql',
      findings: filtered,
      errors: errors.length ? errors : undefined
    };
  },
  async update(context: ScannerContext): Promise<void> {
    const languages = resolveExplicitLanguages(context.config.scanners.codeql);
    for (const language of languages) {
      const queryPack =
        context.config.scanners.codeql.queryPacks?.[language] ??
        (language === DEFAULT_LANGUAGE ? context.config.scanners.codeql.queryPack : undefined) ??
        DEFAULT_QUERY_PACKS[language];
      await runCommand('codeql', ['pack', 'download', queryPack], {
        logger: context.logger,
        verbose: context.options.verbose
      });
    }
  }
};
