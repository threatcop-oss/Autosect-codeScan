import path from 'path';
import ora from 'ora';
import { ScanConfig, ScanOptions, ScanReport, ScanError, Finding } from './types.js';
import { Scanner } from './scanners/types.js';
import { gitleaksScanner } from './scanners/gitleaks.js';
import { trivyScanner } from './scanners/trivy.js';
import { semgrepScanner } from './scanners/semgrep.js';
import { npmAuditScanner } from './scanners/npmAudit.js';
import { horusecScanner } from './scanners/horusec.js';
import { codeqlScanner } from './scanners/codeql.js';
import { resolveExcludedFiles, resolveScanTarget } from './utils/paths.js';
import { createLogger, Logger } from './logger.js';
import { dedupeFindings } from './utils/dedupe.js';
import { isSeverityAtLeast } from './utils/severity.js';
import { getChangedFiles, getChangedFilesSinceCommit, getRepositoryInfo } from './utils/git.js';
import { CacheStore } from './cache.js';
import { startTimer } from './utils/timers.js';
import { buildSummary } from './utils/summary.js';
import { extractCves } from './utils/cve.js';

const scannerMap: Record<string, Scanner> = {
  gitleaks: gitleaksScanner,
  trivy: trivyScanner,
  semgrep: semgrepScanner,
  'npm-audit': npmAuditScanner,
  horusec: horusecScanner,
  codeql: codeqlScanner
};

const CACHE_VERSION = '2';

const normalizeToolName = (tool: string): string => {
  const normalized = tool.trim().toLowerCase();
  if (normalized === 'npm' || normalized === 'npm-audit') {
    return 'npm-audit';
  }
  return normalized;
};

const buildContext = async (
  config: ScanConfig,
  options: ScanOptions,
  logger: Logger
): Promise<{
  excludeSet: Set<string>;
  incrementalFiles?: string[];
}> => {
  const excludeSet = await resolveExcludedFiles(options.targetPath, config.exclude);
  if (options.incremental) {
    const incrementalFiles = await getChangedFiles(options.targetPath);
    return { excludeSet, incrementalFiles };
  }
  if (options.diffCommit) {
    let allChanged: string[];
    try {
      allChanged = await getChangedFilesSinceCommit(options.targetPath, options.diffCommit);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      throw new Error(`Invalid commit reference '${options.diffCommit}': ${msg}`);
    }
    const resolved = path.resolve(options.targetPath);
    const incrementalFiles = allChanged.filter((f) => f.startsWith(resolved));
    return { excludeSet, incrementalFiles };
  }
  return { excludeSet };
};

export const runScan = async (
  config: ScanConfig,
  options: ScanOptions,
  logger = createLogger({ verbose: options.verbose, quiet: options.quiet })
): Promise<ScanReport> => {
  const resolvedTarget = resolveScanTarget(options.targetPath);
  const resolvedOptions: ScanOptions = {
    ...options,
    targetPath: resolvedTarget.targetPath,
    // When caller passed null (non-manifest file like swagger.json), do not use directory's manifest
    manifestPath:
      options.manifestPath === null
        ? undefined
        : options.lockFilePath && options.manifestPath === undefined
          ? undefined
          : (options.manifestPath ?? resolvedTarget.manifestPath),
    manifestType:
      options.manifestPath === null
        ? undefined
        : (options.manifestType ?? resolvedTarget.manifestType),
    lockFilePath: options.lockFilePath ?? resolvedTarget.lockFilePath
  };
  const finishTimer = startTimer();
  const errors: ScanError[] = [];
  const { excludeSet, incrementalFiles } = await buildContext(config, resolvedOptions, logger);

  if (resolvedOptions.verbose) {
    if (incrementalFiles?.length) {
      console.log(
        JSON.stringify({
          targetPath: resolvedOptions.targetPath,
          manifestPath: resolvedOptions.manifestPath,
          manifestType: resolvedOptions.manifestType,
          mode: 'incremental',
          fileCount: incrementalFiles.length
        }, null, 2)
      );
    } else {
      console.log(
        JSON.stringify({
          targetPath: resolvedOptions.targetPath,
          manifestPath: resolvedOptions.manifestPath,
          manifestType: resolvedOptions.manifestType,
          mode: 'full',
          note: resolvedOptions.manifestType ? 'Only the manifest file is scanned' : 'All files under target path (excluding configured exclusions)'
        }, null, 2)
      );
    }
  }

  if ((resolvedOptions.incremental || resolvedOptions.diffCommit) && incrementalFiles && incrementalFiles.length === 0) {
    const repoInfo = await getRepositoryInfo(resolvedOptions.targetPath);
    return {
      timestamp: new Date().toISOString(),
      repository: repoInfo.repository,
      commit: repoInfo.commit,
      duration: finishTimer(),
      summary: { total: 0, by_severity: {}, by_category: {}, by_tool: {} },
      findings: [],
      errors: [
        {
          tool: resolvedOptions.diffCommit ? 'commit-diff' : 'incremental',
          message: resolvedOptions.diffCommit
            ? `No changed files detected between commit ${resolvedOptions.diffCommit} and HEAD within the target path.`
            : 'No changed files detected for incremental scan.'
        }
      ]
    };
  }

  if (resolvedOptions.dryRun) {
    return {
      timestamp: new Date().toISOString(),
      duration: finishTimer(),
      summary: { total: 0, by_severity: {}, by_category: {}, by_tool: {} },
      findings: [],
      errors: [
        {
          tool: 'dry-run',
          message: `Dry run: ${resolvedOptions.targetPath} (${resolvedOptions.tools?.join(', ') ?? 'all tools'})`,
          details: incrementalFiles?.length
            ? `Incremental files: ${incrementalFiles.join(', ')}`
            : undefined
        }
      ]
    };
  }

  // const cache = new CacheStore(config, resolvedOptions.targetPath);
  // When no tools specified: match code-scanner.zip behavior – single manifest → minimal tools
  const defaultToolsByManifest =
    resolvedOptions.manifestType === 'maven'
      ? ['trivy']
      : resolvedOptions.manifestType === 'npm'
        ? ['npm-audit', 'trivy']
        : ['gitleaks', 'trivy', 'semgrep', 'npm-audit'];
  const selectedTools = resolvedOptions.tools?.length
    ? resolvedOptions.tools.map(normalizeToolName)
    : defaultToolsByManifest;

  const unknownTools = selectedTools.filter((tool) => !scannerMap[tool]);
  if (unknownTools.length) {
    errors.push({
      tool: 'orchestrator',
      message: 'Unknown tools were ignored.',
      details: unknownTools.join(', ')
    });
  }
  const activeScanners = selectedTools
    .map((tool) => scannerMap[tool])
    .filter((scanner) => scanner)
    .filter((scanner) => {
      const configKey = scanner.name === 'npm-audit' ? 'npmAudit' : scanner.name;
      return config.scanners[configKey as keyof ScanConfig['scanners']]?.enabled !== false;
    });

  if (!activeScanners.length) {
    const repoInfo = await getRepositoryInfo(resolvedOptions.targetPath);
    return {
      timestamp: new Date().toISOString(),
      repository: repoInfo.repository,
      commit: repoInfo.commit,
      duration: finishTimer(),
      summary: { total: 0, by_severity: {}, by_category: {}, by_tool: {} },
      findings: [],
      errors: [
        {
          tool: 'orchestrator',
          message: 'No scanners selected or enabled.',
          details: unknownTools.length
            ? `Unknown tools: ${unknownTools.join(', ')}`
            : undefined
        }
      ]
    };
  }

  const runScanner = async (scanner: Scanner): Promise<Finding[]> => {
    const spinner = ora({ text: `Running ${scanner.name}...`, isEnabled: true });
    spinner.start();

    // const cacheKey = cache.buildKey([
    //   CACHE_VERSION,
    //   scanner.name,
    //   resolvedOptions.targetPath,
    //   resolvedOptions.manifestPath ?? undefined,
    //   JSON.stringify(config.scanners),
    //   incrementalFiles?.join(',')
    // ]);

    // const cached = await cache.get<Finding[]>(cacheKey);
    // if (cached) {
    //   spinner.succeed(`${scanner.name} (cached)`);
    //   return cached;
    // }

    try {
      const result = await scanner.run({
        targetPath: resolvedOptions.targetPath,
        config,
        options: resolvedOptions,
        logger,
        excludePaths: excludeSet,
        excludePatterns: config.exclude,
        incrementalFiles
      });
      if (result.errors?.length) {
        errors.push(...result.errors);
      }

      spinner.succeed(`${scanner.name} completed`);
      // await cache.set(cacheKey, result.findings);
      return result.findings;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push({ tool: scanner.name, message });
      spinner.fail(`${scanner.name} failed`);
      if (!config.execution.continueOnError || resolvedOptions.failFast) {
        throw error;
      }
      return [];
    }
  };

  let findings: Finding[] = [];
  if (config.execution.parallel) {
    const findingsList = await Promise.all(activeScanners.map(runScanner));
    findings = ([] as Finding[]).concat(...findingsList);
  } else {
    for (const scanner of activeScanners) {
      const result = await runScanner(scanner);
      findings = findings.concat(result);
    }
  }

  const filtered = resolvedOptions.severity
    ? findings.filter((finding) => isSeverityAtLeast(finding.severity, resolvedOptions.severity))
    : findings;

  const deduped = dedupeFindings(filtered);
  const cves = extractCves(deduped);
  const repoInfo = await getRepositoryInfo(resolvedOptions.targetPath);

  return {
    timestamp: new Date().toISOString(),
    repository: repoInfo.repository,
    commit: repoInfo.commit,
    duration: finishTimer(),
    summary: buildSummary(deduped),
    findings: deduped,
    errors: errors.length ? errors : undefined,
    cves: cves.length ? cves : undefined
  };
};
