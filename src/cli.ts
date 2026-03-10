#!/usr/bin/env node
import 'dotenv/config';
import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig, applyCliOptions, resolveConfigPath, writeDefaultConfig } from './config/index.js';
import { runScan } from './orchestrator.js';
import { writeReport } from './reporters/index.js';
import { compareBaseline, loadBaseline, writeBaseline } from './baseline.js';
import { createLogger } from './logger.js';
import { ScanOptions } from './types.js';
import { resolveScanTarget } from './utils/paths.js';
import { evaluateThresholds } from './thresholds.js';
import { buildSummary } from './utils/summary.js';
import fs from 'fs-extra';
import { gitleaksScanner } from './scanners/gitleaks.js';
import { trivyScanner } from './scanners/trivy.js';
import { semgrepScanner } from './scanners/semgrep.js';
import { npmAuditScanner } from './scanners/npmAudit.js';
import { horusecScanner } from './scanners/horusec.js';
import { runCommand } from './scanners/runner.js';

const program = new Command();

const TOOLS: { name: string; command: string; args: string[] }[] = [
  { name: 'gitleaks', command: 'gitleaks', args: ['version'] },
  { name: 'trivy', command: 'trivy', args: ['--version'] },
  { name: 'semgrep', command: 'semgrep', args: ['--version'] },
  { name: 'npm', command: 'npm', args: ['--version'] },
  { name: 'horusec', command: 'horusec', args: ['version'] }
];

const handleVerify = async () => {
  console.log(chalk.bold('Checking scanner tools (must be in PATH)\n'));
  let allOk = true;
  for (const { name, command, args } of TOOLS) {
    try {
      const result = await runCommand(command, args, {});
      const ok = result.exitCode === 0;
      if (!ok) allOk = false;
      const status = ok ? chalk.green('OK') : chalk.yellow('FAIL (non-zero exit)');
      const version = (result.stdout || result.stderr || '').trim().split('\n')[0] || '';
      console.log(`  ${name.padEnd(12)} ${status}  ${version}`);
    } catch (err) {
      allOk = false;
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`  ${name.padEnd(12)} ${chalk.red('MISSING')}  ${msg}`);
    }
  }
  console.log('');
  if (allOk) {
    console.log(chalk.green('All tools are available. Gitleaks/Trivy/Semgrep/Horusec may still report 0 findings on clean repos (no secrets, no rule matches, no vulns).'));
  } else {
    console.log(chalk.yellow('Install missing tools and ensure they are in your PATH.'));
    process.exitCode = 1;
  }
};

const parseList = (value?: string): string[] | undefined => {
  if (!value) return undefined;
  return value.split(',').map((item) => item.trim()).filter(Boolean);
};

const buildScanOptions = (pathArg: string | undefined, opts: any): ScanOptions => {
  const target = resolveScanTarget(pathArg ?? '.');
  return {
    targetPath: target.targetPath,
    manifestPath: target.manifestPath,
    manifestType: target.manifestType,
    lockFilePath: target.lockFilePath,
    // When --tools not set, orchestrator picks by manifest (pom.xml → trivy only; package.json → npm-audit + trivy; else all)
    tools: parseList(opts.tools),
    format: opts.format,
    outputPath: opts.output,
    severity: opts.severity,
    failOn: opts.failOn,
    configPath: opts.config,
    exclude: parseList(opts.exclude),
    parallel: opts.parallel,
    incremental: opts.incremental,
    baselinePath: opts.baseline,
    verbose: opts.verbose,
    quiet: opts.quiet,
    noCache: opts.cache === false,
    failFast: opts.failFast,
    dryRun: opts.dryRun
  };
};

const ensurePathExists = async (options: ScanOptions) => {
  if (!(await fs.pathExists(options.targetPath))) {
    throw new Error(`Target path does not exist: ${options.targetPath}`);
  }
  if (options.manifestPath && !(await fs.pathExists(options.manifestPath))) {
    throw new Error(`Manifest file does not exist: ${options.manifestPath}`);
  }
};

const handleScan = async (pathArg: string | undefined, opts: any) => {
  const options = buildScanOptions(pathArg, opts);
  await ensurePathExists(options);
  const baseConfig = await loadConfig(options.configPath, options.targetPath);
  const config = applyCliOptions(baseConfig, options);
  const logger = createLogger({ verbose: options.verbose, quiet: options.quiet });
  const report = await runScan(config, options, logger);

  if (options.baselinePath) {
    const baseline = await loadBaseline(options.baselinePath);
    const diff = compareBaseline(report, baseline);
    report.findings = diff.newFindings;
    report.summary = buildSummary(report.findings);
  }

  const outputFormat = options.format ?? config.output.format;
  const outputPath = options.outputPath ?? config.output.file;
  const rendered = await writeReport(report, outputFormat, outputPath);

  if (outputFormat === 'html') {
    const { isS3UploadEnabled, uploadReportToS3 } = await import('./s3reports.js');
    if (isS3UploadEnabled()) {
      try {
        console.log(chalk.gray('[S3] Uploading report...'));
        const s3Key = await uploadReportToS3(rendered);
        console.log(chalk.green(`[S3] Upload success: ${s3Key}`));
      } catch (e) {
        const err = e instanceof Error ? e : new Error(String(e));
        console.error(chalk.red('[S3] Upload failed:'), err.message);
        if (err.stack) console.error(chalk.gray(err.stack));
      }
    } else {
      console.log(chalk.gray('[S3] Skipped (not configured)'));
    }
  }

  if (config.output.console || outputFormat === 'console') {
    console.log(rendered);
  }

  if (report.errors?.length) {
    logger.warn({ errors: report.errors }, 'Scan completed');
  }

  const { exitCode, reasons } = evaluateThresholds(report, config.thresholds);
  if (exitCode !== 0 && !options.quiet) {
    logger.error({ reasons }, 'Scan failed threshold checks');
    process.exitCode = exitCode;
  } else if (exitCode !== 0) {
    process.exitCode = exitCode;
  }
};

const handleInit = async (opts: any) => {
  const targetPath = resolveConfigPath(opts.output);
  if (await fs.pathExists(targetPath)) {
    throw new Error(`Config already exists at ${targetPath}`);
  }
  await writeDefaultConfig(targetPath);
  console.log(chalk.green(`Created config at ${targetPath}`));
};

const handleUpdate = async (opts: any) => {
  const options = buildScanOptions('.', opts);
  const baseConfig = await loadConfig(options.configPath);
  const config = applyCliOptions(baseConfig, options);
  const logger = createLogger({ verbose: options.verbose, quiet: options.quiet });

  const scanners = [gitleaksScanner, trivyScanner, semgrepScanner, npmAuditScanner, horusecScanner];
  for (const scanner of scanners) {
    if (!scanner.update) continue;
    const configKey = scanner.name === 'npm-audit' ? 'npmAudit' : scanner.name;
    if (config.scanners[configKey as keyof typeof config.scanners]?.enabled === false) {
      continue;
    }
    logger.info(`Updating ${scanner.name} database/rules...`);
    await scanner.update({
      targetPath: options.targetPath,
      config,
      options,
      logger,
      excludePaths: new Set(config.exclude),
      excludePatterns: config.exclude
    });
  }
};

const handleBaselineCreate = async (pathArg: string | undefined, opts: any) => {
  const options = buildScanOptions(pathArg, opts);
  await ensurePathExists(options);
  const baseConfig = await loadConfig(options.configPath, options.targetPath);
  const config = applyCliOptions(baseConfig, options);
  const logger = createLogger({ verbose: options.verbose, quiet: options.quiet });
  const report = await runScan(config, options, logger);
  const baselinePath = options.baselinePath ?? 'security-baseline.json';
  await writeBaseline(report, baselinePath);
  console.log(chalk.green(`Baseline saved to ${baselinePath}`));
};

const handleBaselineCompare = async (pathArg: string | undefined, opts: any) => {
  const options = buildScanOptions(pathArg, opts);
  if (!options.baselinePath) {
    throw new Error('Baseline path is required for comparison. Use --baseline <path>.');
  }
  await ensurePathExists(options);
  const baseConfig = await loadConfig(options.configPath, options.targetPath);
  const config = applyCliOptions(baseConfig, options);
  const logger = createLogger({ verbose: options.verbose, quiet: options.quiet });
  const report = await runScan(config, options, logger);
  const baseline = await loadBaseline(options.baselinePath);
  const diff = compareBaseline(report, baseline);

  report.findings = diff.newFindings;
  report.summary = buildSummary(report.findings);

  const outputFormat = options.format ?? config.output.format;
  const outputPath = options.outputPath ?? config.output.file;
  const rendered = await writeReport(report, outputFormat, outputPath);

  if (outputFormat === 'html') {
    const { isS3UploadEnabled, uploadReportToS3 } = await import('./s3reports.js');
    if (isS3UploadEnabled()) {
      try {
        console.log(chalk.gray('[S3] Uploading report...'));
        const s3Key = await uploadReportToS3(rendered);
        console.log(chalk.green(`[S3] Upload success: ${s3Key}`));
      } catch (e) {
        const err = e instanceof Error ? e : new Error(String(e));
        console.error(chalk.red('[S3] Upload failed:'), err.message);
        if (err.stack) console.error(chalk.gray(err.stack));
      }
    } else {
      console.log(chalk.gray('[S3] Skipped (not configured)'));
    }
  }

  if (config.output.console || outputFormat === 'console') {
    console.log(rendered);
  }

  const { exitCode, reasons } = evaluateThresholds(report, config.thresholds);
  if (exitCode !== 0) {
    logger.error({ reasons }, 'Baseline comparison failed threshold checks');
    process.exitCode = exitCode;
  }
};

program
  .name('security-scan')
  .description('Unified security scanning CLI')
  .version('0.1.0');

program
  .command('scan [path]')
  .description('Run security scan on target path')
  .option('--tools <tools>', 'Comma-separated list of scanners to run')
  .option('--format <format>', 'Output format (json|sarif|html|markdown|console)')
  .option('--output <path>', 'Output file path')
  .option('--severity <level>', 'Minimum severity to report')
  .option('--fail-on <level>', 'Exit with error if findings at this level or above')
  .option('--config <path>', 'Custom config file path')
  .option('--exclude <patterns>', 'Paths to exclude (comma-separated globs)')
  .option('--parallel', 'Run scanners in parallel', true)
  .option('--incremental', 'Only scan changed files', false)
  .option('--baseline <path>', 'Path to baseline file for comparison')
  .option('--verbose', 'Detailed logging')
  .option('--quiet', 'Minimal output')
  .option('--no-cache', 'Disable caching')
  .option('--fail-fast', 'Stop on first scanner error')
  .option('--dry-run', 'Preview scan without running scanners')
  .action(handleScan);

program
  .command('verify')
  .description('Verify that gitleaks, trivy, semgrep, and npm are installed and runnable')
  .action(handleVerify);

program
  .command('init')
  .description('Initialize configuration file with defaults')
  .option('--output <path>', 'Path to write configuration file')
  .action(handleInit);

program
  .command('update')
  .description('Update scanner databases/rules')
  .option('--config <path>', 'Custom config file path')
  .option('--verbose', 'Detailed logging')
  .option('--quiet', 'Minimal output')
  .action(handleUpdate);

const baseline = program.command('baseline').description('Baseline operations');

baseline
  .command('create [path]')
  .description('Create baseline from current scan')
  .option('--baseline <path>', 'Baseline output path')
  .option('--config <path>', 'Custom config file path')
  .action(handleBaselineCreate);

baseline
  .command('compare [path]')
  .description('Compare current scan against baseline')
  .option('--baseline <path>', 'Baseline input path')
  .option('--config <path>', 'Custom config file path')
  .option('--format <format>', 'Output format (json|sarif|html|markdown|console)')
  .option('--output <path>', 'Output file path')
  .action(handleBaselineCompare);

program.parseAsync(process.argv);
