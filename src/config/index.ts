import { cosmiconfig } from 'cosmiconfig';
import { Ajv, type ErrorObject } from 'ajv';
import fs from 'fs-extra';
import path from 'path';
import yaml from 'js-yaml';
import { ScanConfig, ScanOptions } from '../types.js';
import { configSchema, defaultConfig } from './schema.js';

const ajv = new Ajv({ allErrors: true });
const validate = ajv.compile(configSchema);

const searchPlaces = [
  '.securityrc',
  '.securityrc.json',
  '.securityrc.yaml',
  '.securityrc.yml',
  'security.config.js',
  'package.json'
];

const normalizeConfig = (config: Record<string, unknown>): ScanConfig => {
  const scanners = (config.scanners ?? {}) as Record<string, unknown>;
  const npmAuditConfig = (scanners['npm-audit'] ?? scanners.npmAudit ?? {}) as Record<
    string,
    unknown
  >;

  return {
    ...defaultConfig,
    ...config,
    scanners: {
      ...defaultConfig.scanners,
      ...scanners,
      npmAudit: {
        ...defaultConfig.scanners.npmAudit,
        ...npmAuditConfig
      }
    }
  } as ScanConfig;
};

const mergeConfig = (base: ScanConfig, overrides?: Partial<ScanConfig>): ScanConfig => {
  if (!overrides) {
    return base;
  }

  return {
    ...base,
    ...overrides,
    scanners: {
      ...base.scanners,
      ...overrides.scanners
    },
    output: {
      ...base.output,
      ...overrides.output
    },
    thresholds: {
      ...base.thresholds,
      ...overrides.thresholds
    },
    cache: {
      ...base.cache,
      ...overrides.cache
    },
    execution: {
      ...base.execution,
      ...overrides.execution
    },
    exclude: overrides.exclude ?? base.exclude
  };
};

export const loadConfig = async (
  configPath?: string,
  searchFrom?: string
): Promise<ScanConfig> => {
  const explorer = cosmiconfig('security', { searchPlaces });
  let result;

  if (configPath) {
    result = await explorer.load(configPath);
  } else {
    result = searchFrom ? await explorer.search(searchFrom) : await explorer.search();
  }

  if (!result) {
    return defaultConfig;
  }

  const normalized = normalizeConfig(result.config as Record<string, unknown>);

  if (!validate(normalized)) {
    const errors = (validate.errors ?? []).map(
      (error: ErrorObject) => `${error.instancePath} ${error.message}`
    );
    throw new Error(`Invalid configuration: ${errors.join(', ')}`);
  }

  return normalized;
};

export const applyCliOptions = (config: ScanConfig, options: ScanOptions): ScanConfig => {
  const overrides: Partial<ScanConfig> = {
    output: {
      format: options.format ?? config.output.format,
      file: options.outputPath ?? config.output.file,
      console: config.output.console
    },
    execution: {
      parallel: options.parallel ?? config.execution.parallel,
      continueOnError: options.failFast ? false : config.execution.continueOnError
    },
    exclude: options.exclude ?? config.exclude,
    cache: {
      ...config.cache,
      enabled: options.noCache ? false : config.cache.enabled
    },
    thresholds: {
      ...config.thresholds,
      failOn: options.failOn ?? config.thresholds.failOn
    }
  };

  return mergeConfig(config, overrides);
};

export const writeDefaultConfig = async (targetPath: string): Promise<void> => {
  const configYaml = yaml.dump({
    scanners: {
      gitleaks: { enabled: true, config: '.gitleaks.toml' },
      trivy: { enabled: true, severity: 'CRITICAL,HIGH', vulnType: 'os,library' },
      semgrep: { enabled: true, config: 'auto', rules: ['p/security-audit', 'p/nodejs'] },
      'npm-audit': { enabled: true, auditLevel: 'moderate' },
      horusec: { enabled: true, disableDocker: true },
      codeql: { enabled: true }
    },
    output: {
      format: 'json',
      file: 'security-report.json',
      console: true
    },
    thresholds: {
      failOn: 'high',
      maxCritical: 0,
      maxHigh: 5
    },
    exclude: ['**/node_modules/**', '**/test/**', '**/*.test.js', '**/.next/**', '**/dist/**', '**/build/**', '**/.security-scan-cache/**'],
    cache: {
      enabled: true,
      ttl: 86400
    }
  });

  await fs.outputFile(targetPath, configYaml, 'utf8');
};

export const resolveConfigPath = (customPath?: string): string => {
  if (customPath) {
    return path.resolve(customPath);
  }

  return path.resolve('.securityrc.yml');
};
