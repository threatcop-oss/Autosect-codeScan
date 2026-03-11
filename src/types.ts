export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category =
  | 'secret'
  | 'vulnerability'
  | 'code-quality'
  | 'license'
  | 'config';

export interface Finding {
  id: string;
  tool: string;
  severity: Severity;
  category: Category;
  title: string;
  description: string;
  file: string;
  line?: number;
  column?: number;
  cwe?: string[];
  cve?: string;
  cvss?: number;
  installedVersion?: string;
  fixedVersion?: string;
  confidence?: 'high' | 'medium' | 'low';
  remediation?: string;
  references?: string[];
  metadata?: Record<string, unknown>;
}

export interface ScanError {
  tool: string;
  message: string;
  details?: string;
}

export interface ScanReport {
  timestamp: string;
  repository?: string;
  commit?: string;
  duration: number;
  summary: {
    total: number;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
    by_tool: Record<string, number>;
  };
  findings: Finding[];
  errors?: ScanError[];
  cves?: string[];
}

export type OutputFormat = 'json' | 'sarif' | 'html' | 'markdown' | 'console';
export type ManifestType = 'npm' | 'maven';

export interface ScannerConfigBase {
  enabled: boolean;
  args?: string[];
}

export interface GitleaksConfig extends ScannerConfigBase {
  config?: string;
}

export interface TrivyConfig extends ScannerConfigBase {
  severity?: string;
  vulnType?: string;
  config?: string;
}

export interface SemgrepConfig extends ScannerConfigBase {
  config?: string;
  rules?: string[];
}

export interface NpmAuditConfig extends ScannerConfigBase {
  auditLevel?: string;
}

export interface HorusecConfig extends ScannerConfigBase {
  disableDocker?: boolean;
}

export interface CodeqlConfig extends ScannerConfigBase {}

export interface ScannerConfigs {
  gitleaks: GitleaksConfig;
  trivy: TrivyConfig;
  semgrep: SemgrepConfig;
  npmAudit: NpmAuditConfig;
  horusec: HorusecConfig;
  codeql: CodeqlConfig;
}

export interface OutputConfig {
  format: OutputFormat;
  file?: string;
  console?: boolean;
}

export interface ThresholdConfig {
  failOn?: Severity;
  maxCritical?: number;
  maxHigh?: number;
  maxMedium?: number;
  maxLow?: number;
}

export interface CacheConfig {
  enabled: boolean;
  ttl: number;
}

export interface ExecutionConfig {
  parallel: boolean;
  continueOnError: boolean;
}

export interface ScanConfig {
  scanners: ScannerConfigs;
  output: OutputConfig;
  thresholds: ThresholdConfig;
  exclude: string[];
  cache: CacheConfig;
  execution: ExecutionConfig;
}

export interface ScanOptions {
  targetPath: string;
  tools?: string[];
  format?: OutputFormat;
  outputPath?: string;
  severity?: Severity;
  failOn?: Severity;
  configPath?: string;
  exclude?: string[];
  parallel?: boolean;
  incremental?: boolean;
  baselinePath?: string;
  verbose?: boolean;
  quiet?: boolean;
  noCache?: boolean;
  failFast?: boolean;
  dryRun?: boolean;
  /** Path to manifest file, or null to mean "no manifest" (e.g. user sent a non-manifest file like swagger.json). */
  manifestPath?: string | null;
  manifestType?: ManifestType;
  /** When the user pointed at a lock file (e.g. 6275-package-lock.json), path to that lock file. */
  lockFilePath?: string;
}

export interface BaselineResult {
  newFindings: Finding[];
  resolvedFindings: Finding[];
  unchangedFindings: Finding[];
}
