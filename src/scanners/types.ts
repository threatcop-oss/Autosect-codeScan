import { ScanConfig, ScanOptions, Finding, ScanError } from '../types.js';
import { Logger } from '../logger.js';

export interface ScannerContext {
  targetPath: string;
  config: ScanConfig;
  options: ScanOptions;
  logger: Logger;
  excludePaths: Set<string>;
  excludePatterns: string[];
  incrementalFiles?: string[];
}

export interface ScannerResult {
  tool: string;
  findings: Finding[];
  errors?: ScanError[];
}

export interface Scanner {
  name: string;
  run(context: ScannerContext): Promise<ScannerResult>;
  update?(context: ScannerContext): Promise<void>;
}
