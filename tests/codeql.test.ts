import { beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import { defaultConfig } from '../src/config/schema.js';
import type { ScanConfig } from '../src/types.js';

const runCommand = vi.fn();

vi.mock('../src/scanners/runner.js', () => ({
  runCommand
}));

const logger = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {}
} as any;

const createConfig = (overrides?: Partial<ScanConfig>): ScanConfig => ({
  ...defaultConfig,
  ...overrides,
  scanners: {
    ...defaultConfig.scanners,
    ...overrides?.scanners,
    codeql: {
      ...defaultConfig.scanners.codeql,
      ...overrides?.scanners?.codeql
    }
  },
  execution: {
    ...defaultConfig.execution,
    ...overrides?.execution
  }
});

describe('codeql scanner', () => {
  beforeEach(() => {
    runCommand.mockReset();
  });

  it('parses rich SARIF fields into normalized findings', async () => {
    const tmpDir = String(await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-')));
    const sourceFile = path.join(tmpDir, 'src', 'index.js');
    await fs.ensureDir(path.dirname(sourceFile));
    await fs.writeFile(sourceFile, 'const password = userInput;\n');

    runCommand.mockImplementation(async (_command: string, args: string[]) => {
      if (args[0] === 'database' && args[1] === 'create') {
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      if (args[0] === 'database' && args[1] === 'analyze') {
        const outputIndex = args.indexOf('--output');
        const sarifPath = args[outputIndex + 1];
        await fs.writeJson(sarifPath, {
          runs: [
            {
              tool: {
                driver: {
                  rules: [
                    {
                      id: 'js/sql-injection',
                      name: 'SQL injection',
                      shortDescription: { text: 'Potential SQL injection' },
                      fullDescription: { text: 'User-controlled data reaches a SQL sink.' },
                      helpUri: 'https://codeql.github.com/codeql-query-help/javascript/js-sql-injection/',
                      defaultConfiguration: { level: 'error' },
                      properties: {
                        tags: ['security', 'external/cwe/cwe-89'],
                        precision: 'high',
                        'security-severity': '8.8'
                      }
                    }
                  ]
                }
              },
              results: [
                {
                  ruleId: 'js/sql-injection',
                  level: 'error',
                  message: { text: 'Unsanitized input reaches a SQL query.' },
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: { uri: 'src/index.js' },
                        region: {
                          startLine: 1,
                          startColumn: 7,
                          snippet: { text: 'password = userInput' }
                        }
                      }
                    }
                  ],
                  relatedLocations: [{ id: 1, message: { text: 'Source of taint.' } }],
                  codeFlows: [{ threadFlows: [] }],
                  partialFingerprints: { primaryLocationLineHash: 'abc123' }
                }
              ]
            }
          ]
        });
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      return { stdout: '', stderr: '', exitCode: 0 };
    });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run({
      targetPath: tmpDir,
      config: createConfig(),
      options: { targetPath: tmpDir, manifestType: 'npm' },
      logger,
      excludePaths: new Set(),
      excludePatterns: []
    });

    expect(result.errors).toBeUndefined();
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      tool: 'codeql',
      severity: 'high',
      category: 'vulnerability',
      title: 'SQL injection',
      description: 'Unsanitized input reaches a SQL query.',
      file: sourceFile,
      line: 1,
      column: 7,
      cwe: ['CWE-89'],
      confidence: 'high',
      references: ['https://codeql.github.com/codeql-query-help/javascript/js-sql-injection/'],
      metadata: {
        language: 'javascript',
        ruleId: 'js/sql-injection',
        ruleName: 'SQL injection',
        code: 'password = userInput',
        securityTool: 'codeql',
        precision: 'high',
        securitySeverity: '8.8',
        partialFingerprints: { primaryLocationLineHash: 'abc123' }
      }
    });
    expect(result.findings[0].metadata?.relatedLocations).toEqual([
      { id: 1, message: { text: 'Source of taint.' } }
    ]);
    expect(result.findings[0].metadata?.codeFlows).toEqual([{ threadFlows: [] }]);

    await fs.remove(tmpDir);
  });

  it('uses configured query pack and build command for explicit languages', async () => {
    const tmpDir = String(await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-')));
    const javaFile = path.join(tmpDir, 'src', 'Main.java');
    await fs.ensureDir(path.dirname(javaFile));
    await fs.writeFile(javaFile, 'class Main { public static void main(String[] args) {} }\n');

    runCommand.mockImplementation(async (_command: string, args: string[]) => {
      if (args[0] === 'database' && args[1] === 'analyze') {
        const outputIndex = args.indexOf('--output');
        const sarifPath = args[outputIndex + 1];
        await fs.writeJson(sarifPath, { runs: [] });
      }
      return { stdout: '', stderr: '', exitCode: 0 };
    });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    await codeqlScanner.run({
      targetPath: tmpDir,
      config: createConfig({
        scanners: {
          ...defaultConfig.scanners,
          codeql: {
            enabled: true,
            languages: ['java'],
            queryPacks: {
              java: 'custom/java-queries'
            },
            buildCommands: {
              java: 'mvn -q -DskipTests compile'
            }
          }
        }
      }),
      options: { targetPath: tmpDir },
      logger,
      excludePaths: new Set(),
      excludePatterns: []
    });

    expect(runCommand).toHaveBeenCalledTimes(2);
    expect(runCommand.mock.calls[0][1]).toEqual(
      expect.arrayContaining(['--language=java', '--command', 'mvn -q -DskipTests compile'])
    );
    expect(runCommand.mock.calls[1][1]).toEqual(
      expect.arrayContaining(['custom/java-queries', '--sarif-add-snippets'])
    );

    await fs.remove(tmpDir);
  });

  it('downloads query packs during update for explicit languages', async () => {
    runCommand.mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    await codeqlScanner.update?.({
      targetPath: process.cwd(),
      config: createConfig({
        scanners: {
          ...defaultConfig.scanners,
          codeql: {
            enabled: true,
            languages: ['javascript', 'python'],
            queryPacks: {
              javascript: 'custom/js-pack',
              python: 'custom/py-pack'
            }
          }
        }
      }),
      options: { targetPath: process.cwd() },
      logger,
      excludePaths: new Set(),
      excludePatterns: []
    });

    expect(runCommand).toHaveBeenNthCalledWith(
      1,
      'codeql',
      ['pack', 'download', 'custom/js-pack'],
      expect.any(Object)
    );
    expect(runCommand).toHaveBeenNthCalledWith(
      2,
      'codeql',
      ['pack', 'download', 'custom/py-pack'],
      expect.any(Object)
    );
  });

  it('returns a config error for unsupported explicit languages', async () => {
    const tmpDir = String(await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-')));

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run({
      targetPath: tmpDir,
      config: createConfig({
        scanners: {
          ...defaultConfig.scanners,
          codeql: {
            enabled: true,
            languages: ['php']
          }
        }
      }),
      options: { targetPath: tmpDir },
      logger,
      excludePaths: new Set(),
      excludePatterns: []
    });

    expect(result.findings).toEqual([]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors?.[0]).toMatchObject({
      tool: 'codeql',
      message: expect.stringContaining('Unsupported CodeQL language(s): php'),
      details: expect.stringContaining('Supported groups')
    });
    expect(runCommand).not.toHaveBeenCalled();

    await fs.remove(tmpDir);
  });

  it('returns a parse error when analysis succeeds without producing SARIF', async () => {
    const tmpDir = String(await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-')));
    const sourceFile = path.join(tmpDir, 'src', 'index.js');
    await fs.ensureDir(path.dirname(sourceFile));
    await fs.writeFile(sourceFile, 'console.log("hello");\n');

    runCommand.mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run({
      targetPath: tmpDir,
      config: createConfig(),
      options: { targetPath: tmpDir, manifestType: 'npm' },
      logger,
      excludePaths: new Set(),
      excludePatterns: []
    });

    expect(result.findings).toEqual([]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors?.[0]).toMatchObject({
      tool: 'codeql',
      message: expect.stringContaining('[sarif-parse]'),
      details: undefined
    });
    expect(result.errors?.[0].message).toContain('SARIF output was not generated');
    expect(runCommand).toHaveBeenCalledTimes(2);

    await fs.remove(tmpDir);
  });
});
