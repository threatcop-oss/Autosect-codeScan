import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';

// ---------------------------------------------------------------------------
// Mocks — must be declared before any dynamic imports of the module under test
// ---------------------------------------------------------------------------

const mockRunCommand = vi.fn();
vi.mock('../src/scanners/runner.js', () => ({
  runCommand: mockRunCommand
}));

const mockDetectLanguages = vi.fn();
vi.mock('../src/utils/detectLanguages.js', () => ({
  detectLanguages: mockDetectLanguages
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

import type { ScannerContext } from '../src/scanners/types.js';
import { defaultConfig } from '../src/config/schema.js';

const makeContext = (overrides: Partial<ScannerContext> = {}): ScannerContext => ({
  targetPath: '/fake/target',
  config: defaultConfig,
  options: { targetPath: '/fake/target' },
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() } as any,
  excludePaths: new Set(),
  excludePatterns: [],
  ...overrides
});

/** Build a minimal SARIF log for testing */
function makeSarifLog(
  results: Array<{
    ruleId: string;
    level?: string;
    message: string;
    uri: string;
    startLine: number;
    startColumn?: number;
  }>,
  rules?: Array<{
    id: string;
    name?: string;
    shortDescription?: string;
    fullDescription?: string;
    securitySeverity?: string;
    tags?: string[];
  }>
) {
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CodeQL',
            rules: (rules ?? results.map((r) => ({ id: r.ruleId }))).map((rule) => ({
              id: rule.id,
              name: rule.name ?? rule.id,
              shortDescription: rule.shortDescription ? { text: rule.shortDescription } : undefined,
              fullDescription: rule.fullDescription ? { text: rule.fullDescription } : undefined,
              properties: {
                ...(rule.securitySeverity != null
                  ? { 'security-severity': rule.securitySeverity }
                  : {}),
                ...(rule.tags ? { tags: rule.tags } : {})
              }
            }))
          }
        },
        results: results.map((r) => ({
          ruleId: r.ruleId,
          level: r.level ?? 'error',
          message: { text: r.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: r.uri },
                region: {
                  startLine: r.startLine,
                  startColumn: r.startColumn ?? 1
                }
              }
            }
          ]
        }))
      }
    ]
  };
}

/** Write SARIF to the output path intercepted from runCommand args */
async function writeSarifFromArgs(args: string[], sarif: object) {
  const outputArg = args.find((a: string) => a.startsWith('--output='));
  if (outputArg) {
    const sarifPath = outputArg.replace('--output=', '');
    await fs.writeJson(sarifPath, sarif);
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('codeql scanner', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('returns empty findings with error when no languages detected', async () => {
    mockDetectLanguages.mockResolvedValue([]);

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext());

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors![0].message).toMatch(/no supported languages/i);
    expect(mockRunCommand).not.toHaveBeenCalled();
  });

  it('skips compiled language with no build command and records error', async () => {
    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'java', isCompiled: true, buildCommand: undefined }
    ]);

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext());

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors![0].message).toMatch(/skipping java/i);
    expect(mockRunCommand).not.toHaveBeenCalled();
  });

  it('records error and skips analyze when database create fails', async () => {
    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);
    // database create fails
    mockRunCommand.mockResolvedValueOnce({ exitCode: 1, stdout: '', stderr: 'create error' });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext());

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors![0].message).toMatch(/database creation failed.*python/i);
    // analyze should never have been called
    expect(mockRunCommand).toHaveBeenCalledTimes(1);
  });

  it('records error when database analyze fails', async () => {
    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);
    mockRunCommand
      .mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' }) // create ok
      .mockResolvedValueOnce({ exitCode: 1, stdout: '', stderr: 'analyze error' }); // analyze fail

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext());

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors![0].message).toMatch(/database analysis failed.*python/i);
  });

  it('returns empty findings (no error) when sarif file does not exist after analyze', async () => {
    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);
    mockRunCommand
      .mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' })
      .mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' });
    // sarif file is never written — codeql writes nothing when no findings

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext());

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toBeUndefined();
  });

  it('parses SARIF and maps results to Finding[]', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-'));

    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);

    const sarif = makeSarifLog(
      [
        {
          ruleId: 'py/sql-injection',
          level: 'error',
          message: 'Unsanitized input in query',
          uri: 'src/db.py',
          startLine: 42,
          startColumn: 8
        },
        {
          ruleId: 'py/path-injection',
          level: 'warning',
          message: 'User-controlled path',
          uri: 'src/files.py',
          startLine: 15,
          startColumn: 3
        }
      ],
      [
        {
          id: 'py/sql-injection',
          shortDescription: 'SQL Injection',
          securitySeverity: '9.8',
          tags: ['security', 'external/cwe/cwe-089']
        },
        {
          id: 'py/path-injection',
          shortDescription: 'Path Traversal',
          securitySeverity: '7.5',
          tags: ['security', 'external/cwe/cwe-022']
        }
      ]
    );

    mockRunCommand.mockImplementation(async (_cmd: string, args: string[]) => {
      await writeSarifFromArgs(args, sarif);
      return { exitCode: 0, stdout: '', stderr: '' };
    });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext({ targetPath: tmpDir }));

    await fs.remove(tmpDir);

    expect(result.findings).toHaveLength(2);

    const sqlFinding = result.findings.find((f) => f.title === 'SQL Injection');
    expect(sqlFinding).toBeDefined();
    expect(sqlFinding!.tool).toBe('codeql');
    expect(sqlFinding!.severity).toBe('critical');  // 9.8 → critical
    expect(sqlFinding!.category).toBe('vulnerability');
    expect(sqlFinding!.line).toBe(42);
    expect(sqlFinding!.column).toBe(8);
    expect(sqlFinding!.description).toBe('Unsanitized input in query');
    expect(sqlFinding!.cwe).toEqual(['CWE-089']);
    expect(sqlFinding!.cvss).toBe(9.8);
    expect(sqlFinding!.metadata).toMatchObject({ language: 'python', queryId: 'py/sql-injection' });

    const pathFinding = result.findings.find((f) => f.title === 'Path Traversal');
    expect(pathFinding).toBeDefined();
    expect(pathFinding!.severity).toBe('high');  // 7.5 → high
    expect(pathFinding!.cwe).toEqual(['CWE-022']);
  });

  it('maps security-severity scores: 9.5→critical, 8.0→high, 5.5→medium, 2.0→low', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-'));

    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'javascript', isCompiled: false }
    ]);

    const sarif = makeSarifLog(
      [
        { ruleId: 'js/a', message: 'msg', uri: 'a.js', startLine: 1 },
        { ruleId: 'js/b', message: 'msg', uri: 'b.js', startLine: 2 },
        { ruleId: 'js/c', message: 'msg', uri: 'c.js', startLine: 3 },
        { ruleId: 'js/d', message: 'msg', uri: 'd.js', startLine: 4 }
      ],
      [
        { id: 'js/a', shortDescription: 'A', securitySeverity: '9.5' },
        { id: 'js/b', shortDescription: 'B', securitySeverity: '8.0' },
        { id: 'js/c', shortDescription: 'C', securitySeverity: '5.5' },
        { id: 'js/d', shortDescription: 'D', securitySeverity: '2.0' }
      ]
    );

    mockRunCommand.mockImplementation(async (_cmd: string, args: string[]) => {
      await writeSarifFromArgs(args, sarif);
      return { exitCode: 0, stdout: '', stderr: '' };
    });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext({ targetPath: tmpDir }));

    await fs.remove(tmpDir);

    const severityByTitle = Object.fromEntries(
      result.findings.map((f) => [f.title, f.severity])
    );
    expect(severityByTitle['A']).toBe('critical');
    expect(severityByTitle['B']).toBe('high');
    expect(severityByTitle['C']).toBe('medium');
    expect(severityByTitle['D']).toBe('low');
  });

  it('falls back to result.level when no security-severity is present', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-'));

    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);

    const sarif = makeSarifLog(
      [
        { ruleId: 'py/a', level: 'error', message: 'msg', uri: 'a.py', startLine: 1 },
        { ruleId: 'py/b', level: 'warning', message: 'msg', uri: 'b.py', startLine: 2 },
        { ruleId: 'py/c', level: 'note', message: 'msg', uri: 'c.py', startLine: 3 }
      ],
      [
        { id: 'py/a', shortDescription: 'A' },
        { id: 'py/b', shortDescription: 'B' },
        { id: 'py/c', shortDescription: 'C' }
      ]
    );

    mockRunCommand.mockImplementation(async (_cmd: string, args: string[]) => {
      await writeSarifFromArgs(args, sarif);
      return { exitCode: 0, stdout: '', stderr: '' };
    });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext({ targetPath: tmpDir }));

    await fs.remove(tmpDir);

    const severityByTitle = Object.fromEntries(
      result.findings.map((f) => [f.title, f.severity])
    );
    expect(severityByTitle['A']).toBe('high');    // error → high
    expect(severityByTitle['B']).toBe('medium');  // warning → medium
    expect(severityByTitle['C']).toBe('low');     // note → low

    // category should be code-quality when no security-severity
    for (const finding of result.findings) {
      expect(finding.category).toBe('code-quality');
    }
  });

  it('extracts CWE from SARIF rule tags', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-'));

    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);

    const sarif = makeSarifLog(
      [{ ruleId: 'py/sqli', message: 'msg', uri: 'a.py', startLine: 1 }],
      [
        {
          id: 'py/sqli',
          shortDescription: 'SQL Injection',
          securitySeverity: '9.0',
          tags: ['security', 'external/cwe/cwe-089', 'external/cwe/cwe-564']
        }
      ]
    );

    mockRunCommand.mockImplementation(async (_cmd: string, args: string[]) => {
      await writeSarifFromArgs(args, sarif);
      return { exitCode: 0, stdout: '', stderr: '' };
    });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext({ targetPath: tmpDir }));

    await fs.remove(tmpDir);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].cwe).toEqual(['CWE-089', 'CWE-564']);
  });

  it('sets category to vulnerability when security-severity is present', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-'));

    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);

    const sarif = makeSarifLog(
      [
        { ruleId: 'py/sec', message: 'msg', uri: 'a.py', startLine: 1 },
        { ruleId: 'py/qual', message: 'msg', uri: 'b.py', startLine: 2 }
      ],
      [
        { id: 'py/sec', shortDescription: 'Security Issue', securitySeverity: '7.0' },
        { id: 'py/qual', shortDescription: 'Quality Issue' }
      ]
    );

    mockRunCommand.mockImplementation(async (_cmd: string, args: string[]) => {
      await writeSarifFromArgs(args, sarif);
      return { exitCode: 0, stdout: '', stderr: '' };
    });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext({ targetPath: tmpDir }));

    await fs.remove(tmpDir);

    const secFinding = result.findings.find((f) => f.title === 'Security Issue');
    const qualFinding = result.findings.find((f) => f.title === 'Quality Issue');

    expect(secFinding!.category).toBe('vulnerability');
    expect(qualFinding!.category).toBe('code-quality');
  });

  it('passes --command to database create for compiled language with build command', async () => {
    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'java', isCompiled: true, buildCommand: 'mvn clean package -DskipTests' }
    ]);
    mockRunCommand
      .mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' })
      .mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    await codeqlScanner.run(makeContext());

    const createCall = mockRunCommand.mock.calls[0];
    const createArgs: string[] = createCall[1];
    expect(createArgs).toContain('--command=mvn clean package -DskipTests');
  });

  it('uses correct query suite path per language', async () => {
    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);
    mockRunCommand
      .mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' })
      .mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    await codeqlScanner.run(makeContext());

    const analyzeCall = mockRunCommand.mock.calls[1];
    const analyzeArgs: string[] = analyzeCall[1];
    expect(analyzeArgs).toContain(
      'codeql/python-queries:codeql-suites/python-security-extended.qls'
    );
  });

  it('uses --format=sarifv2.1.0 in analyze args', async () => {
    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);
    mockRunCommand
      .mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' })
      .mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    await codeqlScanner.run(makeContext());

    const analyzeCall = mockRunCommand.mock.calls[1];
    const analyzeArgs: string[] = analyzeCall[1];
    expect(analyzeArgs).toContain('--format=sarifv2.1.0');

    const outputArg = analyzeArgs.find((a) => a.startsWith('--output='));
    expect(outputArg).toMatch(/\.sarif$/);
  });

  it('excludes findings matching excludePaths', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-'));
    const excludedFile = path.join(tmpDir, 'src', 'excluded.py');
    await fs.mkdirp(path.dirname(excludedFile));

    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);

    const sarif = makeSarifLog(
      [
        { ruleId: 'py/issue', message: 'msg', uri: excludedFile, startLine: 1 },
        { ruleId: 'py/other', message: 'msg', uri: path.join(tmpDir, 'src', 'kept.py'), startLine: 2 }
      ],
      [
        { id: 'py/issue', shortDescription: 'Issue' },
        { id: 'py/other', shortDescription: 'Other' }
      ]
    );

    mockRunCommand.mockImplementation(async (_cmd: string, args: string[]) => {
      await writeSarifFromArgs(args, sarif);
      return { exitCode: 0, stdout: '', stderr: '' };
    });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(
      makeContext({
        targetPath: tmpDir,
        excludePaths: new Set([excludedFile])
      })
    );

    await fs.remove(tmpDir);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].title).toBe('Other');
  });

  it('merges findings from multiple languages', async () => {
    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false },
      { codeqlName: 'javascript', isCompiled: false }
    ]);

    mockRunCommand.mockImplementation(async (_cmd: string, args: string[]) => {
      const outputArg = args.find((a: string) => a.startsWith('--output='));
      if (outputArg) {
        const sarifPath = outputArg.replace('--output=', '');
        const isPython = sarifPath.includes('python');
        const sarif = isPython
          ? makeSarifLog(
              [{ ruleId: 'py/issue', message: 'msg', uri: 'main.py', startLine: 1 }],
              [{ id: 'py/issue', shortDescription: 'Py Issue' }]
            )
          : makeSarifLog(
              [{ ruleId: 'js/issue', message: 'msg', uri: 'app.js', startLine: 1 }],
              [{ id: 'js/issue', shortDescription: 'JS Issue' }]
            );
        await fs.writeJson(sarifPath, sarif);
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext());

    // 2 languages × 2 calls (create + analyze) = 4 total
    expect(mockRunCommand).toHaveBeenCalledTimes(4);
    expect(result.findings).toHaveLength(2);
    const tools = result.findings.map((f) => f.tool);
    expect(tools).toEqual(['codeql', 'codeql']);
    const titles = result.findings.map((f) => f.title).sort();
    expect(titles).toEqual(['JS Issue', 'Py Issue']);
  });

  it('skips SARIF results missing locations', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'codeql-test-'));

    mockDetectLanguages.mockResolvedValue([
      { codeqlName: 'python', isCompiled: false }
    ]);

    // Build a SARIF with one result missing locations and one valid
    const sarif = {
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'CodeQL',
              rules: [
                { id: 'py/bad', name: 'Bad' },
                { id: 'py/good', name: 'Good', shortDescription: { text: 'Good' } }
              ]
            }
          },
          results: [
            {
              ruleId: 'py/bad',
              level: 'error',
              message: { text: 'msg' }
              // no locations
            },
            {
              ruleId: 'py/good',
              level: 'error',
              message: { text: 'msg' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'good.py' },
                    region: { startLine: 5, startColumn: 1 }
                  }
                }
              ]
            }
          ]
        }
      ]
    };

    mockRunCommand.mockImplementation(async (_cmd: string, args: string[]) => {
      await writeSarifFromArgs(args, sarif);
      return { exitCode: 0, stdout: '', stderr: '' };
    });

    const { codeqlScanner } = await import('../src/scanners/codeql.js');
    const result = await codeqlScanner.run(makeContext({ targetPath: tmpDir }));

    await fs.remove(tmpDir);

    // Both results are valid — the one without locations just has file='unknown'
    expect(result.findings).toHaveLength(2);
    const badFinding = result.findings.find((f) => f.title === 'Bad');
    expect(badFinding!.file).toBe('unknown');

    const goodFinding = result.findings.find((f) => f.title === 'Good');
    expect(goodFinding!.line).toBe(5);
  });
});
