import { describe, it, expect, vi } from 'vitest';
import path from 'path';
import fs from 'fs-extra';
import os from 'os';
import { defaultConfig } from '../src/config/schema.js';

const runCommand = vi.fn().mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });

vi.mock('../src/scanners/runner.js', () => ({
  runCommand
}));

describe('trivy scanner', () => {
  it('uses manifest path when provided', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'trivy-test-'));
    const manifestPath = path.join(tmpDir, 'pom.xml');
    await fs.writeFile(manifestPath, '<project></project>');

    const { trivyScanner } = await import('../src/scanners/trivy.js');

    await trivyScanner.run({
      targetPath: tmpDir,
      config: defaultConfig,
      options: { targetPath: tmpDir, manifestPath, manifestType: 'maven' },
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as any,
      excludePaths: new Set(),
      excludePatterns: []
    });

    const lastArgs = runCommand.mock.calls.at(-1)?.[1] as string[];
    expect(lastArgs[lastArgs.length - 1]).toBe(manifestPath);

    await fs.remove(tmpDir);
  });

  it('parses array-style results', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'trivy-test-'));
    const reportPath = path.join(os.tmpdir(), 'trivy-report-123.json');
    const raw = [
      {
        Target: 'pom.xml',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2024-0002',
            Severity: 'HIGH',
            PkgName: 'demo'
          }
        ]
      }
    ];
    await fs.writeJson(reportPath, raw);

    runCommand.mockResolvedValueOnce({ stdout: '', stderr: '', exitCode: 0 });

    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(123);

    const { trivyScanner } = await import('../src/scanners/trivy.js');

    const result = await trivyScanner.run({
      targetPath: tmpDir,
      config: defaultConfig,
      options: { targetPath: tmpDir },
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as any,
      excludePaths: new Set(),
      excludePatterns: []
    });

    expect(result.findings.length).toBeGreaterThan(0);

    await fs.remove(tmpDir);
    await fs.remove(reportPath);
    nowSpy.mockRestore();
  });
});
