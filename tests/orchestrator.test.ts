import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import { defaultConfig } from '../src/config/schema.js';
import { Finding, ScanOptions } from '../src/types.js';

const gitleaksRun = vi.fn();
const trivyRun = vi.fn();
const semgrepRun = vi.fn();
const npmAuditRun = vi.fn();

vi.mock('../src/scanners/gitleaks.js', () => ({
  gitleaksScanner: { name: 'gitleaks', run: gitleaksRun }
}));
vi.mock('../src/scanners/trivy.js', () => ({
  trivyScanner: { name: 'trivy', run: trivyRun }
}));
vi.mock('../src/scanners/semgrep.js', () => ({
  semgrepScanner: { name: 'semgrep', run: semgrepRun }
}));
vi.mock('../src/scanners/npmAudit.js', () => ({
  npmAuditScanner: { name: 'npm-audit', run: npmAuditRun }
}));

const createFinding = (
  tool: string,
  id: string,
  severity: Finding['severity'],
  cve?: string
): Finding => ({
  id,
  tool,
  severity,
  category: 'vulnerability',
  title: `Finding ${id}`,
  description: 'Test finding',
  file: 'src/index.ts',
  cve
});

describe('runScan', () => {
  beforeEach(() => {
    gitleaksRun.mockReset();
    trivyRun.mockReset();
    semgrepRun.mockReset();
    npmAuditRun.mockReset();
  });

  it('aggregates findings from scanners', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'scan-test-'));
    gitleaksRun.mockResolvedValue({
      tool: 'gitleaks',
      findings: [createFinding('gitleaks', '1', 'high', 'CVE-2024-0001')]
    });
    trivyRun.mockResolvedValue({ tool: 'trivy', findings: [createFinding('trivy', '2', 'medium')] });
    semgrepRun.mockResolvedValue({ tool: 'semgrep', findings: [] });
    npmAuditRun.mockResolvedValue({ tool: 'npm-audit', findings: [] });

    const { runScan } = await import('../src/orchestrator.js');
    const config = { ...defaultConfig, cache: { enabled: false, ttl: 0 } };
    const options: ScanOptions = { targetPath: tmpDir };

    const report = await runScan(config, options);

    expect(report.findings).toHaveLength(2);
    expect(report.summary.by_tool.gitleaks).toBe(1);
    expect(report.cves).toEqual(['CVE-2024-0001']);
    expect(report.summary.by_tool.trivy).toBe(1);
  });

  it('filters by severity threshold', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'scan-test-'));
    gitleaksRun.mockResolvedValue({ tool: 'gitleaks', findings: [createFinding('gitleaks', '1', 'high')] });
    trivyRun.mockResolvedValue({ tool: 'trivy', findings: [createFinding('trivy', '2', 'low')] });
    semgrepRun.mockResolvedValue({ tool: 'semgrep', findings: [] });
    npmAuditRun.mockResolvedValue({ tool: 'npm-audit', findings: [] });

    const { runScan } = await import('../src/orchestrator.js');
    const config = { ...defaultConfig, cache: { enabled: false, ttl: 0 } };
    const options: ScanOptions = { targetPath: tmpDir, severity: 'high' };

    const report = await runScan(config, options);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0].severity).toBe('high');
  });

  it('resolves file paths to their directory', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'scan-test-'));
    const filePath = path.join(tmpDir, 'pom.xml');
    await fs.writeFile(filePath, '<project></project>');

    let receivedTarget = '';
    gitleaksRun.mockImplementation(async (context: { targetPath: string }) => {
      receivedTarget = context.targetPath;
      return { tool: 'gitleaks', findings: [] };
    });

    const { runScan } = await import('../src/orchestrator.js');
    const config = { ...defaultConfig, cache: { enabled: false, ttl: 0 } };
    const options: ScanOptions = { targetPath: filePath, tools: ['gitleaks'] };

    await runScan(config, options);

    expect(receivedTarget).toBe(tmpDir);
  });

  it('defaults to dependency scanners for manifest paths', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'scan-test-'));
    const filePath = path.join(tmpDir, 'package.json');
    await fs.writeJson(filePath, { name: 'sample' });

    gitleaksRun.mockResolvedValue({ tool: 'gitleaks', findings: [] });
    semgrepRun.mockResolvedValue({ tool: 'semgrep', findings: [] });
    trivyRun.mockResolvedValue({ tool: 'trivy', findings: [] });
    npmAuditRun.mockResolvedValue({ tool: 'npm-audit', findings: [] });

    const { runScan } = await import('../src/orchestrator.js');
    const config = { ...defaultConfig, cache: { enabled: false, ttl: 0 } };
    const options: ScanOptions = { targetPath: filePath };

    await runScan(config, options);

    expect(trivyRun).toHaveBeenCalled();
    expect(npmAuditRun).toHaveBeenCalled();
    expect(gitleaksRun).not.toHaveBeenCalled();
    expect(semgrepRun).not.toHaveBeenCalled();
  });
});
