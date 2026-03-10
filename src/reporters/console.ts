import chalk from 'chalk';
import { table } from 'table';
import { ScanReport } from '../types.js';

export const renderConsole = (report: ScanReport): string => {
  const terminalWidth = process.stdout.columns ?? 120;
  const columns = [
    { min: 8, weight: 1 },
    { min: 8, weight: 1 },
    { min: 20, weight: 4 },
    { min: 14, weight: 2 },
    { min: 12, weight: 2 },
    { min: 12, weight: 2 },
    { min: 20, weight: 4 }
  ];
  const overhead = 3 * columns.length + 1;
  const available = Math.max(40, terminalWidth - overhead);
  const weightSum = columns.reduce((sum, column) => sum + column.weight, 0);
  let widths = columns.map((column) =>
    Math.max(column.min, Math.floor((available * column.weight) / weightSum))
  );
  let totalWidth = widths.reduce((sum, width) => sum + width, 0);
  while (totalWidth > available) {
    const reducible = widths
      .map((width, index) => ({ width, index, min: columns[index].min }))
      .filter((item) => item.width > item.min)
      .sort((a, b) => b.width - a.width);
    if (!reducible.length) break;
    for (const item of reducible) {
      if (totalWidth <= available) break;
      widths[item.index] -= 1;
      totalWidth -= 1;
    }
  }

  const summaryRows = [
    ['Severity', 'Count'],
    ...Object.entries(report.summary.by_severity).map(([severity, count]) => [
      severity,
      String(count)
    ])
  ];

  const toolOrder = ['gitleaks', 'trivy', 'semgrep', 'npm-audit'];
  const byToolRows = [
    ['Tool', 'Count'],
    ...toolOrder.map((tool) => [tool, String(report.summary.by_tool[tool] ?? 0)])
  ];
  const byToolTable = table(byToolRows);

  const getVersion = (
    finding: ScanReport['findings'][number],
    key: 'installedVersion' | 'fixedVersion'
  ): string => {
    const directValue = finding[key];
    if (typeof directValue === 'string' && directValue.length > 0) {
      return directValue;
    }
    const metadata = finding.metadata as Record<string, unknown> | undefined;
    const metaValue = metadata?.[key];
    return typeof metaValue === 'string' && metaValue.length > 0 ? metaValue : '-';
  };

  const interleaveByTool = (findings: ScanReport['findings'], limit: number): ScanReport['findings'] => {
    const byTool = new Map<string, ScanReport['findings']>();
    for (const f of findings) {
      const list = byTool.get(f.tool) ?? [];
      list.push(f);
      byTool.set(f.tool, list);
    }
    const result: ScanReport['findings'] = [];
    const iterators = new Map<string, number>();
    for (const tool of toolOrder) {
      if ((byTool.get(tool)?.length ?? 0) > 0) iterators.set(tool, 0);
    }
    while (result.length < limit) {
      let added = 0;
      for (const tool of toolOrder) {
        const list = byTool.get(tool);
        const idx = iterators.get(tool) ?? 0;
        if (list && idx < list.length) {
          result.push(list[idx]);
          iterators.set(tool, idx + 1);
          added++;
          if (result.length >= limit) break;
        }
      }
      if (added === 0) break;
    }
    return result;
  };

  const allFindings = interleaveByTool(report.findings, report.findings.length);
  const findingsRows = [
    ['Severity', 'Tool', 'Title', 'CVE', 'Installed', 'Fixed', 'File'],
    ...allFindings.map((finding) => [
      finding.severity,
      finding.tool,
      finding.title,
      finding.cve ?? '-',
      getVersion(finding, 'installedVersion'),
      getVersion(finding, 'fixedVersion'),
      `${finding.file}${finding.line ? `:${finding.line}` : ''}`
    ])
  ];

  const summaryTable = table(summaryRows);
  const findingsTable = table(findingsRows, {
    columns: {
      0: { width: widths[0], wrapWord: true },
      1: { width: widths[1], wrapWord: true },
      2: { width: widths[2], wrapWord: true },
      3: { width: widths[3], wrapWord: true },
      4: { width: widths[4], wrapWord: true },
      5: { width: widths[5], wrapWord: true },
      6: { width: widths[6], wrapWord: true }
    }
  });

  const header = chalk.bold('Security Scan Summary');
  const byToolHeader = chalk.bold('Findings by tool');
  const details = chalk.bold(`All Findings (${report.findings.length}, mixed by tool)`);
  const cveHeader = chalk.bold('CVEs');
  const cves =
    report.cves?.length ? report.cves.join(', ') : 'None';
  const cveNote =
    !report.cves?.length &&
    ' (CVEs come from Trivy/npm-audit/semgrep when advisories include them; Gitleaks finds secrets, not CVEs)';

  return [header, summaryTable, byToolHeader, byToolTable, cveHeader, cves + (cveNote || ''), details, findingsTable].join('\n');
};
