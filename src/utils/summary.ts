import { Finding, ScanReport } from '../types.js';

export const buildSummary = (findings: Finding[]): ScanReport['summary'] => {
  const summary: ScanReport['summary'] = {
    total: findings.length,
    by_severity: {},
    by_category: {},
    by_tool: {}
  };

  for (const finding of findings) {
    summary.by_severity[finding.severity] = (summary.by_severity[finding.severity] ?? 0) + 1;
    summary.by_category[finding.category] = (summary.by_category[finding.category] ?? 0) + 1;
    summary.by_tool[finding.tool] = (summary.by_tool[finding.tool] ?? 0) + 1;
  }

  return summary;
};
