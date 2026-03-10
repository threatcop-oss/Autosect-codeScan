import { ScanReport } from '../types.js';

export const renderMarkdown = (report: ScanReport): string => {
  const lines = [
    '# Security Scan Report',
    '',
    `- Timestamp: ${report.timestamp}`,
    `- Total Findings: ${report.summary.total}`,
    `- Repository: ${report.repository ?? 'N/A'}`,
    `- Commit: ${report.commit ?? 'N/A'}`,
    ''
  ];

  lines.push('## Summary', '');
  for (const [severity, count] of Object.entries(report.summary.by_severity)) {
    lines.push(`- ${severity}: ${count}`);
  }

  lines.push('', '## CVEs', '');
  if (report.cves?.length) {
    for (const cve of report.cves) {
      lines.push(`- ${cve}`);
    }
  } else {
    lines.push('- None');
  }

  lines.push('', '## Findings', '');
  for (const finding of report.findings) {
    lines.push(`- **${finding.severity.toUpperCase()}** ${finding.title}`);
    lines.push(
      `  - Tool: ${finding.tool}`,
      `  - CVE: ${finding.cve ?? 'None'}`,
      `  - File: ${finding.file}${finding.line ? `:${finding.line}` : ''}`,
      `  - Description: ${finding.description}`
    );
  }

  return lines.join('\n');
};
