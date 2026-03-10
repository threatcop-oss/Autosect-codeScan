import { ScanReport, Finding } from '../types.js';

const levelFromSeverity = (severity: Finding['severity']): string => {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
};

export const renderSarif = (report: ScanReport): string => {
  const rulesMap = new Map<string, any>();
  const results = report.findings.map((finding) => {
    const ruleId = `${finding.tool}-${finding.title}`.replace(/\s+/g, '-').toLowerCase();
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description }
      });
    }

    return {
      ruleId,
      level: levelFromSeverity(finding.severity),
      message: { text: finding.description },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.file
            },
            region: {
              startLine: finding.line ?? 1,
              startColumn: finding.column ?? 1
            }
          }
        }
      ]
    };
  });

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'code-scanner',
            informationUri: 'https://github.com/openai/codex',
            rules: Array.from(rulesMap.values())
          }
        },
        results
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
};
