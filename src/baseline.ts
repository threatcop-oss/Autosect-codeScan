import fs from 'fs-extra';
import { BaselineResult, Finding, ScanReport } from './types.js';

export const writeBaseline = async (report: ScanReport, baselinePath: string): Promise<void> => {
  await fs.writeJson(baselinePath, report, { spaces: 2 });
};

export const loadBaseline = async (baselinePath: string): Promise<ScanReport> => {
  return fs.readJson(baselinePath);
};

export const compareBaseline = (
  current: ScanReport,
  baseline: ScanReport
): BaselineResult => {
  const baselineMap = new Map(baseline.findings.map((finding) => [finding.id, finding]));
  const currentMap = new Map(current.findings.map((finding) => [finding.id, finding]));

  const newFindings: Finding[] = [];
  const unchangedFindings: Finding[] = [];
  const resolvedFindings: Finding[] = [];

  for (const [id, finding] of currentMap.entries()) {
    if (baselineMap.has(id)) {
      unchangedFindings.push(finding);
    } else {
      newFindings.push(finding);
    }
  }

  for (const [id, finding] of baselineMap.entries()) {
    if (!currentMap.has(id)) {
      resolvedFindings.push(finding);
    }
  }

  return { newFindings, resolvedFindings, unchangedFindings };
};
