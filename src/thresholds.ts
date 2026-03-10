import { ScanReport, Severity, ThresholdConfig } from './types.js';
import { isSeverityAtLeast } from './utils/severity.js';

export const evaluateThresholds = (
  report: ScanReport,
  thresholds: ThresholdConfig
): { exitCode: number; reasons: string[] } => {
  const reasons: string[] = [];
  const bySeverity = report.summary.by_severity;

  if (thresholds.failOn) {
    const violating = report.findings.filter((finding) =>
      isSeverityAtLeast(finding.severity, thresholds.failOn as Severity)
    );
    if (violating.length > 0) {
      reasons.push(`Findings at or above ${thresholds.failOn}: ${violating.length}`);
    }
  }

  if (thresholds.maxCritical !== undefined && (bySeverity.critical ?? 0) > thresholds.maxCritical) {
    reasons.push(`Critical findings exceed ${thresholds.maxCritical}`);
  }
  if (thresholds.maxHigh !== undefined && (bySeverity.high ?? 0) > thresholds.maxHigh) {
    reasons.push(`High findings exceed ${thresholds.maxHigh}`);
  }
  if (thresholds.maxMedium !== undefined && (bySeverity.medium ?? 0) > thresholds.maxMedium) {
    reasons.push(`Medium findings exceed ${thresholds.maxMedium}`);
  }
  if (thresholds.maxLow !== undefined && (bySeverity.low ?? 0) > thresholds.maxLow) {
    reasons.push(`Low findings exceed ${thresholds.maxLow}`);
  }

  return { exitCode: reasons.length ? 1 : 0, reasons };
};
