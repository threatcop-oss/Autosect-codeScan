import { Severity } from '../types.js';

export const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const normalizeSeverity = (value?: string): Severity => {
  if (!value) {
    return 'low';
  }

  const normalized = value.toLowerCase();
  if (normalized.startsWith('crit')) return 'critical';
  if (normalized.startsWith('high')) return 'high';
  if (normalized.startsWith('error')) return 'high';
  if (normalized.startsWith('warn')) return 'medium';
  if (normalized.startsWith('med') || normalized.startsWith('mod')) return 'medium';
  if (normalized.startsWith('low') || normalized.startsWith('rec')) return 'low';
  return 'info';
};

export const isSeverityAtLeast = (severity: Severity, threshold?: Severity): boolean => {
  if (!threshold) {
    return true;
  }

  return severityOrder.indexOf(severity) <= severityOrder.indexOf(threshold);
};

export const highestSeverity = (findings: { severity: Severity }[]): Severity | undefined => {
  if (!findings.length) {
    return undefined;
  }

  return findings.reduce((current, finding) => {
    if (!current) return finding.severity;
    return severityOrder.indexOf(finding.severity) < severityOrder.indexOf(current)
      ? finding.severity
      : current;
  }, undefined as Severity | undefined);
};
