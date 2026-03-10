import crypto from 'crypto';
import { Finding } from '../types.js';

const buildKey = (finding: Finding): string => {
  if (finding.id && finding.tool) {
    return `${finding.tool}:${finding.id}`;
  }
  const key = [
    finding.file,
    finding.line ?? '',
    finding.title,
    finding.severity,
    finding.category
  ].join('|');
  return crypto.createHash('sha256').update(key).digest('hex');
};

export const dedupeFindings = (findings: Finding[]): Finding[] => {
  const seen = new Map<string, Finding>();
  for (const finding of findings) {
    const key = buildKey(finding);
    if (!seen.has(key)) {
      seen.set(key, finding);
    }
  }
  return Array.from(seen.values());
};
