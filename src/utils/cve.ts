import { Finding } from '../types.js';

const cvePattern = /CVE-\d{4}-\d{4,7}/gi;

export const extractCvesFromSources = (
  ...sources: Array<string | string[] | undefined | null>
): string[] => {
  const cveSet = new Set<string>();
  for (const source of sources) {
    if (!source) continue;
    const values = Array.isArray(source) ? source : [source];
    for (const value of values) {
      if (!value) continue;
      const matches = value.match(cvePattern);
      if (matches) {
        for (const match of matches) {
          cveSet.add(match.toUpperCase());
        }
      }
    }
  }
  return Array.from(cveSet.values());
};

export const extractCves = (findings: Finding[]): string[] => {
  const cveSet = new Set<string>();
  for (const finding of findings) {
    if (finding.cve) {
      for (const entry of finding.cve.split(/[\s,]+/)) {
        const trimmed = entry.trim();
        if (trimmed) {
          cveSet.add(trimmed.toUpperCase());
        }
      }
    }
    if (finding.metadata && typeof finding.metadata === 'object') {
      const meta = finding.metadata as Record<string, unknown>;
      const fromMeta = extractCvesFromSources(
        meta.cve as string | string[] | undefined,
        meta.cves as string | string[] | undefined,
        meta.url as string | undefined,
        JSON.stringify(finding.metadata)
      );
      fromMeta.forEach((c) => cveSet.add(c));
    }
  }
  return Array.from(cveSet.values()).sort();
};
