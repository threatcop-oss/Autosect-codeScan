import { describe, it, expect } from 'vitest';
import { evaluateThresholds } from '../src/thresholds.js';
const baseReport = {
    timestamp: new Date().toISOString(),
    duration: 0,
    summary: {
        total: 1,
        by_severity: { high: 1 },
        by_category: { vulnerability: 1 },
        by_tool: { trivy: 1 }
    },
    findings: [
        {
            id: '1',
            tool: 'trivy',
            severity: 'high',
            category: 'vulnerability',
            title: 'Test',
            description: 'Test',
            file: 'src/index.ts'
        }
    ]
};
describe('evaluateThresholds', () => {
    it('returns exit code when failOn is exceeded', () => {
        const result = evaluateThresholds(baseReport, { failOn: 'high' });
        expect(result.exitCode).toBe(1);
        expect(result.reasons.length).toBeGreaterThan(0);
    });
    it('returns zero when thresholds pass', () => {
        const result = evaluateThresholds(baseReport, { failOn: 'critical' });
        expect(result.exitCode).toBe(0);
    });
});
//# sourceMappingURL=thresholds.test.js.map