import { ScanConfig } from '../types.js';

export const defaultConfig: ScanConfig = {
  scanners: {
    gitleaks: { enabled: true },
    trivy: { enabled: true },
    semgrep: { enabled: true },
    npmAudit: { enabled: true },
    horusec: { enabled: true }
  },
  output: {
    format: 'console',
    console: true
  },
  thresholds: {},
  exclude: ['**/node_modules/**', '**/vendor/**', '**/.git/**', '**/.next/**', '**/dist/**', '**/build/**', '**/.security-scan-cache/**'],
  cache: {
    enabled: true,
    ttl: 86400
  },
  execution: {
    parallel: true,
    continueOnError: true
  }
};

export const configSchema = {
  type: 'object',
  properties: {
    scanners: {
      type: 'object',
      properties: {
        gitleaks: {
          type: 'object',
          properties: {
            enabled: { type: 'boolean' },
            config: { type: 'string' },
            args: { type: 'array', items: { type: 'string' } }
          },
          additionalProperties: true
        },
        trivy: {
          type: 'object',
          properties: {
            enabled: { type: 'boolean' },
            severity: { type: 'string' },
            vulnType: { type: 'string' },
            config: { type: 'string' },
            args: { type: 'array', items: { type: 'string' } }
          },
          additionalProperties: true
        },
        semgrep: {
          type: 'object',
          properties: {
            enabled: { type: 'boolean' },
            config: { type: 'string' },
            rules: { type: 'array', items: { type: 'string' } },
            args: { type: 'array', items: { type: 'string' } }
          },
          additionalProperties: true
        },
        'npm-audit': {
          type: 'object',
          properties: {
            enabled: { type: 'boolean' },
            auditLevel: { type: 'string' },
            args: { type: 'array', items: { type: 'string' } }
          },
          additionalProperties: true
        },
        horusec: {
          type: 'object',
          properties: {
            enabled: { type: 'boolean' },
            disableDocker: { type: 'boolean' },
            args: { type: 'array', items: { type: 'string' } }
          },
          additionalProperties: true
        }
      },
      additionalProperties: true
    },
    output: {
      type: 'object',
      properties: {
        format: { type: 'string' },
        file: { type: 'string' },
        console: { type: 'boolean' }
      },
      additionalProperties: true
    },
    thresholds: {
      type: 'object',
      properties: {
        failOn: { type: 'string' },
        maxCritical: { type: 'number' },
        maxHigh: { type: 'number' },
        maxMedium: { type: 'number' },
        maxLow: { type: 'number' }
      },
      additionalProperties: true
    },
    exclude: {
      type: 'array',
      items: { type: 'string' }
    },
    cache: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean' },
        ttl: { type: 'number' }
      },
      additionalProperties: true
    },
    execution: {
      type: 'object',
      properties: {
        parallel: { type: 'boolean' },
        continueOnError: { type: 'boolean' }
      },
      additionalProperties: true
    }
  },
  additionalProperties: true
};
