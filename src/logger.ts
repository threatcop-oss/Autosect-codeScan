import { pino } from 'pino';
import type { Logger as PinoLogger } from 'pino';

export interface LoggerOptions {
  verbose?: boolean;
  quiet?: boolean;
}

export type Logger = PinoLogger;

export const createLogger = (options: LoggerOptions = {}): Logger => {
  // When quiet (script): show info/warn, but error messages are gated in cli.ts
  const level = options.verbose ? 'debug' : 'info';
  return pino({
    level,
    transport:
      process.env.NODE_ENV === 'production'
        ? undefined
        : {
            target: 'pino-pretty',
            options: {
              colorize: true,
              translateTime: 'SYS:standard'
            }
          }
  });
};
