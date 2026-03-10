import { execa } from 'execa';
import { Logger } from '../logger.js';

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export const runCommand = async (
  command: string,
  args: string[],
  options: { cwd?: string; logger?: Logger; verbose?: boolean } = {}
): Promise<CommandResult> => {
  if (options.verbose && options.logger) {
    options.logger.info({ command, args, cwd: options.cwd }, 'Executing scanner command');
  }
  try {
    const result = await execa(command, args, {
      cwd: options.cwd,
      reject: false
    });
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.exitCode ?? 0
    };
  } catch (error) {
    if (error instanceof Error && 'code' in error && (error as any).code === 'ENOENT') {
      throw new Error(`${command} is not installed or not available in PATH.`);
    }
    throw error;
  }
};
