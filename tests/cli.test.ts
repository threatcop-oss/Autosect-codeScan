import { describe, it, expect } from 'vitest';
import { execa } from 'execa';

describe('cli smoke test', () => {
  it('loads help without command registration errors', async () => {
    const result = await execa('node', ['--loader', 'tsx', 'src/cli.ts', '--help'], {
      reject: false
    });

    expect(result.exitCode).toBe(0);
    expect(result.stderr).not.toContain('cannot add command');
  });

  it('loads baseline subcommand help', async () => {
    const result = await execa('node', ['--loader', 'tsx', 'src/cli.ts', 'baseline', '--help'], {
      reject: false
    });

    expect(result.exitCode).toBe(0);
    expect(result.stderr).not.toContain('cannot add command');
  });
});
