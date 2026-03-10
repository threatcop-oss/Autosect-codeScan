import { describe, it, expect } from 'vitest';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import { resolveTargetPath } from '../src/utils/paths.js';

describe('resolveTargetPath', () => {
  it('resolves package.json to directory', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'paths-test-'));
    const filePath = path.join(tmpDir, 'package.json');
    await fs.writeJson(filePath, { name: 'sample' });

    expect(resolveTargetPath(filePath)).toBe(tmpDir);
  });

  it('resolves pom.xml to directory', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'paths-test-'));
    const filePath = path.join(tmpDir, 'pom.xml');
    await fs.writeFile(filePath, '<project></project>');

    expect(resolveTargetPath(filePath)).toBe(tmpDir);
  });
});
