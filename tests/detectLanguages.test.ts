import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import {
  extensionToLanguage,
  inferBuildCommand,
  detectLanguages
} from '../src/utils/detectLanguages.js';

// ---------------------------------------------------------------------------
// extensionToLanguage
// ---------------------------------------------------------------------------

describe('extensionToLanguage', () => {
  it.each([
    ['.js', 'javascript'],
    ['.jsx', 'javascript'],
    ['.ts', 'javascript'],
    ['.tsx', 'javascript'],
    ['.mjs', 'javascript'],
    ['.cjs', 'javascript'],
    ['.py', 'python'],
    ['.pyw', 'python'],
    ['.java', 'java'],
    ['.kt', 'java'],
    ['.kts', 'java'],
    ['.cs', 'csharp'],
    ['.cpp', 'cpp'],
    ['.cc', 'cpp'],
    ['.cxx', 'cpp'],
    ['.c', 'cpp'],
    ['.h', 'cpp'],
    ['.hpp', 'cpp'],
    ['.go', 'go'],
    ['.rb', 'ruby'],
    ['.swift', 'swift']
  ])('maps %s → %s', (ext, expected) => {
    expect(extensionToLanguage(ext)).toBe(expected);
  });

  it('returns null for unknown extensions', () => {
    expect(extensionToLanguage('.txt')).toBeNull();
    expect(extensionToLanguage('.json')).toBeNull();
    expect(extensionToLanguage('.md')).toBeNull();
    expect(extensionToLanguage('')).toBeNull();
  });

  it('is case-insensitive', () => {
    expect(extensionToLanguage('.JS')).toBe('javascript');
    expect(extensionToLanguage('.PY')).toBe('python');
    expect(extensionToLanguage('.Java')).toBe('java');
  });
});

// ---------------------------------------------------------------------------
// inferBuildCommand
// ---------------------------------------------------------------------------

describe('inferBuildCommand', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-lang-test-'));
  });

  afterEach(async () => {
    await fs.remove(tmpDir);
  });

  describe('java', () => {
    it('returns mvn command when pom.xml exists', async () => {
      await fs.writeFile(path.join(tmpDir, 'pom.xml'), '<project/>');
      expect(await inferBuildCommand(tmpDir, 'java')).toBe('mvn clean package -DskipTests');
    });

    it('returns gradle command when build.gradle exists', async () => {
      await fs.writeFile(path.join(tmpDir, 'build.gradle'), '');
      expect(await inferBuildCommand(tmpDir, 'java')).toBe('gradle build -x test');
    });

    it('returns gradle command when build.gradle.kts exists', async () => {
      await fs.writeFile(path.join(tmpDir, 'build.gradle.kts'), '');
      expect(await inferBuildCommand(tmpDir, 'java')).toBe('gradle build -x test');
    });

    it('returns null when no build file found', async () => {
      expect(await inferBuildCommand(tmpDir, 'java')).toBeNull();
    });
  });

  describe('csharp', () => {
    it('returns dotnet build when .csproj exists', async () => {
      await fs.writeFile(path.join(tmpDir, 'MyApp.csproj'), '');
      expect(await inferBuildCommand(tmpDir, 'csharp')).toBe('dotnet build');
    });

    it('returns dotnet build when .sln exists', async () => {
      await fs.writeFile(path.join(tmpDir, 'MyApp.sln'), '');
      expect(await inferBuildCommand(tmpDir, 'csharp')).toBe('dotnet build');
    });

    it('returns null when no build file found', async () => {
      expect(await inferBuildCommand(tmpDir, 'csharp')).toBeNull();
    });
  });

  describe('cpp', () => {
    it('returns cmake command when CMakeLists.txt exists', async () => {
      await fs.writeFile(path.join(tmpDir, 'CMakeLists.txt'), '');
      expect(await inferBuildCommand(tmpDir, 'cpp')).toBe('cmake . && make');
    });

    it('returns make when Makefile exists', async () => {
      await fs.writeFile(path.join(tmpDir, 'Makefile'), '');
      expect(await inferBuildCommand(tmpDir, 'cpp')).toBe('make');
    });

    it('returns null when no build file found', async () => {
      expect(await inferBuildCommand(tmpDir, 'cpp')).toBeNull();
    });
  });

  describe('go', () => {
    it('returns go build when go.mod exists', async () => {
      await fs.writeFile(path.join(tmpDir, 'go.mod'), 'module example.com/app\n\ngo 1.21\n');
      expect(await inferBuildCommand(tmpDir, 'go')).toBe('go build ./...');
    });

    it('returns null when no go.mod found', async () => {
      expect(await inferBuildCommand(tmpDir, 'go')).toBeNull();
    });
  });

  describe('swift', () => {
    it('returns swift build when Package.swift exists', async () => {
      await fs.writeFile(path.join(tmpDir, 'Package.swift'), '');
      expect(await inferBuildCommand(tmpDir, 'swift')).toBe('swift build');
    });

    it('returns null when no Package.swift found', async () => {
      expect(await inferBuildCommand(tmpDir, 'swift')).toBeNull();
    });
  });

  describe('interpreted languages', () => {
    it('returns null for python (not compiled)', async () => {
      expect(await inferBuildCommand(tmpDir, 'python')).toBeNull();
    });

    it('returns null for javascript (not compiled)', async () => {
      expect(await inferBuildCommand(tmpDir, 'javascript')).toBeNull();
    });

    it('returns null for ruby (not compiled)', async () => {
      expect(await inferBuildCommand(tmpDir, 'ruby')).toBeNull();
    });
  });
});

// ---------------------------------------------------------------------------
// detectLanguages
// ---------------------------------------------------------------------------

describe('detectLanguages', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-lang-test-'));
  });

  afterEach(async () => {
    await fs.remove(tmpDir);
  });

  it('returns empty array for empty directory', async () => {
    expect(await detectLanguages(tmpDir)).toEqual([]);
  });

  it('detects a single interpreted language', async () => {
    await fs.writeFile(path.join(tmpDir, 'index.js'), '');
    await fs.writeFile(path.join(tmpDir, 'utils.ts'), '');

    const result = await detectLanguages(tmpDir);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ codeqlName: 'javascript', isCompiled: false });
    expect(result[0].buildCommand).toBeUndefined();
  });

  it('detects python as interpreted with no build command', async () => {
    await fs.writeFile(path.join(tmpDir, 'main.py'), '');

    const result = await detectLanguages(tmpDir);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ codeqlName: 'python', isCompiled: false });
    expect(result[0].buildCommand).toBeUndefined();
  });

  it('detects java as compiled and infers mvn build command', async () => {
    await fs.writeFile(path.join(tmpDir, 'Main.java'), '');
    await fs.writeFile(path.join(tmpDir, 'pom.xml'), '<project/>');

    const result = await detectLanguages(tmpDir);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      codeqlName: 'java',
      isCompiled: true,
      buildCommand: 'mvn clean package -DskipTests'
    });
  });

  it('detects java as compiled with no build command when no build file present', async () => {
    await fs.writeFile(path.join(tmpDir, 'Main.java'), '');

    const result = await detectLanguages(tmpDir);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ codeqlName: 'java', isCompiled: true });
    expect(result[0].buildCommand).toBeUndefined();
  });

  it('detects multiple languages in a mixed repo', async () => {
    await fs.writeFile(path.join(tmpDir, 'app.py'), '');
    await fs.writeFile(path.join(tmpDir, 'index.js'), '');
    await fs.writeFile(path.join(tmpDir, 'Main.java'), '');

    const result = await detectLanguages(tmpDir);
    const names = result.map((l) => l.codeqlName).sort();
    expect(names).toEqual(['java', 'javascript', 'python']);
  });

  it('walks subdirectories recursively', async () => {
    const subDir = path.join(tmpDir, 'src', 'lib');
    await fs.mkdirp(subDir);
    await fs.writeFile(path.join(subDir, 'helpers.py'), '');

    const result = await detectLanguages(tmpDir);
    expect(result).toHaveLength(1);
    expect(result[0].codeqlName).toBe('python');
  });

  it('ignores node_modules directory', async () => {
    const nmDir = path.join(tmpDir, 'node_modules', 'some-pkg');
    await fs.mkdirp(nmDir);
    await fs.writeFile(path.join(nmDir, 'index.js'), '');
    // only real source file
    await fs.writeFile(path.join(tmpDir, 'main.py'), '');

    const result = await detectLanguages(tmpDir);
    expect(result).toHaveLength(1);
    expect(result[0].codeqlName).toBe('python');
  });

  it('ignores other common ignored directories', async () => {
    for (const ignored of ['dist', 'build', '.git', 'vendor', 'target']) {
      const dir = path.join(tmpDir, ignored);
      await fs.mkdirp(dir);
      await fs.writeFile(path.join(dir, 'file.java'), '');
    }
    await fs.writeFile(path.join(tmpDir, 'main.py'), '');

    const result = await detectLanguages(tmpDir);
    expect(result).toHaveLength(1);
    expect(result[0].codeqlName).toBe('python');
  });

  it('ignores files with unknown extensions', async () => {
    await fs.writeFile(path.join(tmpDir, 'README.md'), '');
    await fs.writeFile(path.join(tmpDir, 'data.json'), '');
    await fs.writeFile(path.join(tmpDir, 'config.yaml'), '');

    expect(await detectLanguages(tmpDir)).toEqual([]);
  });

  it('deduplicates language even when multiple files of same type exist', async () => {
    await fs.writeFile(path.join(tmpDir, 'a.py'), '');
    await fs.writeFile(path.join(tmpDir, 'b.py'), '');
    await fs.writeFile(path.join(tmpDir, 'c.py'), '');

    const result = await detectLanguages(tmpDir);
    expect(result).toHaveLength(1);
    expect(result[0].codeqlName).toBe('python');
  });

  it('maps .kt and .kts to java codeql language', async () => {
    await fs.writeFile(path.join(tmpDir, 'Main.kt'), '');
    await fs.writeFile(path.join(tmpDir, 'build.gradle.kts'), '');

    const result = await detectLanguages(tmpDir);
    expect(result).toHaveLength(1);
    expect(result[0].codeqlName).toBe('java');
  });
});
