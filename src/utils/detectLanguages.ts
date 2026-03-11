import path from 'path';
import fs from 'fs-extra';

export interface DetectedLanguage {
  codeqlName: string;
  isCompiled: boolean;
  buildCommand?: string;
}

const EXT_TO_CODEQL: Record<string, string> = {
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'javascript',
  '.tsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.py': 'python',
  '.pyw': 'python',
  '.java': 'java',
  '.kt': 'java',
  '.kts': 'java',
  '.cs': 'csharp',
  '.cpp': 'cpp',
  '.cc': 'cpp',
  '.cxx': 'cpp',
  '.c': 'cpp',
  '.h': 'cpp',
  '.hpp': 'cpp',
  '.go': 'go',
  '.rb': 'ruby',
  '.swift': 'swift'
};

const COMPILED_LANGUAGES = new Set(['java', 'csharp', 'cpp', 'go', 'swift']);

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'vendor',
  '.security-scan-cache', '__pycache__', '.venv', 'venv', 'target'
]);

export function extensionToLanguage(ext: string): string | null {
  return EXT_TO_CODEQL[ext.toLowerCase()] ?? null;
}

export async function inferBuildCommand(
  targetPath: string,
  codeqlName: string
): Promise<string | null> {
  switch (codeqlName) {
    case 'java': {
      if (await fs.pathExists(path.join(targetPath, 'pom.xml'))) {
        return 'mvn clean package -DskipTests';
      }
      if (
        await fs.pathExists(path.join(targetPath, 'build.gradle')) ||
        await fs.pathExists(path.join(targetPath, 'build.gradle.kts'))
      ) {
        return 'gradle build -x test';
      }
      return null;
    }
    case 'csharp': {
      const entries = await fs.readdir(targetPath);
      const hasCsproj = entries.some((e) => e.endsWith('.csproj'));
      const hasSln = entries.some((e) => e.endsWith('.sln'));
      if (hasSln || hasCsproj) return 'dotnet build';
      return null;
    }
    case 'cpp': {
      if (await fs.pathExists(path.join(targetPath, 'CMakeLists.txt'))) {
        return 'cmake . && make';
      }
      if (await fs.pathExists(path.join(targetPath, 'Makefile'))) {
        return 'make';
      }
      return null;
    }
    case 'go': {
      if (await fs.pathExists(path.join(targetPath, 'go.mod'))) {
        return 'go build ./...';
      }
      return null;
    }
    case 'swift': {
      if (await fs.pathExists(path.join(targetPath, 'Package.swift'))) {
        return 'swift build';
      }
      return null;
    }
    default:
      return null;
  }
}

async function walkDir(dirPath: string, langCounts: Map<string, number>): Promise<void> {
  let entries: fs.Dirent[];
  try {
    entries = await fs.readdir(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) {
        await walkDir(path.join(dirPath, entry.name), langCounts);
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      const lang = extensionToLanguage(ext);
      if (lang) {
        langCounts.set(lang, (langCounts.get(lang) ?? 0) + 1);
      }
    }
  }
}

export async function detectLanguages(targetPath: string): Promise<DetectedLanguage[]> {
  const langCounts = new Map<string, number>();
  await walkDir(targetPath, langCounts);

  const results: DetectedLanguage[] = [];

  for (const [codeqlName] of langCounts) {
    const isCompiled = COMPILED_LANGUAGES.has(codeqlName);
    const buildCommand = isCompiled
      ? (await inferBuildCommand(targetPath, codeqlName)) ?? undefined
      : undefined;

    results.push({ codeqlName, isCompiled, buildCommand });
  }

  return results;
}
