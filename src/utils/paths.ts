import path from 'path';
import fs from 'fs-extra';
import { glob } from 'glob';

export interface ScanTarget {
  targetPath: string;
  manifestPath?: string;
  manifestType?: 'npm' | 'maven';
  /** When the user points at a lock file (e.g. 6275-package-lock.json), path to that file. */
  lockFilePath?: string;
}

const isPomFile = (name: string): boolean => {
  const n = name.toLowerCase();
  return n === 'pom.xml' || (n.endsWith('.xml') && n.includes('pom'));
};

const isPackageLockFile = (name: string): boolean => {
  const n = name.toLowerCase();
  return n === 'package-lock.json' || n.endsWith('-package-lock.json');
};

const isPackageJsonFile = (name: string): boolean => {
  if (isPackageLockFile(name)) return false;
  const n = name.toLowerCase();
  return n === 'package.json' || (n.endsWith('.json') && n.includes('package'));
};

const findPomInDir = (dirPath: string): string | undefined => {
  if (!fs.pathExistsSync(dirPath)) return undefined;
  const stat = fs.statSync(dirPath);
  if (!stat.isDirectory()) return undefined;
  const exact = path.join(dirPath, 'pom.xml');
  if (fs.pathExistsSync(exact)) return exact;
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const pom = entries.find(
    (e) => e.isFile() && isPomFile(e.name)
  );
  return pom ? path.join(dirPath, pom.name) : undefined;
};

const findPackageJsonInDir = (dirPath: string): string | undefined => {
  if (!fs.pathExistsSync(dirPath)) return undefined;
  const stat = fs.statSync(dirPath);
  if (!stat.isDirectory()) return undefined;
  const exact = path.join(dirPath, 'package.json');
  if (fs.pathExistsSync(exact)) return exact;
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const pkg = entries.find(
    (e) => e.isFile() && isPackageJsonFile(e.name)
  );
  return pkg ? path.join(dirPath, pkg.name) : undefined;
};

/**
 * Resolve scan target from any path: file (any type), directory, or zip-extracted dir.
 * Known manifests (package.json, pom.xml, etc.) set manifestPath/manifestType; other files scan the containing directory.
 */
export const resolveScanTarget = (inputPath: string): ScanTarget => {
  const resolved = path.resolve(inputPath || '.');
  const baseName = path.basename(resolved);
  const baseLower = baseName.toLowerCase();
  if (baseLower === 'package.json' || isPackageJsonFile(baseName)) {
    return { targetPath: path.dirname(resolved), manifestPath: resolved, manifestType: 'npm' };
  }
  if (baseLower === 'pom.xml' || isPomFile(baseName)) {
    return { targetPath: path.dirname(resolved), manifestPath: resolved, manifestType: 'maven' };
  }
  if (fs.pathExistsSync(resolved)) {
    const stat = fs.statSync(resolved);
    if (stat.isFile()) {
      const dir = path.dirname(resolved);
      if (isPackageLockFile(baseName)) {
        const stem = baseName.replace(/-lock\.json$/i, '');
        const siblingManifest = path.join(dir, stem + '.json');
        if (fs.pathExistsSync(siblingManifest)) {
          return { targetPath: dir, manifestPath: siblingManifest, manifestType: 'npm', lockFilePath: resolved };
        }
        // Lock file only (no sibling package.json): still pass lockFilePath so scanners can use it
        return { targetPath: dir, lockFilePath: resolved, manifestType: 'npm' };
      }
      return { targetPath: dir };
    }
    const pomPath = findPomInDir(resolved);
    if (pomPath) {
      return { targetPath: resolved, manifestPath: pomPath, manifestType: 'maven' };
    }
    const packageJsonPath = findPackageJsonInDir(resolved);
    if (packageJsonPath) {
      return { targetPath: resolved, manifestPath: packageJsonPath, manifestType: 'npm' };
    }
  }
  return { targetPath: resolved };
};

export const resolveTargetPath = (inputPath: string): string => {
  return resolveScanTarget(inputPath).targetPath;
};

/**
 * When manifest is named like 1169-package.json, the lock file may be 1169-package-lock.json.
 * Returns the path to that prefixed lock file (caller should check pathExists).
 */
export const getPrefixedPackageLockPath = (manifestPath: string, targetDir: string): string => {
  const base = path.basename(manifestPath);
  const stem = base.replace(/\.json$/i, '');
  return path.join(targetDir, `${stem}-lock.json`);
};

export const resolveExcludedFiles = async (
  basePath: string,
  patterns: string[]
): Promise<Set<string>> => {
  if (!patterns.length) {
    return new Set();
  }
  const matches = await glob(patterns, {
    cwd: basePath,
    absolute: true,
    dot: true,
    nodir: true
  });
  return new Set(matches.map((file) => path.resolve(file)));
};

export const isExcluded = (
  filePath: string,
  excluded: Set<string>,
  basePath?: string
): boolean => {
  if (!filePath) {
    return false;
  }

  const resolved = path.isAbsolute(filePath)
    ? filePath
    : path.resolve(basePath ?? process.cwd(), filePath);
  return excluded.has(resolved);
};
