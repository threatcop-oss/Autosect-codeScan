import { simpleGit, SimpleGit } from 'simple-git';
import path from 'path';

export const getGitClient = (repoPath: string): SimpleGit => {
  return simpleGit({ baseDir: repoPath, binary: 'git' });
};

export const getRepositoryInfo = async (repoPath: string): Promise<{
  repository?: string;
  commit?: string;
}> => {
  try {
    const git = getGitClient(repoPath);
    const [remotes, commit] = await Promise.all([git.getRemotes(true), git.revparse(['HEAD'])]);
    const origin = remotes.find((remote) => remote.name === 'origin');
    return {
      repository: origin?.refs.fetch ?? origin?.refs.push,
      commit
    };
  } catch {
    return {};
  }
};

export const getChangedFilesSinceCommit = async (
  repoPath: string,
  commitHash: string
): Promise<string[]> => {
  try {
    const git = getGitClient(repoPath);
    const diff = await git.diff(['--name-only', `${commitHash}..HEAD`]);
    const files = diff
      .split('\n')
      .map((file) => file.trim())
      .filter(Boolean)
      .map((file) => path.resolve(repoPath, file));
    return Array.from(new Set(files));
  } catch {
    return [];
  }
};

export const getChangedFiles = async (repoPath: string): Promise<string[]> => {
  try {
    const git = getGitClient(repoPath);
    const diff = await git.diff(['--name-only', 'HEAD']);
    const untracked = await git.raw(['ls-files', '--others', '--exclude-standard']);
    const files = new Set<string>();

    diff
      .split('\n')
      .map((file) => file.trim())
      .filter(Boolean)
      .forEach((file) => files.add(path.resolve(repoPath, file)));

    untracked
      .split('\n')
      .map((file) => file.trim())
      .filter(Boolean)
      .forEach((file) => files.add(path.resolve(repoPath, file)));

    return Array.from(files.values());
  } catch {
    return [];
  }
};
