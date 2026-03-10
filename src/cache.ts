import crypto from 'crypto';
import path from 'path';
import fs from 'fs-extra';
import { ScanConfig } from './types.js';

export interface CacheEntry<T> {
  timestamp: number;
  payload: T;
}

export class CacheStore {
  private cacheDir: string;

  constructor(private config: ScanConfig, private basePath: string) {
    this.cacheDir = path.join(basePath, '.security-scan-cache');
  }

  async get<T>(key: string): Promise<T | undefined> {
    if (!this.config.cache.enabled) {
      return undefined;
    }

    const filePath = this.getCachePath(key);
    if (!(await fs.pathExists(filePath))) {
      return undefined;
    }

    const entry = (await fs.readJson(filePath)) as CacheEntry<T>;
    if (Date.now() - entry.timestamp > this.config.cache.ttl * 1000) {
      await fs.remove(filePath);
      return undefined;
    }

    return entry.payload;
  }

  async set<T>(key: string, payload: T): Promise<void> {
    if (!this.config.cache.enabled) {
      return;
    }

    await fs.ensureDir(this.cacheDir);
    const entry: CacheEntry<T> = { timestamp: Date.now(), payload };
    await fs.writeJson(this.getCachePath(key), entry, { spaces: 2 });
  }

  buildKey(parts: Array<string | undefined>): string {
    const hash = crypto
      .createHash('sha256')
      .update(parts.filter(Boolean).join('|'))
      .digest('hex');
    return hash;
  }

  private getCachePath(key: string): string {
    return path.join(this.cacheDir, `${key}.json`);
  }
}
