import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { OsvBatchMatch } from "../core/types";

function sanitize(value: string): string {
  return encodeURIComponent(value);
}

function desanitize(value: string): string {
  return decodeURIComponent(value);
}

function splitCacheFileName(fileName: string): { id: string; modified: string } | null {
  if (!fileName.endsWith(".json")) {
    return null;
  }
  const withoutExt = fileName.slice(0, -5);
  const splitIndex = withoutExt.lastIndexOf("__");
  if (splitIndex < 0) {
    return null;
  }

  const id = withoutExt.slice(0, splitIndex);
  const modified = withoutExt.slice(splitIndex + 2);
  if (!id || !modified) {
    return null;
  }

  return { id: desanitize(id), modified: desanitize(modified) };
}

function defaultCacheDir(): string {
  const xdg = process.env.XDG_CACHE_HOME;
  if (xdg && xdg.length > 0) {
    return path.join(xdg, "npmvulncheck", "osv");
  }
  return path.join(os.homedir(), ".cache", "npmvulncheck", "osv");
}

export class OsvCache {
  readonly dir: string;
  private readonly vulnDir: string;
  private readonly queryDir: string;

  constructor(cacheDir?: string) {
    this.dir = cacheDir ?? defaultCacheDir();
    this.vulnDir = path.join(this.dir, "vulns");
    this.queryDir = path.join(this.dir, "queries");
  }

  async ensureDir(): Promise<void> {
    await Promise.all([
      fs.mkdir(this.dir, { recursive: true }),
      fs.mkdir(this.vulnDir, { recursive: true }),
      fs.mkdir(this.queryDir, { recursive: true })
    ]);
  }

  private vulnFilePath(id: string, modified: string): string {
    return path.join(this.vulnDir, `${sanitize(id)}__${sanitize(modified)}.json`);
  }

  private legacyVulnFilePath(id: string, modified: string): string {
    return path.join(this.dir, `${sanitize(id)}__${sanitize(modified)}.json`);
  }

  private queryFilePath(name: string, version: string): string {
    return path.join(this.queryDir, `${sanitize(name)}__${sanitize(version)}.json`);
  }

  private async listVulnFiles(): Promise<Array<{ absolutePath: string; id: string; modified: string }>> {
    await this.ensureDir();

    const out: Array<{ absolutePath: string; id: string; modified: string }> = [];
    const addFilesFromDir = async (dirPath: string): Promise<void> => {
      const files = await fs.readdir(dirPath).catch(() => []);
      for (const file of files) {
        const parsed = splitCacheFileName(file);
        if (!parsed) {
          continue;
        }
        out.push({
          absolutePath: path.join(dirPath, file),
          id: parsed.id,
          modified: parsed.modified
        });
      }
    };

    await addFilesFromDir(this.vulnDir);
    await addFilesFromDir(this.dir);
    return out;
  }

  async get<T>(id: string, modified: string): Promise<T | undefined> {
    await this.ensureDir();
    const file = this.vulnFilePath(id, modified);
    const legacyFile = this.legacyVulnFilePath(id, modified);
    const text =
      (await fs.readFile(file, "utf8").catch(() => undefined)) ??
      (await fs.readFile(legacyFile, "utf8").catch(() => undefined));
    if (!text) {
      return undefined;
    }

    return JSON.parse(text) as T;
  }

  async getLatestById<T>(id: string): Promise<T | undefined> {
    const files = await this.listVulnFiles();
    let bestByModified: { absolutePath: string; modifiedMs: number } | undefined;
    let bestByMtime: { absolutePath: string; mtimeMs: number } | undefined;

    for (const entry of files) {
      if (entry.id !== id) {
        continue;
      }

      const modifiedMs = new Date(entry.modified).getTime();
      if (!Number.isNaN(modifiedMs)) {
        if (!bestByModified || modifiedMs > bestByModified.modifiedMs) {
          bestByModified = { absolutePath: entry.absolutePath, modifiedMs };
        }
        continue;
      }

      const stat = await fs.stat(entry.absolutePath).catch(() => undefined);
      if (!stat) {
        continue;
      }

      if (!bestByMtime || stat.mtimeMs > bestByMtime.mtimeMs) {
        bestByMtime = { absolutePath: entry.absolutePath, mtimeMs: stat.mtimeMs };
      }
    }

    const bestPath = bestByModified?.absolutePath ?? bestByMtime?.absolutePath;
    if (!bestPath) {
      return undefined;
    }

    const text = await fs.readFile(bestPath, "utf8").catch(() => undefined);
    if (!text) {
      return undefined;
    }

    return JSON.parse(text) as T;
  }

  async put<T>(id: string, modified: string, payload: T): Promise<void> {
    await this.ensureDir();
    const file = this.vulnFilePath(id, modified);
    await fs.writeFile(file, JSON.stringify(payload), "utf8");
  }

  async getQuery(name: string, version: string): Promise<OsvBatchMatch[] | undefined> {
    await this.ensureDir();
    const file = this.queryFilePath(name, version);
    const text = await fs.readFile(file, "utf8").catch(() => undefined);
    if (!text) {
      return undefined;
    }
    return JSON.parse(text) as OsvBatchMatch[];
  }

  async putQuery(name: string, version: string, matches: OsvBatchMatch[]): Promise<void> {
    await this.ensureDir();
    await fs.writeFile(this.queryFilePath(name, version), JSON.stringify(matches), "utf8");
  }

  async getVulnSummary(): Promise<{ count: number; lastUpdated?: string }> {
    await this.ensureDir();
    const files = await this.listVulnFiles();
    const dedup = new Set<string>();
    let lastUpdated: string | undefined;

    for (const entry of files) {
      const key = `${entry.id}::${entry.modified}`;
      if (dedup.has(key)) {
        continue;
      }
      dedup.add(key);

      const modifiedDate = new Date(entry.modified);
      if (!Number.isNaN(modifiedDate.getTime())) {
        const iso = modifiedDate.toISOString();
        if (!lastUpdated || new Date(iso) > new Date(lastUpdated)) {
          lastUpdated = iso;
        }
        continue;
      }

      const stat = await fs.stat(entry.absolutePath).catch(() => undefined);
      if (!stat) {
        continue;
      }
      const iso = new Date(stat.mtimeMs).toISOString();
      if (!lastUpdated || new Date(iso) > new Date(lastUpdated)) {
        lastUpdated = iso;
      }
    }

    return {
      count: dedup.size,
      lastUpdated
    };
  }
}
