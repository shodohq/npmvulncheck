import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

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

  constructor(cacheDir?: string) {
    this.dir = cacheDir ?? defaultCacheDir();
  }

  async ensureDir(): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true });
  }

  private filePath(id: string, modified: string): string {
    return path.join(this.dir, `${sanitize(id)}__${sanitize(modified)}.json`);
  }

  async get<T>(id: string, modified: string): Promise<T | undefined> {
    await this.ensureDir();
    const file = this.filePath(id, modified);
    const text = await fs.readFile(file, "utf8").catch(() => undefined);
    if (!text) {
      return undefined;
    }

    return JSON.parse(text) as T;
  }

  async getLatestById<T>(id: string): Promise<T | undefined> {
    await this.ensureDir();
    const files = await fs.readdir(this.dir);
    let best: { file: string; mtimeMs: number } | undefined;

    for (const file of files) {
      const parsed = splitCacheFileName(file);
      if (!parsed || parsed.id !== id) {
        continue;
      }

      const stat = await fs.stat(path.join(this.dir, file)).catch(() => undefined);
      if (!stat) {
        continue;
      }

      if (!best || stat.mtimeMs > best.mtimeMs) {
        best = { file, mtimeMs: stat.mtimeMs };
      }
    }

    if (!best) {
      return undefined;
    }

    const text = await fs.readFile(path.join(this.dir, best.file), "utf8").catch(() => undefined);
    if (!text) {
      return undefined;
    }

    return JSON.parse(text) as T;
  }

  async put<T>(id: string, modified: string, payload: T): Promise<void> {
    await this.ensureDir();
    const file = this.filePath(id, modified);
    await fs.writeFile(file, JSON.stringify(payload), "utf8");
  }
}
