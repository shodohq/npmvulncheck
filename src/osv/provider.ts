import { OsvBatchMatch, OsvVulnerability } from "../core/types";
import { OsvCache } from "./cache";
import { OsvClient, OsvQuery } from "./client";

export interface VulnerabilityProvider {
  name: string;
  queryPackages(
    pkgs: Array<{ name: string; version: string }>
  ): Promise<Map<string, OsvBatchMatch[]>>;
  getVuln(id: string, modified?: string): Promise<OsvVulnerability>;
  listPackageVersions?(name: string): Promise<string[] | undefined>;
}

type QueryState = {
  name: string;
  version: string;
  pageToken?: string;
};

const BATCH_SIZE = 256;

function keyOf(name: string, version: string): string {
  return `${name}@${version}`;
}

function toBatchQuery(state: QueryState): OsvQuery {
  return {
    package: {
      ecosystem: "npm",
      name: state.name
    },
    version: state.version,
    ...(state.pageToken ? { page_token: state.pageToken } : {})
  };
}

function chunk<T>(list: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let i = 0; i < list.length; i += size) {
    result.push(list.slice(i, i + size));
  }
  return result;
}

export class OsvProvider implements VulnerabilityProvider {
  readonly name = "osv";
  private readonly packageVersionsCache = new Map<string, Promise<string[] | undefined>>();

  constructor(
    private readonly client: OsvClient,
    private readonly cache: OsvCache,
    private readonly offline: boolean
  ) {}

  async queryPackages(
    pkgs: Array<{ name: string; version: string }>
  ): Promise<Map<string, OsvBatchMatch[]>> {
    const dedup = new Map<string, QueryState>();
    for (const pkg of pkgs) {
      const key = keyOf(pkg.name, pkg.version);
      if (!dedup.has(key)) {
        dedup.set(key, { name: pkg.name, version: pkg.version });
      }
    }

    const states = Array.from(dedup.values());
    const out = new Map<string, OsvBatchMatch[]>();
    for (const state of states) {
      out.set(keyOf(state.name, state.version), []);
    }

    if (this.offline) {
      const missing: string[] = [];
      for (const state of states) {
        const key = keyOf(state.name, state.version);
        const cached = await this.cache.getQuery(state.name, state.version);
        if (!cached) {
          missing.push(key);
          continue;
        }
        out.set(key, cached);
      }

      if (missing.length > 0) {
        const preview = missing.slice(0, 5);
        const suffix = missing.length > preview.length ? " ..." : "";
        throw new Error(
          `Offline mode: missing cached OSV query results for ${preview.join(", ")}${suffix}. ` +
            "Run an online scan once to warm the cache."
        );
      }
      return out;
    }

    for (const group of chunk(states, BATCH_SIZE)) {
      await this.queryBatchWithPaging(group, out);
    }

    for (const state of states) {
      const key = keyOf(state.name, state.version);
      await this.cache.putQuery(state.name, state.version, out.get(key) ?? []);
    }

    return out;
  }

  async getVuln(id: string, modified?: string): Promise<OsvVulnerability> {
    if (modified) {
      const cached = await this.cache.get<OsvVulnerability>(id, modified);
      if (cached) {
        return cached;
      }

      if (this.offline) {
        const latestCached = await this.cache.getLatestById<OsvVulnerability>(id);
        if (latestCached) {
          return latestCached;
        }
        throw new Error(`Offline mode: vulnerability ${id} is not in cache.`);
      }
    }

    if (!modified) {
      const latestCached = await this.cache.getLatestById<OsvVulnerability>(id);
      if (latestCached) {
        return latestCached;
      }
    }

    if (this.offline) {
      throw new Error(`Offline mode: vulnerability ${id} is not in cache.`);
    }

    const vuln = (await this.client.getVulnerability(id)) as OsvVulnerability;
    const cacheModified = modified ?? vuln.modified ?? "unknown";
    await this.cache.put(id, cacheModified, vuln);
    return vuln;
  }

  async listPackageVersions(name: string): Promise<string[] | undefined> {
    const fromCache = this.packageVersionsCache.get(name);
    if (fromCache) {
      return fromCache;
    }

    const loaded = (async () => {
      if (this.offline) {
        return undefined;
      }

      const encodedName = encodeURIComponent(name);
      const response = await fetch(`https://registry.npmjs.org/${encodedName}`, {
        headers: {
          accept: "application/vnd.npm.install-v1+json, application/json"
        }
      }).catch(() => undefined);

      if (!response || !response.ok) {
        return undefined;
      }

      const metadata = (await response.json().catch(() => undefined)) as
        | {
            versions?: Record<string, unknown>;
          }
        | undefined;
      if (!metadata?.versions || typeof metadata.versions !== "object") {
        return undefined;
      }

      return Object.keys(metadata.versions);
    })();

    this.packageVersionsCache.set(name, loaded);
    return loaded;
  }

  private async queryBatchWithPaging(
    initial: QueryState[],
    out: Map<string, OsvBatchMatch[]>
  ): Promise<void> {
    let pending: QueryState[] = initial;

    while (pending.length > 0) {
      const response = await this.client.queryBatch(pending.map(toBatchQuery));
      if (!response.results || response.results.length !== pending.length) {
        throw new Error("OSV querybatch: response/result length mismatch");
      }

      const next: QueryState[] = [];
      for (let i = 0; i < response.results.length; i += 1) {
        const state = pending[i];
        const result = response.results[i];
        const key = keyOf(state.name, state.version);
        const list = out.get(key);
        if (!list) {
          continue;
        }

        for (const vuln of result.vulns ?? []) {
          if (!list.some((entry) => entry.id === vuln.id && entry.modified === vuln.modified)) {
            list.push({ id: vuln.id, modified: vuln.modified });
          }
        }

        if (result.next_page_token) {
          next.push({ ...state, pageToken: result.next_page_token });
        }
      }

      pending = next;
    }
  }
}
