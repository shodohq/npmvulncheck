import { OsvBatchMatch, OsvVulnerability } from "../core/types";
import { OsvCache } from "./cache";
import { OsvClient, OsvQuery } from "./client";

export interface VulnerabilityProvider {
  name: string;
  queryPackages(
    pkgs: Array<{ name: string; version: string }>
  ): Promise<Map<string, OsvBatchMatch[]>>;
  getVuln(id: string, modified?: string): Promise<OsvVulnerability>;
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
      return out;
    }

    for (const group of chunk(states, BATCH_SIZE)) {
      await this.queryBatchWithPaging(group, out);
    }

    return out;
  }

  async getVuln(id: string, modified?: string): Promise<OsvVulnerability> {
    if (modified) {
      const cached = await this.cache.get<OsvVulnerability>(id, modified);
      if (cached) {
        return cached;
      }
    }

    const latestCached = await this.cache.getLatestById<OsvVulnerability>(id);
    if (latestCached && this.offline) {
      return latestCached;
    }

    if (this.offline) {
      throw new Error(`Offline mode: vulnerability ${id} is not in cache.`);
    }

    const vuln = (await this.client.getVulnerability(id)) as OsvVulnerability;
    const cacheModified = modified ?? vuln.modified ?? "unknown";
    await this.cache.put(id, cacheModified, vuln);
    return vuln;
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
