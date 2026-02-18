import { afterEach, describe, expect, it } from "vitest";
import { OsvVulnerability } from "../src/core/types";
import { OsvCache } from "../src/osv/cache";
import { OsvQuery } from "../src/osv/client";
import { OsvProvider } from "../src/osv/provider";
import { cleanupTempDirs, makeTempDir } from "./helpers";

type QueryBatchResponse = {
  results: Array<{
    vulns?: Array<{ id: string; modified?: string }>;
    next_page_token?: string;
  }>;
};

class FakeClient {
  queryCalls: OsvQuery[][] = [];
  queryResponses: QueryBatchResponse[] = [];
  vulnCalls: string[] = [];
  vulnResponses = new Map<string, OsvVulnerability>();

  async queryBatch(queries: OsvQuery[]): Promise<QueryBatchResponse> {
    this.queryCalls.push(queries);
    const response = this.queryResponses.shift();
    if (!response) {
      throw new Error("Unexpected queryBatch call");
    }
    return response;
  }

  async getVulnerability(id: string): Promise<OsvVulnerability> {
    this.vulnCalls.push(id);
    const response = this.vulnResponses.get(id);
    if (!response) {
      throw new Error(`Unexpected getVulnerability call for ${id}`);
    }
    return response;
  }
}

async function makeProvider(client: FakeClient, offline = false): Promise<OsvProvider> {
  const cacheDir = await makeTempDir("npmvulncheck-osv-cache-");
  return new OsvProvider(client as never, new OsvCache(cacheDir), offline);
}

afterEach(async () => {
  await cleanupTempDirs();
});

describe("OsvProvider.queryPackages", () => {
  it("maps querybatch results by input order", async () => {
    const client = new FakeClient();
    client.queryResponses.push({
      results: [
        { vulns: [{ id: "GHSA-b", modified: "2025-01-01T00:00:00Z" }] },
        { vulns: [{ id: "GHSA-a", modified: "2025-01-02T00:00:00Z" }] }
      ]
    });

    const provider = await makeProvider(client);
    const results = await provider.queryPackages([
      { name: "pkg-one", version: "1.0.0" },
      { name: "pkg-two", version: "2.0.0" }
    ]);

    expect(results.get("pkg-one@1.0.0")?.[0].id).toBe("GHSA-b");
    expect(results.get("pkg-two@2.0.0")?.[0].id).toBe("GHSA-a");
  });

  it("uses npm ecosystem and sends version without purl", async () => {
    const client = new FakeClient();
    client.queryResponses.push({ results: [{ vulns: [] }] });

    const provider = await makeProvider(client);
    await provider.queryPackages([{ name: "left-pad", version: "1.3.0" }]);

    expect(client.queryCalls).toHaveLength(1);
    const request = client.queryCalls[0][0] as Record<string, unknown>;
    expect((request.package as { ecosystem: string }).ecosystem).toBe("npm");
    expect(request.version).toBe("1.3.0");
    expect(request).not.toHaveProperty("purl");
  });

  it("treats missing vulns or empty vulns as no findings", async () => {
    const client = new FakeClient();
    client.queryResponses.push({
      results: [
        {},
        { vulns: [] }
      ]
    });

    const provider = await makeProvider(client);
    const results = await provider.queryPackages([
      { name: "a", version: "1.0.0" },
      { name: "b", version: "2.0.0" }
    ]);

    expect(results.get("a@1.0.0")).toEqual([]);
    expect(results.get("b@2.0.0")).toEqual([]);
  });

  it("follows partial pagination and merges extra pages", async () => {
    const client = new FakeClient();
    client.queryResponses.push({
      results: [
        { vulns: [{ id: "GHSA-a1", modified: "2024-01-01T00:00:00Z" }] },
        {
          vulns: [{ id: "GHSA-b1", modified: "2024-01-01T00:00:00Z" }],
          next_page_token: "token-b"
        },
        { vulns: [{ id: "GHSA-c1", modified: "2024-01-01T00:00:00Z" }] }
      ]
    });
    client.queryResponses.push({
      results: [
        {
          vulns: [{ id: "GHSA-b2", modified: "2024-01-02T00:00:00Z" }]
        }
      ]
    });

    const provider = await makeProvider(client);
    const results = await provider.queryPackages([
      { name: "pkg-a", version: "1.0.0" },
      { name: "pkg-b", version: "1.0.0" },
      { name: "pkg-c", version: "1.0.0" }
    ]);

    expect(client.queryCalls).toHaveLength(2);
    expect(client.queryCalls[1]).toHaveLength(1);
    expect(client.queryCalls[1][0].package.name).toBe("pkg-b");
    expect(client.queryCalls[1][0].page_token).toBe("token-b");

    expect(results.get("pkg-b@1.0.0")?.map((entry) => entry.id)).toEqual(["GHSA-b1", "GHSA-b2"]);
  });

  it("handles multiple next_page_token queries in a follow-up call", async () => {
    const client = new FakeClient();
    client.queryResponses.push({
      results: [
        { vulns: [{ id: "GHSA-a1" }], next_page_token: "token-a" },
        { vulns: [{ id: "GHSA-b1" }] },
        { vulns: [{ id: "GHSA-c1" }], next_page_token: "token-c" }
      ]
    });
    client.queryResponses.push({
      results: [
        { vulns: [{ id: "GHSA-a2" }] },
        { vulns: [{ id: "GHSA-c2" }] }
      ]
    });

    const provider = await makeProvider(client);
    const results = await provider.queryPackages([
      { name: "pkg-a", version: "1.0.0" },
      { name: "pkg-b", version: "1.0.0" },
      { name: "pkg-c", version: "1.0.0" }
    ]);

    expect(client.queryCalls).toHaveLength(2);
    expect(client.queryCalls[1]).toHaveLength(2);
    expect(client.queryCalls[1].map((query) => query.package.name)).toEqual(["pkg-a", "pkg-c"]);

    expect(results.get("pkg-a@1.0.0")?.map((entry) => entry.id)).toEqual(["GHSA-a1", "GHSA-a2"]);
    expect(results.get("pkg-c@1.0.0")?.map((entry) => entry.id)).toEqual(["GHSA-c1", "GHSA-c2"]);
  });

  it("reads query matches from cache in offline mode", async () => {
    const onlineClient = new FakeClient();
    onlineClient.queryResponses.push({
      results: [{ vulns: [{ id: "GHSA-offline", modified: "2025-01-01T00:00:00Z" }] }]
    });

    const cacheDir = await makeTempDir("npmvulncheck-osv-cache-");
    const cache = new OsvCache(cacheDir);
    const onlineProvider = new OsvProvider(onlineClient as never, cache, false);
    await onlineProvider.queryPackages([{ name: "pkg-a", version: "1.0.0" }]);

    const offlineClient = new FakeClient();
    const offlineProvider = new OsvProvider(offlineClient as never, new OsvCache(cacheDir), true);
    const results = await offlineProvider.queryPackages([{ name: "pkg-a", version: "1.0.0" }]);

    expect(results.get("pkg-a@1.0.0")).toEqual([{ id: "GHSA-offline", modified: "2025-01-01T00:00:00Z" }]);
    expect(offlineClient.queryCalls).toEqual([]);
  });

  it("throws in offline mode when query cache is missing", async () => {
    const client = new FakeClient();
    const provider = await makeProvider(client, true);

    await expect(provider.queryPackages([{ name: "pkg-missing", version: "1.0.0" }])).rejects.toThrow(
      "Offline mode: missing cached OSV query results"
    );
    expect(client.queryCalls).toEqual([]);
  });
});

describe("OsvProvider.getVuln caching", () => {
  it("prefers cached latest record when modified is not specified", async () => {
    const client = new FakeClient();
    client.vulnResponses.set("GHSA-cache", {
      id: "GHSA-cache",
      modified: "2025-02-01T00:00:00Z",
      summary: "from-network"
    });

    const cacheDir = await makeTempDir("npmvulncheck-osv-cache-");
    const cache = new OsvCache(cacheDir);
    await cache.put("GHSA-cache", "2025-01-01T00:00:00Z", {
      id: "GHSA-cache",
      modified: "2025-01-01T00:00:00Z",
      summary: "cached"
    });

    const provider = new OsvProvider(client as never, cache, false);
    const vuln = await provider.getVuln("GHSA-cache");

    expect(vuln.summary).toBe("cached");
    expect(client.vulnCalls).toEqual([]);
  });

  it("does not fetch details again when vulnId+modified exists in cache", async () => {
    const client = new FakeClient();
    const cacheDir = await makeTempDir("npmvulncheck-osv-cache-");
    const cache = new OsvCache(cacheDir);
    await cache.put("GHSA-cache", "2025-01-01T00:00:00Z", {
      id: "GHSA-cache",
      modified: "2025-01-01T00:00:00Z",
      summary: "cached"
    });

    const provider = new OsvProvider(client as never, cache, false);
    const vuln = await provider.getVuln("GHSA-cache", "2025-01-01T00:00:00Z");

    expect(vuln.summary).toBe("cached");
    expect(client.vulnCalls).toEqual([]);
  });

  it("re-fetches details when modified changes", async () => {
    const client = new FakeClient();
    client.vulnResponses.set("GHSA-cache", {
      id: "GHSA-cache",
      modified: "2025-02-01T00:00:00Z",
      summary: "fresh"
    });

    const cacheDir = await makeTempDir("npmvulncheck-osv-cache-");
    const cache = new OsvCache(cacheDir);
    await cache.put("GHSA-cache", "2025-01-01T00:00:00Z", {
      id: "GHSA-cache",
      modified: "2025-01-01T00:00:00Z",
      summary: "stale"
    });

    const provider = new OsvProvider(client as never, cache, false);
    const vuln = await provider.getVuln("GHSA-cache", "2025-02-01T00:00:00Z");

    expect(vuln.summary).toBe("fresh");
    expect(client.vulnCalls).toEqual(["GHSA-cache"]);

    const cached = await cache.get<OsvVulnerability>("GHSA-cache", "2025-02-01T00:00:00Z");
    expect(cached?.summary).toBe("fresh");
  });

  it("uses latest cached record in offline mode", async () => {
    const client = new FakeClient();
    const cacheDir = await makeTempDir("npmvulncheck-osv-cache-");
    const cache = new OsvCache(cacheDir);

    await cache.put("GHSA-offline", "2024-01-01T00:00:00Z", {
      id: "GHSA-offline",
      modified: "2024-01-01T00:00:00Z",
      summary: "old"
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    await cache.put("GHSA-offline", "2025-01-01T00:00:00Z", {
      id: "GHSA-offline",
      modified: "2025-01-01T00:00:00Z",
      summary: "new"
    });

    const provider = new OsvProvider(client as never, cache, true);
    const vuln = await provider.getVuln("GHSA-offline");

    expect(vuln.summary).toBe("new");
    expect(client.vulnCalls).toEqual([]);
  });
});
