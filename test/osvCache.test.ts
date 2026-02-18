import { afterEach, describe, expect, it } from "vitest";
import { OsvCache } from "../src/osv/cache";
import { cleanupTempDirs, makeTempDir } from "./helpers";

afterEach(async () => {
  await cleanupTempDirs();
});

describe("OsvCache", () => {
  it("stores and reads query cache entries", async () => {
    const cacheDir = await makeTempDir("npmvulncheck-osv-cache-");
    const cache = new OsvCache(cacheDir);

    await cache.putQuery("left-pad", "1.3.0", [{ id: "GHSA-1", modified: "2025-01-01T00:00:00Z" }]);
    const cached = await cache.getQuery("left-pad", "1.3.0");
    expect(cached).toEqual([{ id: "GHSA-1", modified: "2025-01-01T00:00:00Z" }]);
  });

  it("reports vuln cache summary with latest modified timestamp", async () => {
    const cacheDir = await makeTempDir("npmvulncheck-osv-cache-");
    const cache = new OsvCache(cacheDir);

    await cache.put("GHSA-a", "2025-01-01T00:00:00Z", { id: "GHSA-a" });
    await cache.put("GHSA-b", "2025-02-01T00:00:00Z", { id: "GHSA-b" });

    const summary = await cache.getVulnSummary();
    expect(summary.count).toBe(2);
    expect(summary.lastUpdated).toBe("2025-02-01T00:00:00.000Z");
  });
});
