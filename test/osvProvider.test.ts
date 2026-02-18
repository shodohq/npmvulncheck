import { describe, expect, it } from "vitest";
import { OsvCache } from "../src/osv/cache";
import { OsvProvider } from "../src/osv/provider";

class FakeClient {
  calls = 0;

  async queryBatch(_: unknown[]): Promise<{ results: Array<{ vulns?: Array<{ id: string; modified?: string }> }> }> {
    this.calls += 1;
    return {
      results: [
        { vulns: [{ id: "GHSA-b", modified: "2025-01-01T00:00:00Z" }] },
        { vulns: [{ id: "GHSA-a", modified: "2025-01-02T00:00:00Z" }] }
      ]
    };
  }

  async getVulnerability(id: string): Promise<unknown> {
    return { id, modified: "2025-01-02T00:00:00Z" };
  }
}

describe("OsvProvider", () => {
  it("keeps querybatch result mapping by input order", async () => {
    const client = new FakeClient();
    const provider = new OsvProvider(client as never, new OsvCache("/tmp/npmvulncheck-test-cache"), false);

    const results = await provider.queryPackages([
      { name: "pkg-one", version: "1.0.0" },
      { name: "pkg-two", version: "2.0.0" }
    ]);

    expect(results.get("pkg-one@1.0.0")?.[0].id).toBe("GHSA-b");
    expect(results.get("pkg-two@2.0.0")?.[0].id).toBe("GHSA-a");
    expect(client.calls).toBe(1);
  });
});
