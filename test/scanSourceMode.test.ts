import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runScan } from "../src/core/scan";
import { DepGraph, OsvBatchMatch, OsvVulnerability, ScanOptions } from "../src/core/types";
import { DependencyGraphProvider } from "../src/deps/provider";
import { VulnerabilityProvider } from "../src/osv/provider";
import { cleanupTempDirs, makeTempDir } from "./helpers";

class FakeDepsProvider implements DependencyGraphProvider {
  constructor(private readonly graph: DepGraph) {}

  async detect(_projectRoot: string): Promise<boolean> {
    return true;
  }

  async load(_projectRoot: string, _mode: "lockfile" | "installed"): Promise<DepGraph> {
    return this.graph;
  }
}

class FakeVulnProvider implements VulnerabilityProvider {
  readonly name = "osv";
  queryCalls: Array<{ name: string; version: string }> = [];

  async queryPackages(pkgs: Array<{ name: string; version: string }>): Promise<Map<string, OsvBatchMatch[]>> {
    this.queryCalls = pkgs;
    const out = new Map<string, OsvBatchMatch[]>();
    for (const pkg of pkgs) {
      out.set(`${pkg.name}@${pkg.version}`, [{ id: `GHSA-${pkg.name}`, modified: "2025-01-01T00:00:00Z" }]);
    }
    return out;
  }

  async getVuln(id: string): Promise<OsvVulnerability> {
    const packageName = id.replace(/^GHSA-/, "");
    return {
      id,
      summary: `vuln for ${packageName}`,
      modified: "2025-01-01T00:00:00Z",
      affected: [
        {
          package: {
            ecosystem: "npm",
            name: packageName
          },
          ranges: [{ events: [{ introduced: "0" }] }]
        }
      ],
      references: []
    };
  }
}

function makeGraph(): DepGraph {
  const edges = [
    { from: "root", to: "node_modules/pkg-a", name: "pkg-a", type: "prod" as const },
    { from: "root", to: "node_modules/pkg-b", name: "pkg-b", type: "prod" as const },
    { from: "node_modules/pkg-a", to: "node_modules/pkg-c", name: "pkg-c", type: "prod" as const }
  ];

  return {
    ecosystem: "npm",
    rootId: "root",
    nodes: new Map([
      ["root", { id: "root", name: "root", version: "1.0.0", location: "root", flags: {} }],
      ["node_modules/pkg-a", { id: "node_modules/pkg-a", name: "pkg-a", version: "1.0.0", location: "node_modules/pkg-a", flags: {} }],
      ["node_modules/pkg-b", { id: "node_modules/pkg-b", name: "pkg-b", version: "1.0.0", location: "node_modules/pkg-b", flags: {} }],
      ["node_modules/pkg-c", { id: "node_modules/pkg-c", name: "pkg-c", version: "1.0.0", location: "node_modules/pkg-c", flags: {} }]
    ]),
    edges,
    edgesByFrom: new Map([
      ["root", edges.slice(0, 2)],
      ["node_modules/pkg-a", [edges[2]]]
    ]),
    rootDirectNodeIds: new Set(["node_modules/pkg-a", "node_modules/pkg-b"]),
    resolvePackage: (name: string) => {
      if (name === "pkg-a") {
        return "node_modules/pkg-a";
      }
      return undefined;
    }
  };
}

function makeOptions(root: string): ScanOptions {
  return {
    root,
    mode: "source",
    format: "json",
    entries: ["src/index.ts"],
    conditions: [],
    includeTypeImports: false,
    showTraces: false,
    showVerbose: false,
    includeDev: false,
    exitCodeOn: "none",
    failOn: "all",
    offline: false
  };
}

afterEach(async () => {
  await cleanupTempDirs();
});

describe("runScan source mode", () => {
  it("keeps unreachable findings but places them at lower priority", async () => {
    const tempDir = await makeTempDir("npmvulncheck-scan-source-");
    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(path.join(srcDir, "index.ts"), 'import "pkg-a";\n', "utf8");

    const deps = new FakeDepsProvider(makeGraph());
    const vulns = new FakeVulnProvider();
    const result = await runScan(makeOptions(tempDir), deps, vulns, "0.1.0");

    expect(vulns.queryCalls.map((pkg) => pkg.name).sort()).toEqual(["pkg-a", "pkg-b", "pkg-c"]);
    expect(result.findings.map((finding) => finding.vulnId).sort()).toEqual([
      "GHSA-pkg-a",
      "GHSA-pkg-b",
      "GHSA-pkg-c"
    ]);

    const byId = new Map(result.findings.map((finding) => [finding.vulnId, finding]));
    expect(byId.get("GHSA-pkg-a")?.priority?.level).toBe("high");
    expect(byId.get("GHSA-pkg-c")?.priority?.level).toBe("high");
    expect(byId.get("GHSA-pkg-b")?.priority?.level).toBe("low");
    expect(byId.get("GHSA-pkg-b")?.affected[0].reachability?.level).toBe("transitive");
    expect(byId.get("GHSA-pkg-b")?.affected[0].reachability?.reachable).toBe(false);
    expect(result.findings[result.findings.length - 1]?.vulnId).toBe("GHSA-pkg-b");
  });

  it("falls back to full inventory when source analysis has only unknown imports", async () => {
    const tempDir = await makeTempDir("npmvulncheck-scan-source-unknown-");
    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(path.join(srcDir, "index.ts"), "const name = process.env.PKG;\nrequire(name);\n", "utf8");

    const deps = new FakeDepsProvider(makeGraph());
    const vulns = new FakeVulnProvider();
    const result = await runScan(makeOptions(tempDir), deps, vulns, "0.1.0");

    expect(vulns.queryCalls.map((pkg) => pkg.name).sort()).toEqual(["pkg-a", "pkg-b", "pkg-c"]);
    expect(result.findings.map((finding) => finding.vulnId).sort()).toEqual([
      "GHSA-pkg-a",
      "GHSA-pkg-b",
      "GHSA-pkg-c"
    ]);

    const pkgBFinding = result.findings.find((finding) => finding.vulnId === "GHSA-pkg-b");
    expect(pkgBFinding?.priority?.level).toBe("medium");
    expect(pkgBFinding?.affected[0].reachability?.level).toBe("unknown");
  });

  it("falls back to full inventory when at least one import cannot be resolved", async () => {
    const tempDir = await makeTempDir("npmvulncheck-scan-source-unresolved-");
    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(path.join(srcDir, "index.ts"), 'import "pkg-a";\nimport "pkg-missing";\n', "utf8");

    const deps = new FakeDepsProvider(makeGraph());
    const vulns = new FakeVulnProvider();
    const result = await runScan(makeOptions(tempDir), deps, vulns, "0.1.0");

    expect(vulns.queryCalls.map((pkg) => pkg.name).sort()).toEqual(["pkg-a", "pkg-b", "pkg-c"]);
    expect(result.findings.map((finding) => finding.vulnId).sort()).toEqual([
      "GHSA-pkg-a",
      "GHSA-pkg-b",
      "GHSA-pkg-c"
    ]);

    const pkgBFinding = result.findings.find((finding) => finding.vulnId === "GHSA-pkg-b");
    expect(pkgBFinding?.priority?.level).toBe("medium");
    expect(pkgBFinding?.affected[0].reachability?.level).toBe("unknown");
  });

  it("includes unresolved import diagnostics when explain-resolve is enabled", async () => {
    const tempDir = await makeTempDir("npmvulncheck-scan-source-explain-");
    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(path.join(srcDir, "index.ts"), 'import "pkg-missing";\n', "utf8");

    const deps = new FakeDepsProvider(makeGraph());
    const vulns = new FakeVulnProvider();
    const result = await runScan({ ...makeOptions(tempDir), explainResolve: true }, deps, vulns, "0.1.0");

    expect(result.meta.sourceAnalysis).toBeDefined();
    expect(result.meta.sourceAnalysis?.unresolvedImports.length).toBeGreaterThan(0);
    expect(result.meta.sourceAnalysis?.unresolvedImports[0].specifier).toBe("pkg-missing");
  });
});
