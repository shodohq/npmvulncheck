import { describe, expect, it } from "vitest";
import { runScan } from "../src/core/scan";
import { DepGraph, OsvBatchMatch, OsvVulnerability, ScanOptions } from "../src/core/types";
import { DependencyGraphProvider } from "../src/deps/provider";
import { VulnerabilityProvider } from "../src/osv/provider";

class SinglePackageDepsProvider implements DependencyGraphProvider {
  constructor(private readonly graph: DepGraph) {}

  async detect(_projectRoot: string): Promise<boolean> {
    return true;
  }

  async load(_projectRoot: string, _mode: "lockfile" | "installed"): Promise<DepGraph> {
    return this.graph;
  }
}

class ControlledVulnProvider implements VulnerabilityProvider {
  readonly name = "osv";
  readonly queriedVersions: string[] = [];

  constructor(
    private readonly vulnByVersion: Map<string, string[]>,
    private readonly vulnDetails: Map<string, OsvVulnerability>,
    private readonly registryVersionsByPackage: Map<string, string[]>
  ) {}

  async queryPackages(pkgs: Array<{ name: string; version: string }>): Promise<Map<string, OsvBatchMatch[]>> {
    const out = new Map<string, OsvBatchMatch[]>();
    for (const pkg of pkgs) {
      const key = `${pkg.name}@${pkg.version}`;
      this.queriedVersions.push(key);
      const vulnIds = this.vulnByVersion.get(key) ?? [];
      out.set(
        key,
        vulnIds.map((id) => ({
          id,
          modified: "2025-01-01T00:00:00Z"
        }))
      );
    }
    return out;
  }

  async getVuln(id: string): Promise<OsvVulnerability> {
    const detail = this.vulnDetails.get(id);
    if (!detail) {
      throw new Error(`Missing test vulnerability detail for ${id}`);
    }
    return detail;
  }

  async listPackageVersions(name: string): Promise<string[] | undefined> {
    return this.registryVersionsByPackage.get(name);
  }
}

function makeGraph(name: string, version: string): DepGraph {
  const depNodeId = `node_modules/${name}`;
  const edges = [{ from: "root", to: depNodeId, name, type: "prod" as const }];

  return {
    ecosystem: "npm",
    rootId: "root",
    nodes: new Map([
      ["root", { id: "root", name: "fixture-root", version: "1.0.0", location: "root", flags: {} }],
      [
        depNodeId,
        {
          id: depNodeId,
          name,
          version,
          location: depNodeId,
          source: "registry",
          flags: {}
        }
      ]
    ]),
    edges,
    edgesByFrom: new Map([["root", edges]]),
    rootDirectNodeIds: new Set([depNodeId]),
    resolvePackage: () => undefined
  };
}

function makeScanOptions(): ScanOptions {
  return {
    root: process.cwd(),
    mode: "lockfile",
    format: "json",
    entries: [],
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

describe("runScan fix suggestion selection", () => {
  it("re-queries candidate fixed versions and picks a non-vulnerable version", async () => {
    const depsProvider = new SinglePackageDepsProvider(makeGraph("pkg-a", "1.0.0"));
    const vulnProvider = new ControlledVulnProvider(
      new Map<string, string[]>([
        ["pkg-a@1.0.0", ["GHSA-pkg-a"]],
        ["pkg-a@1.1.0", ["GHSA-pkg-a"]],
        ["pkg-a@1.2.0", []]
      ]),
      new Map<string, OsvVulnerability>([
        [
          "GHSA-pkg-a",
          {
            id: "GHSA-pkg-a",
            modified: "2025-01-01T00:00:00Z",
            affected: [
              {
                package: {
                  ecosystem: "npm",
                  name: "pkg-a"
                },
                ranges: [
                  {
                    events: [{ introduced: "0" }, { fixed: "1.1.0" }, { fixed: "1.2.0" }]
                  }
                ]
              }
            ],
            references: []
          }
        ]
      ]),
      new Map()
    );

    const result = await runScan(makeScanOptions(), depsProvider, vulnProvider, "0.1.0");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].affected[0].fix?.fixedVersion).toBe("1.2.0");
    expect(vulnProvider.queriedVersions).toContain("pkg-a@1.1.0");
    expect(vulnProvider.queriedVersions).toContain("pkg-a@1.2.0");
  });

  it("falls back to registry versions when OSV fixed events are absent", async () => {
    const depsProvider = new SinglePackageDepsProvider(makeGraph("pkg-b", "1.0.0"));
    const vulnProvider = new ControlledVulnProvider(
      new Map<string, string[]>([
        ["pkg-b@1.0.0", ["GHSA-pkg-b"]],
        ["pkg-b@1.0.1", ["GHSA-pkg-b"]],
        ["pkg-b@1.0.2", ["GHSA-pkg-b"]],
        ["pkg-b@1.1.0", []]
      ]),
      new Map<string, OsvVulnerability>([
        [
          "GHSA-pkg-b",
          {
            id: "GHSA-pkg-b",
            modified: "2025-01-01T00:00:00Z",
            affected: [
              {
                package: {
                  ecosystem: "npm",
                  name: "pkg-b"
                },
                ranges: [
                  {
                    events: [{ introduced: "0" }, { last_affected: "1.0.2" }]
                  }
                ]
              }
            ],
            references: []
          }
        ]
      ]),
      new Map<string, string[]>([
        ["pkg-b", ["1.0.0", "1.0.1", "1.0.2", "1.1.0"]]
      ])
    );

    const result = await runScan(makeScanOptions(), depsProvider, vulnProvider, "0.1.0");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].affected[0].fix?.fixedVersion).toBe("1.1.0");
    expect(vulnProvider.queriedVersions).toContain("pkg-b@1.1.0");
  });

  it("ignores older fixed candidates and does not propose downgrades", async () => {
    const depsProvider = new SinglePackageDepsProvider(makeGraph("pkg-c", "3.0.0"));
    const vulnProvider = new ControlledVulnProvider(
      new Map<string, string[]>([
        ["pkg-c@3.0.0", ["GHSA-pkg-c"]],
        ["pkg-c@2.5.0", []],
        ["pkg-c@3.1.0", []]
      ]),
      new Map<string, OsvVulnerability>([
        [
          "GHSA-pkg-c",
          {
            id: "GHSA-pkg-c",
            modified: "2025-01-01T00:00:00Z",
            affected: [
              {
                package: {
                  ecosystem: "npm",
                  name: "pkg-c"
                },
                ranges: [
                  {
                    events: [{ introduced: "0" }, { fixed: "2.5.0" }, { introduced: "3.0.0" }, { fixed: "3.1.0" }]
                  }
                ]
              }
            ],
            references: []
          }
        ]
      ]),
      new Map()
    );

    const result = await runScan(makeScanOptions(), depsProvider, vulnProvider, "0.1.0");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].affected[0].fix?.fixedVersion).toBe("3.1.0");
    expect(vulnProvider.queriedVersions).toContain("pkg-c@3.1.0");
    expect(vulnProvider.queriedVersions).not.toContain("pkg-c@2.5.0");
  });
});
