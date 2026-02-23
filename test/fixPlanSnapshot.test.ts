import { describe, expect, it } from "vitest";
import { DepGraph, Finding, ScanResult } from "../src/core/types";
import { buildRemediationPlan } from "../src/remediation";

function makeGraph(): DepGraph {
  const rootId = "root";
  const parentId = "node_modules/parent";
  const transitiveId = "node_modules/pkg-a";
  const directId = "node_modules/pkg-b";
  const edges = [
    { from: rootId, to: parentId, name: "parent", type: "prod" as const },
    { from: parentId, to: transitiveId, name: "pkg-a", type: "prod" as const },
    { from: rootId, to: directId, name: "pkg-b", type: "prod" as const }
  ];

  return {
    ecosystem: "npm",
    manager: "npm",
    rootId,
    nodes: new Map([
      [rootId, { id: rootId, name: "fixture", version: "1.0.0", location: rootId, flags: {} }],
      [parentId, { id: parentId, name: "parent", version: "2.0.0", location: parentId, flags: {} }],
      [transitiveId, { id: transitiveId, name: "pkg-a", version: "1.0.0", location: transitiveId, flags: {} }],
      [directId, { id: directId, name: "pkg-b", version: "2.0.0", location: directId, flags: {} }]
    ]),
    edges,
    edgesByFrom: new Map([
      [rootId, [edges[0], edges[2]]],
      [parentId, [edges[1]]]
    ]),
    rootDirectNodeIds: new Set([parentId, directId]),
    resolvePackage: () => undefined
  };
}

function makeFinding(params: {
  vulnId: string;
  packageId: string;
  packageName: string;
  packageVersion: string;
  fixedVersion?: string;
  paths: string[][];
}): Finding {
  return {
    vulnId: params.vulnId,
    aliases: [],
    summary: params.vulnId,
    affected: [
      {
        package: {
          id: params.packageId,
          name: params.packageName,
          version: params.packageVersion,
          location: params.packageId,
          flags: {}
        },
        paths: params.paths,
        reachability: {
          reachable: true,
          level: "import",
          evidences: [],
          traces: []
        },
        fix: params.fixedVersion
          ? {
              fixedVersion: params.fixedVersion
            }
          : undefined
      }
    ],
    references: []
  };
}

function makeScanResult(): ScanResult {
  return {
    meta: {
      tool: {
        name: "npmvulncheck",
        version: "0.1.0"
      },
      mode: "lockfile",
      format: "json",
      db: {
        name: "osv"
      },
      timestamp: "2026-01-01T00:00:00.000Z"
    },
    findings: [
      makeFinding({
        vulnId: "GHSA-transitive",
        packageId: "node_modules/pkg-a",
        packageName: "pkg-a",
        packageVersion: "1.0.0",
        fixedVersion: "1.2.0",
        paths: [["fixture@1.0.0", "parent@2.0.0", "pkg-a@1.0.0"]]
      }),
      makeFinding({
        vulnId: "GHSA-direct",
        packageId: "node_modules/pkg-b",
        packageName: "pkg-b",
        packageVersion: "2.0.0",
        fixedVersion: "2.2.0",
        paths: [["fixture@1.0.0", "pkg-b@2.0.0"]]
      })
    ],
    stats: {
      nodes: 4,
      edges: 3,
      queriedPackages: 3,
      vulnerabilities: 2
    }
  };
}

describe("fix plan snapshot", () => {
  it("matches expected override plan output", () => {
    const plan = buildRemediationPlan(makeScanResult(), makeGraph(), {
      strategy: "override",
      manager: "npm",
      policy: {
        scope: "by-parent",
        upgradeLevel: "any",
        onlyReachable: false,
        includeUnreachable: true,
        includeDev: false
      },
      relock: true,
      verify: true
    });

    expect(plan).toMatchSnapshot();
  });
});
