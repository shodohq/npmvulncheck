import { describe, expect, it } from "vitest";
import { Finding } from "../src/core/types";
import { buildOverridePlan } from "../src/remediation/strategies/overrideStrategy";

function makeFinding(params: {
  vulnId: string;
  packageId: string;
  packageName: string;
  packageVersion: string;
  paths: string[][];
  fixedVersion?: string;
  reachable?: boolean;
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
          reachable: Boolean(params.reachable),
          level: params.reachable ? "import" : "unknown",
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

describe("buildOverridePlan", () => {
  it("plans transitive overrides and excludes direct dependencies", () => {
    const findings: Finding[] = [
      makeFinding({
        vulnId: "GHSA-transitive",
        packageId: "node_modules/pkg-a",
        packageName: "pkg-a",
        packageVersion: "1.0.0",
        fixedVersion: "1.2.0",
        reachable: true,
        paths: [["root@1.0.0", "parent@2.0.0", "pkg-a@1.0.0"]]
      }),
      makeFinding({
        vulnId: "GHSA-direct",
        packageId: "node_modules/pkg-b",
        packageName: "pkg-b",
        packageVersion: "2.0.0",
        fixedVersion: "2.1.0",
        reachable: true,
        paths: [["root@1.0.0", "pkg-b@2.0.0"]]
      }),
      makeFinding({
        vulnId: "GHSA-no-fix",
        packageId: "node_modules/pkg-c",
        packageName: "pkg-c",
        packageVersion: "3.0.0",
        reachable: true,
        paths: [["root@1.0.0", "parent@1.0.0", "pkg-c@3.0.0"]]
      })
    ];

    const plan = buildOverridePlan({
      manager: "npm",
      findings,
      rootDirectNodeIds: new Set(["node_modules/pkg-b"]),
      policy: {
        scope: "global",
        upgradeLevel: "any",
        onlyReachable: false,
        includeUnreachable: true,
        includeDev: false
      }
    });

    const op = plan.operations.find((operation) => operation.kind === "manifest-override");
    expect(op).toBeDefined();
    if (!op || op.kind !== "manifest-override") {
      return;
    }

    expect(op.changes).toHaveLength(1);
    expect(op.changes[0]).toMatchObject({
      package: "pkg-a",
      to: "1.2.0",
      scope: "global"
    });

    expect(plan.fixes.fixedVulnerabilities).toEqual(["GHSA-transitive"]);
    expect(plan.fixes.remainingVulnerabilities).toEqual(["GHSA-direct", "GHSA-no-fix"]);
  });

  it("creates by-parent scoped changes when requested", () => {
    const plan = buildOverridePlan({
      manager: "pnpm",
      findings: [
        makeFinding({
          vulnId: "GHSA-parent-scope",
          packageId: "node_modules/pkg-a",
          packageName: "pkg-a",
          packageVersion: "1.0.0",
          fixedVersion: "1.2.0",
          reachable: true,
          paths: [["root@1.0.0", "webpack@5.90.0", "pkg-a@1.0.0"]]
        })
      ],
      rootDirectNodeIds: new Set(),
      policy: {
        scope: "by-parent",
        upgradeLevel: "any",
        onlyReachable: false,
        includeUnreachable: true,
        includeDev: false
      }
    });

    const op = plan.operations.find((operation) => operation.kind === "manifest-override");
    expect(op).toBeDefined();
    if (!op || op.kind !== "manifest-override") {
      return;
    }

    expect(op.changes[0].scope).toEqual({
      parent: "webpack",
      parentVersion: "5.90.0"
    });
  });

  it("creates by-parent overrides for each unique parent path", () => {
    const plan = buildOverridePlan({
      manager: "npm",
      findings: [
        makeFinding({
          vulnId: "GHSA-multi-parent",
          packageId: "node_modules/pkg-a",
          packageName: "pkg-a",
          packageVersion: "1.0.0",
          fixedVersion: "1.2.0",
          reachable: true,
          paths: [
            ["root@1.0.0", "webpack@5.90.0", "pkg-a@1.0.0"],
            ["root@1.0.0", "rollup@4.12.0", "pkg-a@1.0.0"],
            ["root@1.0.0", "webpack@5.90.0", "pkg-a@1.0.0"]
          ]
        })
      ],
      rootDirectNodeIds: new Set(),
      policy: {
        scope: "by-parent",
        upgradeLevel: "any",
        onlyReachable: false,
        includeUnreachable: true,
        includeDev: false
      }
    });

    const op = plan.operations.find((operation) => operation.kind === "manifest-override");
    expect(op).toBeDefined();
    if (!op || op.kind !== "manifest-override") {
      return;
    }

    expect(op.changes).toHaveLength(2);
    expect(op.changes.map((change) => change.scope)).toEqual([
      { parent: "rollup", parentVersion: "4.12.0" },
      { parent: "webpack", parentVersion: "5.90.0" }
    ]);
  });

  it("filters out unreachable findings when onlyReachable is enabled", () => {
    const plan = buildOverridePlan({
      manager: "npm",
      findings: [
        makeFinding({
          vulnId: "GHSA-unreachable",
          packageId: "node_modules/pkg-a",
          packageName: "pkg-a",
          packageVersion: "1.0.0",
          fixedVersion: "1.2.0",
          reachable: false,
          paths: [["root@1.0.0", "parent@2.0.0", "pkg-a@1.0.0"]]
        })
      ],
      rootDirectNodeIds: new Set(),
      policy: {
        scope: "global",
        upgradeLevel: "any",
        onlyReachable: true,
        includeUnreachable: false,
        includeDev: false
      }
    });

    expect(plan.operations).toHaveLength(0);
    expect(plan.fixes.fixedVulnerabilities).toEqual([]);
    expect(plan.fixes.remainingVulnerabilities).toEqual([]);
  });

  it("does not allow downgrade candidates even with upgrade-level any", () => {
    const plan = buildOverridePlan({
      manager: "npm",
      findings: [
        makeFinding({
          vulnId: "GHSA-downgrade",
          packageId: "node_modules/pkg-a",
          packageName: "pkg-a",
          packageVersion: "3.2.0",
          fixedVersion: "2.9.0",
          reachable: true,
          paths: [["root@1.0.0", "parent@2.0.0", "pkg-a@3.2.0"]]
        })
      ],
      rootDirectNodeIds: new Set(),
      policy: {
        scope: "global",
        upgradeLevel: "any",
        onlyReachable: false,
        includeUnreachable: true,
        includeDev: false
      }
    });

    expect(plan.operations).toHaveLength(0);
    expect(plan.fixes.fixedVulnerabilities).toEqual([]);
    expect(plan.fixes.remainingVulnerabilities).toEqual(["GHSA-downgrade"]);
  });
});
