import { describe, expect, it } from "vitest";
import { ScanResult } from "../src/core/types";
import { renderJson } from "../src/report/json";
import { renderOpenVex } from "../src/report/openvex";
import { renderSarif } from "../src/report/sarif";
import { RemediationPlan } from "../src/remediation/types";

function makeResult(reachability: { reachable: boolean; level: "import" | "transitive" | "unknown" }): ScanResult {
  return {
    meta: {
      tool: { name: "npmvulncheck", version: "0.1.0" },
      mode: "source",
      format: "text",
      db: { name: "osv" },
      timestamp: "2026-01-01T00:00:00.000Z"
    },
    findings: [
      {
        vulnId: "GHSA-test",
        aliases: ["CVE-2026-0001"],
        summary: "Test vulnerability",
        severity: [{ type: "CVSS_V3", score: "HIGH" }],
        affected: [
          {
            package: {
              id: "node_modules/pkg",
              name: "pkg",
              version: "1.0.0",
              location: "node_modules/pkg",
              purl: "pkg:npm/pkg@1.0.0",
              flags: {}
            },
            paths: [["root@1.0.0", "pkg@1.0.0"]],
            reachability: {
              reachable: reachability.reachable,
              level: reachability.level,
              evidences: reachability.reachable
                ? [{ kind: "import", file: "src/index.ts", line: 1, column: 1, specifier: "pkg", importText: 'import "pkg"' }]
                : [],
              traces: [[reachability.reachable ? "src/index.ts:1:1" : "unreachable", "pkg"]]
            }
          }
        ],
        references: [{ type: "ADVISORY", url: "https://example.test/advisory" }]
      }
    ],
    stats: { nodes: 2, edges: 1, queriedPackages: 1, vulnerabilities: 1 }
  };
}

function makeRemediationPlan(): RemediationPlan {
  return {
    tool: "npmvulncheck",
    strategy: "auto",
    packageManager: "npm",
    target: {
      onlyReachable: false,
      includeDev: false
    },
    operations: [
      {
        id: "op-manifest-direct-upgrade-1",
        kind: "manifest-direct-upgrade",
        file: "package.json",
        depField: "dependencies",
        package: "pkg",
        fromRange: "1.0.0",
        toRange: "1.2.0",
        why: "Fixes GHSA-test"
      }
    ],
    fixes: {
      fixedVulnerabilities: ["GHSA-test"],
      remainingVulnerabilities: []
    },
    summary: {
      reasonedTopChoices: [
        {
          opId: "op-manifest-direct-upgrade-1",
          rationale: "fixture",
          risk: "low"
        }
      ]
    }
  };
}

describe("report renderers", () => {
  it("renders SARIF with required top-level fields", () => {
    const parsed = JSON.parse(renderSarif(makeResult({ reachable: true, level: "import" }))) as {
      version: string;
      runs: Array<{ tool: { driver: { rules: Array<{ id: string }> } }; results: unknown[] }>;
    };

    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].tool.driver.rules[0].id).toBe("GHSA-test");
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
  });

  it("renders SARIF fixes when a remediation plan is supplied", () => {
    const result = makeResult({ reachable: true, level: "import" });
    const plan = makeRemediationPlan();

    const parsed = JSON.parse(
      renderSarif(result, {
        remediationPlan: plan
      })
    ) as {
      runs: Array<{ results: Array<{ fixes?: Array<{ description: { text: string } }> }> }>;
    };

    expect(parsed.runs[0].results[0].fixes?.length).toBeGreaterThan(0);
    expect(parsed.runs[0].results[0].fixes?.[0]?.description.text).toContain("Upgrade direct dependency pkg");
  });

  it("renders JSON remediation payload and fix note when remediation plan is supplied", () => {
    const result = makeResult({ reachable: true, level: "import" });
    const parsed = JSON.parse(
      renderJson(result, {
        remediationPlan: makeRemediationPlan()
      })
    ) as {
      remediation?: { strategy?: string };
      findings: Array<{ affected: Array<{ fix?: { note?: string } }> }>;
    };

    expect(parsed.remediation?.strategy).toBe("auto");
    expect(parsed.findings[0].affected[0].fix?.note).toContain("Upgrade direct dependency pkg");
  });

  it("renders OpenVEX action_statement from remediation plan when available", () => {
    const parsed = JSON.parse(
      renderOpenVex(makeResult({ reachable: true, level: "import" }), {
        remediationPlan: makeRemediationPlan()
      })
    ) as {
      statements: Array<{ action_statement?: string }>;
    };

    expect(parsed.statements[0].action_statement).toContain("Upgrade direct dependency pkg");
  });

  it("renders OpenVEX not_affected with justification for unreachable findings", () => {
    const parsed = JSON.parse(renderOpenVex(makeResult({ reachable: false, level: "transitive" }))) as {
      statements: Array<{ status: string; justification?: string }>;
    };

    expect(parsed.statements).toHaveLength(1);
    expect(parsed.statements[0].status).toBe("not_affected");
    expect(parsed.statements[0].justification).toBe("vulnerable_code_not_in_execute_path");
  });

  it("renders OpenVEX under_investigation when reachability is unknown", () => {
    const parsed = JSON.parse(renderOpenVex(makeResult({ reachable: false, level: "unknown" }))) as {
      statements: Array<{ status: string; justification?: string }>;
    };

    expect(parsed.statements).toHaveLength(1);
    expect(parsed.statements[0].status).toBe("under_investigation");
    expect(parsed.statements[0].justification).toBeUndefined();
  });
});
