import { describe, expect, it } from "vitest";
import { ScanResult } from "../src/core/types";
import { renderOpenVex } from "../src/report/openvex";
import { renderSarif } from "../src/report/sarif";

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
