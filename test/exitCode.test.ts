import { describe, expect, it } from "vitest";
import { determineExitCode } from "../src/cli/exitCode";
import { Finding, ScanOptions, ScanResult } from "../src/core/types";

function makeFinding(id: string, reachable: boolean, direct: boolean): Finding {
  return {
    vulnId: id,
    aliases: [],
    summary: "test",
    affected: [
      {
        package: {
          id: direct ? "node_modules/direct" : "node_modules/transitive",
          name: "pkg",
          version: "1.0.0",
          location: direct ? "node_modules/direct" : "node_modules/transitive",
          flags: {}
        },
        paths: [direct ? ["root@1.0.0", "pkg@1.0.0"] : ["root@1.0.0", "a@1.0.0", "pkg@1.0.0"]],
        reachability: reachable
          ? {
              reachable: true,
              level: "transitive",
              evidences: [],
              traces: [["src/index.ts:1:1", "a", "pkg"]]
            }
          : {
              reachable: false,
              level: "unknown",
              evidences: [],
              traces: [["unreachable"]]
            }
      }
    ],
    references: []
  };
}

function makeResult(findings: Finding[]): ScanResult {
  return {
    meta: {
      tool: { name: "npmvulncheck", version: "0.1.0" },
      mode: "source",
      format: "text",
      db: { name: "osv" },
      timestamp: "2026-01-01T00:00:00.000Z"
    },
    findings,
    stats: {
      nodes: 1,
      edges: 0,
      queriedPackages: 1,
      vulnerabilities: findings.length
    }
  };
}

function makeOptions(overrides: Partial<ScanOptions>): ScanOptions {
  return {
    root: process.cwd(),
    mode: "source",
    format: "text",
    entries: [],
    showTraces: false,
    showVerbose: false,
    includeDev: false,
    exitCodeOn: "findings",
    failOn: "all",
    offline: false,
    ...overrides
  };
}

describe("determineExitCode", () => {
  it("returns 1 for findings in text-compatible mode", () => {
    const code = determineExitCode(
      makeResult([makeFinding("GHSA-1", true, true)]),
      makeOptions({ exitCodeOn: "findings" })
    );
    expect(code).toBe(1);
  });

  it("returns 0 when exit policy is none (json/sarif/openvex default compatibility)", () => {
    const code = determineExitCode(
      makeResult([makeFinding("GHSA-1", true, true)]),
      makeOptions({ format: "json", exitCodeOn: "none" })
    );
    expect(code).toBe(0);
  });

  it("respects reachable-findings and fail-on filters", () => {
    const findings = [
      makeFinding("GHSA-unreachable", false, true),
      makeFinding("GHSA-transitive", true, false)
    ];

    const reachableOnly = determineExitCode(
      makeResult(findings),
      makeOptions({ exitCodeOn: "reachable-findings", failOn: "all" })
    );
    expect(reachableOnly).toBe(1);

    const directReachableOnly = determineExitCode(
      makeResult(findings),
      makeOptions({ exitCodeOn: "reachable-findings", failOn: "direct" })
    );
    expect(directReachableOnly).toBe(0);
  });
});
