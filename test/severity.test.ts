import { describe, expect, it } from "vitest";
import { Finding, ScanResult } from "../src/core/types";
import { passesSeverityThreshold } from "../src/policy/filters";
import { findingHighestSeverityLevel } from "../src/policy/severity";
import { renderSarif } from "../src/report/sarif";

function makeFinding(score: string): Finding {
  return {
    vulnId: "GHSA-test",
    aliases: [],
    summary: "test",
    severity: [{ type: "CVSS_V3", score }],
    affected: [
      {
        package: {
          id: "node_modules/pkg",
          name: "pkg",
          version: "1.0.0",
          location: "node_modules/pkg",
          flags: {}
        },
        paths: [["root@1.0.0", "pkg@1.0.0"]]
      }
    ],
    references: []
  };
}

function makeResult(finding: Finding): ScanResult {
  return {
    meta: {
      tool: { name: "npmvulncheck", version: "0.1.0" },
      mode: "source",
      format: "sarif",
      db: { name: "osv" },
      timestamp: "2026-01-01T00:00:00.000Z"
    },
    findings: [finding],
    stats: { nodes: 1, edges: 0, queriedPackages: 1, vulnerabilities: 1 }
  };
}

describe("severity parsing", () => {
  it("parses CVSS vector and computes severity level", () => {
    const finding = makeFinding("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(findingHighestSeverityLevel(finding)).toBe("critical");
  });

  it("applies severity threshold using numeric score", () => {
    const finding = makeFinding("7.5");
    expect(passesSeverityThreshold(finding, "high")).toBe(true);
    expect(passesSeverityThreshold(finding, "critical")).toBe(false);
  });

  it("uses parsed severity for SARIF level", () => {
    const finding = makeFinding("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    const sarif = JSON.parse(renderSarif(makeResult(finding))) as {
      runs: Array<{ results: Array<{ level: string }> }>;
    };
    expect(sarif.runs[0].results[0].level).toBe("error");
  });
});
