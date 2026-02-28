import { describe, expect, it } from "vitest";
import { Finding, ScanMode } from "../src/core/types";
import { evaluateFindingPriority } from "../src/policy/priority";

function makeFinding(
  reachability?: { reachable: boolean; level: "import" | "transitive" | "unknown" },
  severityScore?: string
): Finding {
  return {
    vulnId: "GHSA-priority-test",
    aliases: [],
    summary: "priority test",
    severity: severityScore ? [{ type: "CVSS_V3", score: severityScore }] : undefined,
    affected: [
      {
        package: {
          id: "node_modules/pkg",
          name: "pkg",
          version: "1.0.0",
          location: "node_modules/pkg",
          flags: {}
        },
        paths: [["root@1.0.0", "pkg@1.0.0"]],
        reachability: reachability
          ? {
              reachable: reachability.reachable,
              level: reachability.level,
              evidences: [],
              traces: [["trace"]]
            }
          : undefined
      }
    ],
    references: []
  };
}

function evaluate(mode: ScanMode, finding: Finding) {
  return evaluateFindingPriority(finding, mode);
}

describe("evaluateFindingPriority", () => {
  it("ranks reachable findings higher than unknown and unreachable in source mode", () => {
    const reachable = evaluate("source", makeFinding({ reachable: true, level: "import" }, "HIGH"));
    const unknown = evaluate("source", makeFinding({ reachable: false, level: "unknown" }, "HIGH"));
    const unreachable = evaluate("source", makeFinding({ reachable: false, level: "transitive" }, "HIGH"));

    expect(reachable.level).toBe("high");
    expect(reachable.reason).toBe("reachable");
    expect(unknown.level).toBe("medium");
    expect(unknown.reason).toBe("unknown-reachability");
    expect(unreachable.level).toBe("low");
    expect(unreachable.reason).toBe("unreachable");

    expect(reachable.score).toBeGreaterThan(unknown.score);
    expect(unknown.score).toBeGreaterThan(unreachable.score);
  });

  it("falls back to severity-based priority outside source mode", () => {
    const high = evaluate("lockfile", makeFinding(undefined, "9.8"));
    const medium = evaluate("lockfile", makeFinding(undefined, "5.0"));
    const low = evaluate("lockfile", makeFinding(undefined, "2.0"));

    expect(high.level).toBe("high");
    expect(medium.level).toBe("medium");
    expect(low.level).toBe("low");
    expect(high.reason).toBe("severity");
    expect(high.score).toBeGreaterThan(medium.score);
    expect(medium.score).toBeGreaterThan(low.score);
  });
});
