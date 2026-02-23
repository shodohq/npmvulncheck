import { describe, expect, it } from "vitest";
import { renderRemediationText } from "../src/remediation/render";
import { RemediationPlan } from "../src/remediation/types";

function makePlan(opId: string): RemediationPlan {
  return {
    tool: "npmvulncheck",
    strategy: "override",
    packageManager: "npm",
    target: {
      onlyReachable: false,
      includeDev: false
    },
    operations: [],
    fixes: {
      fixedVulnerabilities: [],
      remainingVulnerabilities: ["GHSA-example"]
    },
    summary: {
      reasonedTopChoices: [
        {
          opId,
          rationale: "No applicable transitive overrides were generated from current findings.",
          risk: "high"
        }
      ]
    }
  };
}

describe("renderRemediationText", () => {
  it("shows a direct dependency hint when direct upgrades are required", () => {
    const text = renderRemediationText(makePlan("op-direct-upgrade-required"));

    expect(text).toContain("No manifest override changes were generated.");
    expect(text).toContain(
      "Hint: override strategy currently remediates transitive dependencies only. Upgrade vulnerable direct dependencies in package.json."
    );
  });

  it("omits direct dependency hint for generic no-op plans", () => {
    const text = renderRemediationText(makePlan("op-no-applicable-override"));

    expect(text).toContain("No manifest override changes were generated.");
    expect(text).not.toContain("Upgrade vulnerable direct dependencies in package.json.");
  });

  it("renders direct dependency changes when present", () => {
    const plan = makePlan("op-manifest-direct-upgrade-1");
    plan.operations = [
      {
        id: "op-manifest-direct-upgrade-1",
        kind: "manifest-direct-upgrade",
        file: "package.json",
        depField: "dependencies",
        package: "lodash",
        fromRange: "^4.17.0",
        toRange: "4.17.21",
        why: "test"
      }
    ];
    plan.fixes.fixedVulnerabilities = ["GHSA-example"];
    plan.fixes.remainingVulnerabilities = [];

    const text = renderRemediationText(plan);

    expect(text).toContain("Direct dependency changes:");
    expect(text).toContain("lodash: ^4.17.0 -> 4.17.21 [field=dependencies]");
    expect(text).not.toContain("No manifest override changes were generated.");
  });
});
