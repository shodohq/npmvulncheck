import { describe, expect, it } from "vitest";
import { NpmOverridesProvider } from "../src/remediation/providers/npmOverridesProvider";
import { PnpmOverridesProvider } from "../src/remediation/providers/pnpmOverridesProvider";
import { YarnResolutionsProvider } from "../src/remediation/providers/yarnResolutionsProvider";
import { RemediationPlan } from "../src/remediation/types";

function makePlan(manager: "npm" | "pnpm" | "yarn", changes: Array<{
  package: string;
  to: string;
  scope: "global" | { parent: string; parentVersion?: string };
}>): RemediationPlan {
  return {
    tool: "npmvulncheck",
    strategy: "override",
    packageManager: manager,
    target: {
      onlyReachable: false,
      includeDev: false
    },
    operations: [
      {
        id: "op-1",
        kind: "manifest-override",
        manager,
        file: "package.json",
        changes: changes.map((change) => ({
          package: change.package,
          to: change.to,
          scope: change.scope,
          why: "test"
        }))
      }
    ],
    fixes: {
      fixedVulnerabilities: [],
      remainingVulnerabilities: []
    },
    summary: {
      reasonedTopChoices: []
    }
  };
}

describe("remediation manifest providers", () => {
  it("builds npm override keys for global and parent-scoped overrides", () => {
    const provider = new NpmOverridesProvider();

    expect(provider.buildOverrideKey({ pkg: "lodash" })).toBe("lodash");
    expect(provider.buildOverrideKey({ pkg: "lodash", scope: { parent: "webpack" } })).toBe("webpack>lodash");
    expect(provider.buildOverrideKey({ pkg: "lodash", scope: { parent: "webpack", parentVersion: "5.0.0" } })).toBe(
      "webpack@5.0.0>lodash"
    );
  });

  it("merges npm scoped overrides into nested objects", () => {
    const provider = new NpmOverridesProvider();
    const merged = provider.mergeOverrides(
      {
        debug: "4.3.4"
      },
      {
        "webpack>lodash": "4.17.21"
      }
    );

    expect(merged).toEqual({
      debug: "4.3.4",
      webpack: {
        lodash: "4.17.21"
      }
    });
  });

  it("builds pnpm override keys", () => {
    const provider = new PnpmOverridesProvider();

    expect(provider.buildOverrideKey({ pkg: "lodash" })).toBe("lodash");
    expect(provider.buildOverrideKey({ pkg: "lodash", scope: { parent: "webpack", parentVersion: "5.0.0" } })).toBe(
      "webpack@5.0.0>lodash"
    );
  });

  it("builds yarn resolution keys", () => {
    const provider = new YarnResolutionsProvider();

    expect(provider.buildOverrideKey({ pkg: "lodash" })).toBe("lodash");
    expect(provider.buildOverrideKey({ pkg: "memory-fs", scope: { parent: "webpack" } })).toBe("webpack/memory-fs");
    expect(provider.buildOverrideKey({ pkg: "memory-fs", scope: { parent: "webpack", parentVersion: "5.1.0" } })).toBe(
      "webpack@5.1.0/memory-fs"
    );
  });

  it("validates npm direct dependency override conflicts", () => {
    const provider = new NpmOverridesProvider();
    const plan = makePlan("npm", [
      {
        package: "lodash",
        to: "4.17.21",
        scope: "global"
      }
    ]);

    const validation = provider.validate(plan, {
      name: "fixture",
      version: "1.0.0",
      dependencies: {
        lodash: "^4.17.0"
      }
    });

    expect(validation.ok).toBe(false);
    if (validation.ok) {
      return;
    }
    expect(validation.errors.some((message) => message.includes("EOVERRIDE"))).toBe(true);
  });
});
