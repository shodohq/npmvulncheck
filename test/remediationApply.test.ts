import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyRemediationPlan } from "../src/remediation";
import { RemediationPlan } from "../src/remediation/types";
import { DependencyGraphProvider } from "../src/deps/provider";
import { VulnerabilityProvider } from "../src/osv/provider";
import { cleanupTempDirs, makeTempDir } from "./helpers";

afterEach(async () => {
  await cleanupTempDirs();
});

const unusedDepsProvider: DependencyGraphProvider = {
  detect: async () => true,
  load: async () => {
    throw new Error("not used");
  }
};

const unusedVulnProvider: VulnerabilityProvider = {
  name: "osv",
  queryPackages: async () => new Map(),
  getVuln: async () => {
    throw new Error("not used");
  }
};

function makeNpmPlan(): RemediationPlan {
  return {
    tool: "npmvulncheck",
    strategy: "override",
    packageManager: "npm",
    target: {
      onlyReachable: false,
      includeDev: false
    },
    operations: [
      {
        id: "op-manifest-override-1",
        kind: "manifest-override",
        manager: "npm",
        file: "package.json",
        changes: [
          {
            package: "lodash",
            to: "4.17.21",
            scope: "global",
            why: "test"
          }
        ]
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

describe("applyRemediationPlan validation", () => {
  it("rejects invalid npm override plans before writing files", async () => {
    const root = await makeTempDir("npmvulncheck-remediation-apply-");
    const packageJsonPath = path.join(root, "package.json");
    const original = JSON.stringify(
      {
        name: "fixture",
        version: "1.0.0",
        dependencies: {
          lodash: "^4.17.0"
        }
      },
      null,
      2
    );
    await fs.writeFile(packageJsonPath, `${original}\n`, "utf8");

    await expect(
      applyRemediationPlan(
        makeNpmPlan(),
        {
          projectRoot: root,
          rollbackOnFail: true
        },
        unusedDepsProvider,
        unusedVulnProvider
      )
    ).rejects.toThrow("EOVERRIDE");

    const after = await fs.readFile(packageJsonPath, "utf8");
    expect(after).toBe(`${original}\n`);
  });

  it("applies direct upgrade before override validation in auto strategy", async () => {
    const root = await makeTempDir("npmvulncheck-remediation-apply-auto-");
    const packageJsonPath = path.join(root, "package.json");
    await fs.writeFile(
      packageJsonPath,
      `${JSON.stringify(
        {
          name: "fixture",
          version: "1.0.0",
          dependencies: {
            lodash: "^4.17.0"
          }
        },
        null,
        2
      )}\n`,
      "utf8"
    );

    const plan: RemediationPlan = {
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
          package: "lodash",
          fromRange: "^4.17.0",
          toRange: "4.17.21",
          why: "test direct"
        },
        {
          id: "op-manifest-override-1",
          kind: "manifest-override",
          manager: "npm",
          file: "package.json",
          changes: [
            {
              package: "lodash",
              to: "4.17.21",
              scope: "global",
              why: "test override"
            }
          ]
        }
      ],
      fixes: {
        fixedVulnerabilities: ["GHSA-test"],
        remainingVulnerabilities: []
      },
      summary: {
        reasonedTopChoices: []
      }
    };

    await expect(
      applyRemediationPlan(
        plan,
        {
          projectRoot: root,
          rollbackOnFail: true
        },
        unusedDepsProvider,
        unusedVulnProvider
      )
    ).resolves.toEqual({});

    const parsed = JSON.parse(await fs.readFile(packageJsonPath, "utf8")) as {
      dependencies?: Record<string, string>;
      overrides?: Record<string, string>;
    };
    expect(parsed.dependencies?.lodash).toBe("4.17.21");
    expect(parsed.overrides?.lodash).toBe("4.17.21");
  });
});
