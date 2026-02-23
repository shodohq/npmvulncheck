import fs from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { DepGraph, DependencyManager } from "../src/core/types";
import { DependencyGraphProvider } from "../src/deps/provider";
import { VulnerabilityProvider } from "../src/osv/provider";
import { applyRemediationPlan } from "../src/remediation";
import { buildRelockCommand } from "../src/remediation/apply/relockRunner";
import { RemediationPlan } from "../src/remediation/types";
import { cleanupTempDirs, makeTempDir } from "./helpers";

afterEach(async () => {
  await cleanupTempDirs();
});

class RootOnlyDepsProvider implements DependencyGraphProvider {
  async detect(_projectRoot: string): Promise<boolean> {
    return true;
  }

  async load(_projectRoot: string, _mode: "lockfile" | "installed"): Promise<DepGraph> {
    return {
      ecosystem: "npm",
      rootId: "root",
      nodes: new Map([
        ["root", { id: "root", name: "fixture", version: "1.0.0", location: "root", flags: {} }]
      ]),
      edges: [],
      edgesByFrom: new Map(),
      rootDirectNodeIds: new Set(),
      resolvePackage: () => undefined
    };
  }
}

class NoVulnProvider implements VulnerabilityProvider {
  readonly name = "osv";

  async queryPackages(
    pkgs: Array<{ name: string; version: string }>
  ): Promise<Map<string, Array<{ id: string; modified?: string }>>> {
    const out = new Map<string, Array<{ id: string; modified?: string }>>();
    for (const pkg of pkgs) {
      out.set(`${pkg.name}@${pkg.version}`, []);
    }
    return out;
  }

  async getVuln(_id: string): Promise<never> {
    throw new Error("not used");
  }
}

function hasCommand(command: string, args: string[] = ["--version"]): boolean {
  const result = spawnSync(command, args, { stdio: "ignore" });
  return result.status === 0;
}

function hasYarnBerry(): boolean {
  const result = spawnSync("yarn", ["--version"], {
    encoding: "utf8"
  });
  if (result.status !== 0) {
    return false;
  }

  const major = Number.parseInt(String(result.stdout ?? "").trim().split(".")[0] ?? "", 10);
  return Number.isFinite(major) && major >= 2;
}

const PNPM_AVAILABLE = hasCommand("pnpm");
const YARN_BERRY_AVAILABLE = hasYarnBerry();

function lockfileName(manager: DependencyManager): string {
  if (manager === "npm") {
    return "package-lock.json";
  }
  if (manager === "pnpm") {
    return "pnpm-lock.yaml";
  }
  return "yarn.lock";
}

function lockfileContent(manager: DependencyManager): string | undefined {
  if (manager === "npm") {
    return `${JSON.stringify(
      {
        name: "fixture",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "fixture",
            version: "1.0.0"
          }
        }
      },
      null,
      2
    )}\n`;
  }

  if (manager === "pnpm") {
    return ["lockfileVersion: '9.0'", "importers:", "  .: {}"].join("\n");
  }

  return undefined;
}

function packageJsonContent(manager: DependencyManager): string {
  return `${JSON.stringify(
    {
      name: "fixture",
      version: "1.0.0",
      private: true,
      packageManager:
        manager === "pnpm" ? "pnpm@10.26.2" : manager === "yarn" ? "yarn@4.5.0" : undefined
    },
    null,
    2
  )}\n`;
}

function makePlan(manager: DependencyManager): RemediationPlan {
  const relock = buildRelockCommand(manager);
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
        id: "op-manifest-override-1",
        kind: "manifest-override",
        manager,
        file: "package.json",
        changes: [
          {
            package: "left-pad",
            to: "1.3.0",
            scope: "global",
            why: "fixture"
          }
        ]
      },
      {
        id: "op-relock-1",
        kind: "relock",
        manager,
        command: relock.command,
        args: relock.args
      },
      {
        id: "op-verify-1",
        kind: "verify",
        note: "fixture verify"
      }
    ],
    fixes: {
      fixedVulnerabilities: ["GHSA-simulated"],
      remainingVulnerabilities: []
    },
    summary: {
      reasonedTopChoices: []
    }
  };
}

function expectManifestOverride(manager: DependencyManager, parsed: Record<string, unknown>): void {
  if (manager === "npm") {
    const overrides = parsed.overrides as Record<string, string> | undefined;
    expect(overrides?.["left-pad"]).toBe("1.3.0");
    return;
  }

  if (manager === "pnpm") {
    const pnpm = parsed.pnpm as { overrides?: Record<string, string> } | undefined;
    expect(pnpm?.overrides?.["left-pad"]).toBe("1.3.0");
    return;
  }

  const resolutions = parsed.resolutions as Record<string, string> | undefined;
  expect(resolutions?.["left-pad"]).toBe("1.3.0");
}

async function runManagerE2E(manager: DependencyManager): Promise<void> {
  const root = await makeTempDir(`npmvulncheck-remediation-e2e-${manager}-`);
  const packageJsonPath = path.join(root, "package.json");
  const lockfilePath = path.join(root, lockfileName(manager));

  await fs.writeFile(packageJsonPath, packageJsonContent(manager), "utf8");
  const initialLockfile = lockfileContent(manager);
  if (initialLockfile !== undefined) {
    await fs.writeFile(lockfilePath, initialLockfile, "utf8");
  }

  const applied = await applyRemediationPlan(
    makePlan(manager),
    {
      projectRoot: root,
      lockfilePath,
      rollbackOnFail: true,
      verify: {
        scanOptions: {
          root,
          mode: "lockfile",
          format: "json",
          entries: [],
          conditions: [],
          includeTypeImports: false,
          showTraces: false,
          showVerbose: false,
          includeDev: false,
          exitCodeOn: "none",
          failOn: "all",
          offline: true
        },
        expectedFixedVulnIds: ["GHSA-simulated"],
        baselineVulnIds: ["GHSA-simulated"],
        noIntroduce: true,
        toolVersion: "0.1.0"
      }
    },
    new RootOnlyDepsProvider(),
    new NoVulnProvider()
  );

  const parsed = JSON.parse(await fs.readFile(packageJsonPath, "utf8")) as Record<string, unknown>;
  expectManifestOverride(manager, parsed);
  expect(applied.verify?.ok).toBe(true);
  expect(applied.verify?.fixedVulnerabilities).toEqual(["GHSA-simulated"]);
}

describe("remediation e2e apply/relock/verify", () => {
  it("applies manifest overrides, relocks with npm, and verifies", async () => {
    await runManagerE2E("npm");
  });

  it.skipIf(!PNPM_AVAILABLE)("applies manifest overrides, relocks with pnpm, and verifies", async () => {
    await runManagerE2E("pnpm");
  });

  it.skipIf(!YARN_BERRY_AVAILABLE)("applies manifest overrides, relocks with yarn berry, and verifies", async () => {
    await runManagerE2E("yarn");
  });
});
