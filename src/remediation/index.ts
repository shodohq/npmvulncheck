import fs from "node:fs/promises";
import path from "node:path";
import { DepGraph } from "../core/types";
import { ScanResult } from "../core/types";
import { DependencyGraphProvider } from "../deps/provider";
import { VulnerabilityProvider } from "../osv/provider";
import { applyManifestOverrideOperation } from "./apply/manifestWriter";
import { buildRelockCommand, runRelockOperation } from "./apply/relockRunner";
import { runVerify } from "./apply/verifyRunner";
import { getManifestOverrideProvider } from "./providers";
import { buildOverridePlan } from "./strategies/overrideStrategy";
import {
  ApplyRemediationOptions,
  ApplyRemediationResult,
  BuildRemediationPlanOptions,
  RemediationPlan,
  RemediationStrategy
} from "./types";

function resolveStrategy(strategy: RemediationStrategy): "override" {
  if (strategy === "override" || strategy === "auto") {
    return "override";
  }

  throw new Error(`Strategy \"${strategy}\" is not implemented yet. Use --strategy=override.`);
}

export function buildRemediationPlan(
  result: ScanResult,
  graph: DepGraph,
  options: BuildRemediationPlanOptions
): RemediationPlan {
  const resolvedStrategy = resolveStrategy(options.strategy);

  const basePlan =
    resolvedStrategy === "override"
      ? buildOverridePlan({
          manager: options.manager,
          findings: result.findings,
          rootDirectNodeIds: graph.rootDirectNodeIds,
          policy: options.policy
        })
      : undefined;

  if (!basePlan) {
    throw new Error(`Unsupported strategy: ${options.strategy}`);
  }

  const operations = [...basePlan.operations];

  if (options.relock) {
    const relock = buildRelockCommand(options.manager);
    operations.push({
      id: "op-relock-1",
      kind: "relock",
      manager: options.manager,
      command: relock.command,
      args: relock.args
    });
  }

  if (options.verify) {
    operations.push({
      id: "op-verify-1",
      kind: "verify",
      note: "Rescan to confirm selected vulnerabilities were fixed."
    });
  }

  return {
    ...basePlan,
    strategy: options.strategy,
    operations
  };
}

async function snapshotFile(filePath: string, snapshots: Map<string, string | undefined>): Promise<void> {
  if (snapshots.has(filePath)) {
    return;
  }

  const stat = await fs.stat(filePath).catch(() => undefined);
  if (stat && !stat.isFile()) {
    return;
  }

  const raw = await fs.readFile(filePath, "utf8").catch(() => undefined);
  snapshots.set(filePath, raw);
}

async function rollbackSnapshots(snapshots: Map<string, string | undefined>): Promise<void> {
  for (const [filePath, content] of snapshots.entries()) {
    if (content === undefined) {
      await fs.rm(filePath, { force: true });
      continue;
    }
    await fs.writeFile(filePath, content, "utf8");
  }
}

async function validateManifestOverrideOperations(plan: RemediationPlan, packageJsonPath: string): Promise<void> {
  const operations = plan.operations.filter((operation) => operation.kind === "manifest-override");
  if (operations.length === 0) {
    return;
  }

  const raw = await fs.readFile(packageJsonPath, "utf8");
  const packageJson = JSON.parse(raw) as unknown;

  const managers = new Set(operations.map((operation) => operation.manager));
  const errors: string[] = [];

  for (const manager of managers) {
    const provider = getManifestOverrideProvider(manager);
    const validation = provider.validate(plan, packageJson);
    if (!validation.ok) {
      errors.push(...validation.errors.map((message) => `${manager}: ${message}`));
    }
  }

  if (errors.length > 0) {
    throw new Error(`Invalid remediation plan:\n${errors.join("\n")}`);
  }
}

export async function applyRemediationPlan(
  plan: RemediationPlan,
  options: ApplyRemediationOptions,
  depsProvider: DependencyGraphProvider,
  vulnProvider: VulnerabilityProvider
): Promise<ApplyRemediationResult> {
  const snapshots = new Map<string, string | undefined>();
  const packageJsonPath = path.join(options.projectRoot, "package.json");

  let verifyResult: ApplyRemediationResult["verify"];

  try {
    await validateManifestOverrideOperations(plan, packageJsonPath);

    for (const operation of plan.operations) {
      if (operation.kind === "manifest-override") {
        await snapshotFile(packageJsonPath, snapshots);
        await applyManifestOverrideOperation(operation, options.projectRoot);
        continue;
      }

      if (operation.kind === "relock") {
        if (options.lockfilePath) {
          await snapshotFile(options.lockfilePath, snapshots);
        }
        await runRelockOperation(operation, options.projectRoot);
        continue;
      }

      if (operation.kind === "verify") {
        if (!options.verify) {
          continue;
        }

        verifyResult = await runVerify(options.verify, depsProvider, vulnProvider);
      }
    }
  } catch (error) {
    if (options.rollbackOnFail) {
      await rollbackSnapshots(snapshots);
    }
    throw error;
  }

  return {
    verify: verifyResult
  };
}
