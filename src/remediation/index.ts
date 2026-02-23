import fs from "node:fs/promises";
import path from "node:path";
import { DepGraph } from "../core/types";
import { ScanResult } from "../core/types";
import { DependencyGraphProvider } from "../deps/provider";
import { VulnerabilityProvider } from "../osv/provider";
import { applyManifestDirectUpgradeOperation, applyManifestOverrideOperation } from "./apply/manifestWriter";
import { buildRelockCommand, runRelockOperation } from "./apply/relockRunner";
import { runVerify } from "./apply/verifyRunner";
import { getManifestOverrideProvider } from "./providers";
import { buildOverridePlan } from "./strategies/overrideStrategy";
import { buildHybridPlan } from "./strategies/hybridStrategy";
import {
  ApplyRemediationOptions,
  ApplyRemediationResult,
  BuildRemediationPlanOptions,
  RemediationPlan,
  RemediationStrategy
} from "./types";

const DIRECT_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"] as const;
type DirectField = (typeof DIRECT_FIELDS)[number];

function resolveStrategy(strategy: RemediationStrategy): "override" | "direct" | "auto" {
  if (strategy === "override" || strategy === "direct" || strategy === "auto") {
    return strategy;
  }

  throw new Error(`Strategy \"${strategy}\" is not implemented yet. Use --strategy=override|direct|auto.`);
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
      : buildHybridPlan({
          manager: options.manager,
          findings: result.findings,
          rootDirectNodeIds: graph.rootDirectNodeIds,
          policy: options.policy,
          includeDirect: true,
          includeTransitive: resolvedStrategy === "auto",
          strategyLabel: resolvedStrategy
        });

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

function asObject(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function cloneJsonObject<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function resolveDirectUpgradeTarget(
  packageJson: Record<string, unknown>,
  operation: Extract<RemediationPlan["operations"][number], { kind: "manifest-direct-upgrade" }>
): { field: DirectField; deps: Record<string, unknown> } | undefined {
  const preferred = asObject(packageJson[operation.depField]);
  if (preferred && typeof preferred[operation.package] === "string") {
    return {
      field: operation.depField,
      deps: preferred
    };
  }

  for (const field of DIRECT_FIELDS) {
    const deps = asObject(packageJson[field]);
    if (deps && typeof deps[operation.package] === "string") {
      return { field, deps };
    }
  }

  return undefined;
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

function validateManifestDirectUpgradeOperations(plan: RemediationPlan, packageJson: Record<string, unknown>): string[] {
  const errors: string[] = [];
  for (const operation of plan.operations) {
    if (operation.kind !== "manifest-direct-upgrade") {
      continue;
    }

    if (!operation.package || !operation.toRange) {
      errors.push(`invalid direct upgrade operation "${operation.id}" (missing package or toRange).`);
      continue;
    }

    const target = resolveDirectUpgradeTarget(packageJson, operation);
    if (!target) {
      errors.push(
        `direct dependency "${operation.package}" was not found in dependencies/devDependencies/optionalDependencies.`
      );
    }
  }
  return errors;
}

function applyDirectUpgradeOperationsToManifest(
  packageJson: Record<string, unknown>,
  plan: RemediationPlan
): Record<string, unknown> {
  const projected = cloneJsonObject(packageJson);

  for (const operation of plan.operations) {
    if (operation.kind !== "manifest-direct-upgrade") {
      continue;
    }

    const target = resolveDirectUpgradeTarget(projected, operation);
    if (!target) {
      continue;
    }

    target.deps[operation.package] = operation.toRange;
    projected[target.field] = target.deps;
  }

  return projected;
}

async function validateManifestOperations(plan: RemediationPlan, packageJsonPath: string): Promise<void> {
  const raw = await fs.readFile(packageJsonPath, "utf8");
  const packageJson = JSON.parse(raw) as unknown;
  if (!packageJson || typeof packageJson !== "object" || Array.isArray(packageJson)) {
    throw new Error("Invalid remediation plan:\npackage.json is not a JSON object.");
  }

  const packageObject = packageJson as Record<string, unknown>;
  const errors = validateManifestDirectUpgradeOperations(plan, packageObject);

  const overrideOperations = plan.operations.filter((operation) => operation.kind === "manifest-override");
  if (overrideOperations.length === 0) {
    if (errors.length > 0) {
      throw new Error(`Invalid remediation plan:\n${errors.join("\n")}`);
    }
    return;
  }

  const projectedManifest = applyDirectUpgradeOperationsToManifest(packageObject, plan);

  const managers = new Set(overrideOperations.map((operation) => operation.manager));

  for (const manager of managers) {
    const provider = getManifestOverrideProvider(manager);
    const validation = provider.validate(plan, projectedManifest);
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
    await validateManifestOperations(plan, packageJsonPath);

    for (const operation of plan.operations) {
      if (operation.kind === "manifest-direct-upgrade") {
        await snapshotFile(packageJsonPath, snapshots);
        await applyManifestDirectUpgradeOperation(operation, options.projectRoot);
        continue;
      }

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
