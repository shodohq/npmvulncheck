import fs from "node:fs/promises";
import path from "node:path";
import { DepGraph, DependencyManager, ScanMode } from "../core/types";
import { NpmArboristProvider } from "./npmArborist";
import { PnpmLockfileProvider } from "./pnpm";
import {
  DependencyGraphProvider,
  DetectResult,
  LockfileProvider,
  PackageResolver,
  ProviderCapabilities,
  ProviderContext
} from "./provider";
import { YarnLockfileProvider } from "./yarn";

type LockfileSelection = {
  provider: LockfileProvider;
  detected: DetectResult;
};

function mergeDetectDetails(detected: DetectResult, details: Record<string, unknown>): DetectResult {
  return {
    ...detected,
    details: {
      ...(detected.details ?? {}),
      ...details
    }
  };
}

function normalizeManager(packageManager: string | undefined): DependencyManager | undefined {
  if (!packageManager) {
    return undefined;
  }
  const [name] = packageManager.split("@", 1);
  if (name === "npm" || name === "pnpm" || name === "yarn") {
    return name;
  }
  return undefined;
}

async function readPackageManagerField(projectRoot: string): Promise<DependencyManager | undefined> {
  const packageJsonPath = path.join(projectRoot, "package.json");
  const raw = await fs.readFile(packageJsonPath, "utf8").catch(() => undefined);
  if (!raw) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(raw) as { packageManager?: string };
    return normalizeManager(parsed.packageManager);
  } catch {
    return undefined;
  }
}

class NpmLockfileAdapter implements LockfileProvider {
  name: "npm" = "npm";

  constructor(private readonly npmProvider: NpmArboristProvider) {}

  async detect(rootDir: string): Promise<DetectResult | null> {
    const packageLockPath = path.join(rootDir, "package-lock.json");
    const shrinkwrapPath = path.join(rootDir, "npm-shrinkwrap.json");
    const [packageLockStat, shrinkwrapStat] = await Promise.all([
      fs.stat(packageLockPath).catch(() => null),
      fs.stat(shrinkwrapPath).catch(() => null)
    ]);

    if (packageLockStat?.isFile()) {
      return {
        manager: "npm",
        lockfilePath: packageLockPath
      };
    }

    if (shrinkwrapStat?.isFile()) {
      return {
        manager: "npm",
        lockfilePath: shrinkwrapPath
      };
    }

    return null;
  }

  async load(rootDir: string): Promise<ProviderContext> {
    const detected = await this.detect(rootDir);
    if (!detected) {
      throw new Error(`npm lockfile not found in ${rootDir}`);
    }

    const graph = await this.npmProvider.load(rootDir, "lockfile");
    graph.manager = "npm";

    const resolver: PackageResolver = {
      resolve: (request: string, issuerFile: string): string[] => {
        const candidates = graph.resolvePackageCandidates?.(request, issuerFile, "esm-import", ["node", "import", "default"]);
        if (candidates && candidates.length > 0) {
          return candidates;
        }
        const single = graph.resolvePackage(request, issuerFile, "esm-import", ["node", "import", "default"]);
        return single ? [single] : [];
      }
    };

    const capabilities: ProviderCapabilities = {
      lockfileGraph: true,
      lockfileResolver: true,
      fsResolver: true,
      pnpResolver: false
    };

    return {
      detect: detected,
      graph,
      capabilities,
      resolver
    };
  }
}

export class ProviderRegistry implements DependencyGraphProvider {
  private readonly npmProvider: NpmArboristProvider;
  private readonly lockfileProviders: LockfileProvider[];

  constructor(
    npmProvider = new NpmArboristProvider(),
    pnpmProvider = new PnpmLockfileProvider(),
    yarnProvider = new YarnLockfileProvider()
  ) {
    this.npmProvider = npmProvider;
    this.lockfileProviders = [pnpmProvider, yarnProvider, new NpmLockfileAdapter(this.npmProvider)];
  }

  private async selectLockfileProvider(projectRoot: string): Promise<LockfileSelection | null> {
    const [preferredManager, detections] = await Promise.all([
      readPackageManagerField(projectRoot),
      Promise.all(this.lockfileProviders.map(async (provider) => ({ provider, detected: await provider.detect(projectRoot) })))
    ]);

    const available = detections.filter(
      (item): item is { provider: LockfileProvider; detected: DetectResult } => item.detected !== null
    );
    if (available.length === 0) {
      return null;
    }

    const detectedManagers = available.map((item) => item.detected.manager);
    const warnings: string[] = [];
    if (preferredManager && !detectedManagers.includes(preferredManager)) {
      warnings.push(
        `package.json#packageManager is "${preferredManager}" but matching lockfile was not found; falling back to detected lockfile.`
      );
    }

    const withSelectionWarnings = (
      selected: { provider: LockfileProvider; detected: DetectResult },
      reason: "packageManager" | "fallback"
    ): LockfileSelection => {
      const selectionWarnings = [...warnings];
      if (available.length > 1) {
        const selectionReason =
          reason === "packageManager" ? "based on package.json#packageManager" : "by default priority order";
        selectionWarnings.unshift(
          `Multiple lockfiles detected (${detectedManagers.join(", ")}). ` +
            `Using ${selected.detected.manager} ${selectionReason}.`
        );
      }
      return {
        provider: selected.provider,
        detected:
          selectionWarnings.length > 0
            ? mergeDetectDetails(selected.detected, { warnings: selectionWarnings, detectedManagers })
            : selected.detected
      };
    };

    if (preferredManager) {
      const preferred = available.find((item) => item.detected.manager === preferredManager);
      if (preferred) {
        return withSelectionWarnings(preferred, "packageManager");
      }
    }

    const fallbackOrder: DependencyManager[] = ["pnpm", "yarn", "npm"];
    for (const manager of fallbackOrder) {
      const hit = available.find((item) => item.detected.manager === manager);
      if (hit) {
        return withSelectionWarnings(hit, "fallback");
      }
    }

    return withSelectionWarnings(available[0], "fallback");
  }

  async detect(projectRoot: string, mode: ScanMode = "lockfile"): Promise<boolean> {
    if (mode === "installed") {
      return this.npmProvider.detect(projectRoot, "installed");
    }
    const selected = await this.selectLockfileProvider(projectRoot);
    return Boolean(selected);
  }

  async detectContext(projectRoot: string, mode: ScanMode = "lockfile"): Promise<DetectResult | null> {
    if (mode === "installed") {
      const installed = await this.npmProvider.detect(projectRoot, "installed");
      return installed
        ? {
            manager: "npm",
            lockfilePath: path.join(projectRoot, "node_modules")
          }
        : null;
    }
    const selected = await this.selectLockfileProvider(projectRoot);
    return selected?.detected ?? null;
  }

  async load(projectRoot: string, mode: Extract<ScanMode, "lockfile" | "installed">): Promise<DepGraph> {
    if (mode === "installed") {
      const graph = await this.npmProvider.load(projectRoot, "installed");
      graph.manager = "npm";
      return graph;
    }

    const selected = await this.selectLockfileProvider(projectRoot);
    if (!selected) {
      throw new Error(
        `No supported lockfile found in ${projectRoot}. Expected one of: pnpm-lock.yaml, yarn.lock, package-lock.json, npm-shrinkwrap.json.`
      );
    }

    const context = await selected.provider.load(projectRoot);
    const graph = context.graph;
    graph.manager = selected.detected.manager;

    if (context.resolver && !graph.resolvePackageCandidates) {
      graph.resolvePackageCandidates = (
        specifier: string,
        fromFile?: string,
        _importKind?: unknown,
        _conditions?: string[]
      ): string[] => context.resolver?.resolve(specifier, fromFile ?? path.join(projectRoot, "package.json")) ?? [];
    }

    return graph;
  }
}
