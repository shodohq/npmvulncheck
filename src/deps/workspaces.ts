import fs from "node:fs/promises";
import path from "node:path";

export type PackageJsonImporter = {
  key: string;
  absPath: string;
  name: string;
  version: string;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
  peerDependencies: Record<string, string>;
};

type WorkspaceField = string[] | { packages?: string[] };

type PackageJsonManifest = {
  name?: string;
  version?: string;
  workspaces?: WorkspaceField;
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readPackageJson(filePath: string): Promise<PackageJsonManifest | undefined> {
  const text = await fs.readFile(filePath, "utf8").catch(() => undefined);
  if (!text) {
    return undefined;
  }

  try {
    return JSON.parse(text) as PackageJsonManifest;
  } catch {
    return undefined;
  }
}

function toDependencyRecord(value: Record<string, unknown> | undefined): Record<string, string> {
  if (!value) {
    return {};
  }

  const out: Record<string, string> = {};
  for (const [name, range] of Object.entries(value)) {
    if (typeof range === "string") {
      out[name] = range;
    }
  }
  return out;
}

function normalizeWorkspacePatterns(workspaces: WorkspaceField | undefined): string[] {
  if (!workspaces) {
    return [];
  }
  if (Array.isArray(workspaces)) {
    return workspaces.filter((item): item is string => typeof item === "string");
  }
  if (isRecord(workspaces) && Array.isArray(workspaces.packages)) {
    return workspaces.packages.filter((item): item is string => typeof item === "string");
  }
  return [];
}

async function resolveWorkspacePattern(rootDir: string, pattern: string): Promise<string[]> {
  const normalized = pattern.replace(/\\/g, "/").replace(/^\.\//, "");
  if (!normalized.includes("*")) {
    const abs = path.resolve(rootDir, normalized);
    const stat = await fs.stat(path.join(abs, "package.json")).catch(() => null);
    return stat?.isFile() ? [abs] : [];
  }

  if (!normalized.endsWith("/*")) {
    return [];
  }

  const base = normalized.slice(0, -2);
  const baseAbs = path.resolve(rootDir, base);
  const entries = await fs.readdir(baseAbs, { withFileTypes: true }).catch(() => []);
  const out: string[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const abs = path.join(baseAbs, entry.name);
    const stat = await fs.stat(path.join(abs, "package.json")).catch(() => null);
    if (stat?.isFile()) {
      out.push(abs);
    }
  }

  return out;
}

export async function discoverPackageJsonImporters(rootDir: string): Promise<PackageJsonImporter[]> {
  const rootPkgPath = path.join(rootDir, "package.json");
  const rootManifest = await readPackageJson(rootPkgPath);
  if (!rootManifest) {
    return [];
  }

  const importers: PackageJsonImporter[] = [];
  const appendImporter = async (absPath: string, key: string): Promise<void> => {
    const manifest = await readPackageJson(path.join(absPath, "package.json"));
    if (!manifest) {
      return;
    }

    importers.push({
      key,
      absPath,
      name: typeof manifest.name === "string" && manifest.name.length > 0 ? manifest.name : path.basename(absPath),
      version: typeof manifest.version === "string" && manifest.version.length > 0 ? manifest.version : "0.0.0",
      dependencies: toDependencyRecord(manifest.dependencies),
      devDependencies: toDependencyRecord(manifest.devDependencies),
      optionalDependencies: toDependencyRecord(manifest.optionalDependencies),
      peerDependencies: toDependencyRecord(manifest.peerDependencies)
    });
  };

  await appendImporter(rootDir, ".");

  const patterns = normalizeWorkspacePatterns(rootManifest.workspaces);
  const workspaceAbsPaths = new Set<string>();
  for (const pattern of patterns) {
    const matches = await resolveWorkspacePattern(rootDir, pattern);
    for (const abs of matches) {
      workspaceAbsPaths.add(abs);
    }
  }

  const sorted = Array.from(workspaceAbsPaths).sort((a, b) => a.localeCompare(b));
  for (const abs of sorted) {
    const rel = path.relative(rootDir, abs) || ".";
    await appendImporter(abs, rel.replace(/\\/g, "/"));
  }

  return importers;
}
