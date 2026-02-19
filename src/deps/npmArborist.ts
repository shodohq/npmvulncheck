import fs from "node:fs/promises";
import fsSync from "node:fs";
import path from "node:path";
import Arborist from "@npmcli/arborist";
import { DepEdgeType, DepGraph, DependencyEdge, ImportKind, PackageNode } from "../core/types";
import { normalizePackageSpecifier } from "../reachability/packageResolve";
import { buildEdgesByFrom, makeEmptyDepGraph, makePurl } from "./graph";
import { DependencyGraphProvider } from "./provider";

type ArboristEdge = {
  name?: string;
  type?: string;
  to?: ArboristNode | null;
};

type ArboristNode = {
  location: string;
  name?: string;
  version?: string;
  dev?: boolean;
  optional?: boolean;
  peer?: boolean;
  path?: string;
  realpath?: string;
  edgesOut?: Map<string, ArboristEdge>;
  inventory?: {
    values: () => IterableIterator<ArboristNode>;
  };
  resolve?: (name: string) => ArboristNode | null;
};

type PackageManifest = {
  imports?: unknown;
  exports?: unknown;
};

type ResolverContext = {
  node: ArboristNode;
  realpath: string;
};

type BarePackageSpecifier = {
  packageName: string;
  subpath: string;
};

type ResolveWithNodeResult = {
  resolved?: ArboristNode;
  blockedByExports?: boolean;
};

type TargetResolutionStatus = "resolved" | "blocked" | "unresolved";

function mapEdgeType(edgeType: string | undefined): DepEdgeType {
  switch (edgeType) {
    case "dev":
      return "dev";
    case "peer":
    case "peerOptional":
      return "peer";
    case "optional":
      return "optional";
    default:
      return "prod";
  }
}

function packageNameFromNode(node: ArboristNode, projectRoot: string): string {
  if (node.name && node.name.length > 0) {
    return node.name;
  }
  return path.basename(projectRoot);
}

function packageVersionFromNode(node: ArboristNode): string {
  if (node.version && node.version.length > 0) {
    return node.version;
  }
  return "0.0.0";
}

function toPackageNode(node: ArboristNode, projectRoot: string): PackageNode {
  const name = packageNameFromNode(node, projectRoot);
  const version = packageVersionFromNode(node);
  const source = node.location.includes("node_modules") ? "registry" : "workspace";
  return {
    id: node.location,
    name,
    version,
    location: node.location,
    purl: makePurl(name, version),
    source,
    flags: {
      dev: node.dev,
      optional: node.optional,
      peer: node.peer
    }
  };
}

function toAbsoluteRealpath(projectRoot: string, node: ArboristNode): string {
  const candidate = node.realpath ?? node.path ?? path.resolve(projectRoot, node.location);
  try {
    return fsSync.realpathSync(candidate);
  } catch {
    return path.resolve(candidate);
  }
}

function isSubPath(parentDir: string, childPath: string): boolean {
  const rel = path.relative(parentDir, childPath);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function createContainingNodeFinder(rootContext: ResolverContext, contexts: ResolverContext[]): (fromFile?: string) => ArboristNode {
  const sorted = [...contexts].sort((a, b) => b.realpath.length - a.realpath.length);
  const cache = new Map<string, ArboristNode>();

  return (fromFile?: string): ArboristNode => {
    if (!fromFile) {
      return rootContext.node;
    }

    let normalized = cache.get(fromFile);
    if (normalized) {
      return normalized;
    }

    const absolute = path.resolve(fromFile);
    for (const context of sorted) {
      if (isSubPath(context.realpath, absolute)) {
        cache.set(fromFile, context.node);
        return context.node;
      }
    }

    cache.set(fromFile, rootContext.node);
    return rootContext.node;
  };
}

function matchImportsKey(imports: Record<string, unknown>, specifier: string): { value: unknown; match?: string } | undefined {
  if (Object.prototype.hasOwnProperty.call(imports, specifier)) {
    return { value: imports[specifier] };
  }

  let best: { key: string; value: unknown; match: string } | undefined;
  for (const [key, value] of Object.entries(imports)) {
    const wildcardIndex = key.indexOf("*");
    if (wildcardIndex < 0) {
      continue;
    }

    const prefix = key.slice(0, wildcardIndex);
    const suffix = key.slice(wildcardIndex + 1);
    if (!specifier.startsWith(prefix) || !specifier.endsWith(suffix)) {
      continue;
    }

    const matched = specifier.slice(prefix.length, specifier.length - suffix.length);
    if (!best || key.length > best.key.length) {
      best = { key, value, match: matched };
    }
  }

  if (!best) {
    return undefined;
  }

  return {
    value: best.value,
    match: best.match
  };
}

function isConditionKeyMatch(key: string, conditions: string[]): boolean {
  return key === "default" || conditions.includes(key);
}

function defaultConditionsForImportKind(importKind?: ImportKind): string[] {
  if (importKind === "cjs-require") {
    return ["node", "require", "default"];
  }
  return ["node", "import", "default"];
}

function parseBarePackageSpecifier(specifier: string): BarePackageSpecifier | undefined {
  if (
    !specifier ||
    specifier.startsWith(".") ||
    specifier.startsWith("/") ||
    specifier.startsWith("#") ||
    specifier.startsWith("node:")
  ) {
    return undefined;
  }

  if (specifier.startsWith("@")) {
    const parts = specifier.split("/");
    if (parts.length < 2) {
      return undefined;
    }
    const packageName = `${parts[0]}/${parts[1]}`;
    const subpath = parts.length > 2 ? `./${parts.slice(2).join("/")}` : ".";
    return { packageName, subpath };
  }

  const parts = specifier.split("/");
  const packageName = parts[0];
  if (!packageName) {
    return undefined;
  }
  const subpath = parts.length > 1 ? `./${parts.slice(1).join("/")}` : ".";
  return { packageName, subpath };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function matchExportsKey(exportsRecord: Record<string, unknown>, subpath: string): { value: unknown; match?: string } | undefined {
  if (Object.prototype.hasOwnProperty.call(exportsRecord, subpath)) {
    return { value: exportsRecord[subpath] };
  }

  let best: { key: string; value: unknown; match: string } | undefined;
  for (const [key, value] of Object.entries(exportsRecord)) {
    const wildcardIndex = key.indexOf("*");
    if (wildcardIndex < 0) {
      continue;
    }

    const prefix = key.slice(0, wildcardIndex);
    const suffix = key.slice(wildcardIndex + 1);
    if (!subpath.startsWith(prefix) || !subpath.endsWith(suffix)) {
      continue;
    }

    const matched = subpath.slice(prefix.length, subpath.length - suffix.length);
    if (!best || key.length > best.key.length) {
      best = { key, value, match: matched };
    }
  }

  if (!best) {
    return undefined;
  }

  return { value: best.value, match: best.match };
}

function hasSubpathExportsKeys(exportsRecord: Record<string, unknown>): boolean {
  return Object.keys(exportsRecord).some((key) => key === "." || key.startsWith("./"));
}

function resolveExportsTargetStatus(
  value: unknown,
  wildcardMatch: string | undefined,
  conditions: string[]
): TargetResolutionStatus {
  if (value === null) {
    return "blocked";
  }

  if (typeof value === "string") {
    const replaced = wildcardMatch ? value.replace(/\*/g, wildcardMatch) : value;
    return replaced.length > 0 ? "resolved" : "unresolved";
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const resolved = resolveExportsTargetStatus(item, wildcardMatch, conditions);
      if (resolved !== "unresolved") {
        return resolved;
      }
    }
    return "unresolved";
  }

  if (isRecord(value)) {
    for (const [condition, conditionValue] of Object.entries(value)) {
      if (!isConditionKeyMatch(condition, conditions)) {
        continue;
      }

      const resolved = resolveExportsTargetStatus(conditionValue, wildcardMatch, conditions);
      if (resolved !== "unresolved") {
        return resolved;
      }
    }
    return "unresolved";
  }

  return "unresolved";
}

function isSubpathExported(exportsField: unknown, subpath: string, conditions: string[]): boolean {
  if (exportsField === undefined) {
    return true;
  }

  if (!isRecord(exportsField)) {
    return subpath === "." && resolveExportsTargetStatus(exportsField, undefined, conditions) === "resolved";
  }

  if (!hasSubpathExportsKeys(exportsField)) {
    return subpath === "." && resolveExportsTargetStatus(exportsField, undefined, conditions) === "resolved";
  }

  const matched = matchExportsKey(exportsField, subpath);
  if (!matched) {
    return false;
  }

  return resolveExportsTargetStatus(matched.value, matched.match, conditions) === "resolved";
}

function resolveImportsTarget(
  value: unknown,
  wildcardMatch: string | undefined,
  conditions: string[],
  resolvePackageFromNode: (specifier: string) => string | undefined | null,
  resolveNestedImports: (specifier: string) => string | undefined | null,
  seenTargets: Set<string>
): string | undefined | null {
  if (value === null) {
    return null;
  }

  if (typeof value === "string") {
    const resolvedValue = wildcardMatch ? value.replace(/\*/g, wildcardMatch) : value;
    if (resolvedValue.startsWith("#")) {
      if (seenTargets.has(resolvedValue)) {
        return undefined;
      }
      seenTargets.add(resolvedValue);
      return resolveNestedImports(resolvedValue);
    }

    if (resolvedValue.startsWith(".") || resolvedValue.startsWith("/")) {
      return undefined;
    }

    return resolvePackageFromNode(resolvedValue);
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const resolved = resolveImportsTarget(
        item,
        wildcardMatch,
        conditions,
        resolvePackageFromNode,
        resolveNestedImports,
        seenTargets
      );
      if (resolved !== undefined) {
        return resolved;
      }
    }
    return undefined;
  }

  if (typeof value === "object" && value !== null) {
    for (const [condition, conditionValue] of Object.entries(value)) {
      if (!isConditionKeyMatch(condition, conditions)) {
        continue;
      }

      const resolved = resolveImportsTarget(
        conditionValue,
        wildcardMatch,
        conditions,
        resolvePackageFromNode,
        resolveNestedImports,
        seenTargets
      );
      if (resolved !== undefined) {
        return resolved;
      }
    }
  }

  return undefined;
}

function resolveWithNode(
  node: ArboristNode,
  specifier: string,
  importKind: ImportKind | undefined,
  conditions: string[] | undefined,
  packageManifestByNodeId: Map<string, PackageManifest>
): ResolveWithNodeResult {
  if (!node.resolve) {
    return {};
  }

  const parsedSpecifier = parseBarePackageSpecifier(specifier);
  const packageName = parsedSpecifier?.packageName ?? normalizePackageSpecifier(specifier) ?? specifier;
  if (!packageName) {
    return {};
  }

  const resolved = node.resolve(packageName);
  if (!resolved || !resolved.location) {
    return {};
  }

  if (parsedSpecifier) {
    const manifest = packageManifestByNodeId.get(resolved.location);
    if (manifest?.exports !== undefined) {
      const effectiveConditions =
        conditions && conditions.length > 0 ? Array.from(new Set(conditions)) : defaultConditionsForImportKind(importKind);
      if (!isSubpathExported(manifest.exports, parsedSpecifier.subpath, effectiveConditions)) {
        return { blockedByExports: true };
      }
    }
  }

  return { resolved };
}

async function readPackageManifest(packageRoot: string): Promise<PackageManifest | undefined> {
  const manifestPath = path.join(packageRoot, "package.json");
  const text = await fs.readFile(manifestPath, "utf8").catch(() => undefined);
  if (!text) {
    return undefined;
  }

  try {
    return JSON.parse(text) as PackageManifest;
  } catch {
    return undefined;
  }
}

export class NpmArboristProvider implements DependencyGraphProvider {
  async detect(projectRoot: string, mode: "lockfile" | "installed" | "source" = "lockfile"): Promise<boolean> {
    const lockPath = path.join(projectRoot, "package-lock.json");
    const shrinkwrapPath = path.join(projectRoot, "npm-shrinkwrap.json");
    const nodeModulesPath = path.join(projectRoot, "node_modules");

    const [lockStat, shrinkStat, nodeModulesStat] = await Promise.all([
      fs.stat(lockPath).catch(() => null),
      fs.stat(shrinkwrapPath).catch(() => null),
      fs.stat(nodeModulesPath).catch(() => null)
    ]);

    const hasLock = Boolean(lockStat?.isFile() || shrinkStat?.isFile());
    const hasNodeModules = Boolean(nodeModulesStat?.isDirectory());

    if (mode === "installed") {
      return hasNodeModules;
    }

    return hasLock;
  }

  async load(projectRoot: string, mode: "lockfile" | "installed"): Promise<DepGraph> {
    const graph = makeEmptyDepGraph();
    graph.manager = "npm";

    if (mode === "installed") {
      const nodeModulesPath = path.join(projectRoot, "node_modules");
      const stat = await fs.stat(nodeModulesPath).catch(() => null);
      if (!stat?.isDirectory()) {
        throw new Error(`installed mode requires node_modules at ${nodeModulesPath}`);
      }
    }

    const arb = new Arborist({ path: projectRoot });
    const rootNode: ArboristNode =
      mode === "installed"
        ? ((await arb.loadActual()) as ArboristNode)
        : ((await arb.loadVirtual()) as ArboristNode);

    const inventory = rootNode.inventory ? Array.from(rootNode.inventory.values()) : [rootNode];

    for (const node of inventory) {
      const pkgNode = toPackageNode(node, projectRoot);
      graph.nodes.set(pkgNode.id, pkgNode);
    }

    const edges: DependencyEdge[] = [];
    for (const node of inventory) {
      const fromId = node.location;
      if (!graph.nodes.has(fromId) || !node.edgesOut) {
        continue;
      }

      for (const edge of node.edgesOut.values()) {
        const toNode = edge.to;
        if (!toNode || !toNode.location || !graph.nodes.has(toNode.location)) {
          continue;
        }
        const depEdge: DependencyEdge = {
          from: fromId,
          to: toNode.location,
          name: edge.name ?? graph.nodes.get(toNode.location)?.name ?? "unknown",
          type: mapEdgeType(edge.type)
        };
        edges.push(depEdge);
      }
    }

    graph.rootId = rootNode.location;
    graph.importers?.set(".", rootNode.location);
    graph.edges = edges;
    graph.edgesByFrom = buildEdgesByFrom(edges);

    for (const edge of graph.edgesByFrom.get(graph.rootId) ?? []) {
      graph.rootDirectNodeIds.add(edge.to);
    }

    const contexts: ResolverContext[] = inventory.map((node) => ({
      node,
      realpath: toAbsoluteRealpath(projectRoot, node)
    }));
    const rootContext = contexts.find((context) => context.node.location === rootNode.location) ?? {
      node: rootNode,
      realpath: toAbsoluteRealpath(projectRoot, rootNode)
    };
    const containingNodeForFile = createContainingNodeFinder(rootContext, contexts);

    const packageManifestByNodeId = new Map<string, PackageManifest>();
    const packageImportsByNodeId = new Map<string, unknown>();
    await Promise.all(
      contexts.map(async (context) => {
        const manifest = await readPackageManifest(context.realpath);
        if (manifest) {
          packageManifestByNodeId.set(context.node.location, manifest);
        }
        if (manifest?.imports) {
          packageImportsByNodeId.set(context.node.location, manifest.imports);
        }
      })
    );

    const resolveFromContainingNode = (
      specifier: string,
      containingNode: ArboristNode,
      importKind?: ImportKind,
      conditions?: string[]
    ): string | undefined | null => {
      const resolvedFromContaining = resolveWithNode(
        containingNode,
        specifier,
        importKind,
        conditions,
        packageManifestByNodeId
      );
      if (resolvedFromContaining.blockedByExports) {
        return null;
      }
      if (resolvedFromContaining.resolved && graph.nodes.has(resolvedFromContaining.resolved.location)) {
        return resolvedFromContaining.resolved.location;
      }

      return undefined;
    };

    graph.resolvePackage = (
      specifier: string,
      fromFile?: string,
      importKind?: ImportKind,
      conditions?: string[]
    ): string | undefined | null => {
      const containingNode = containingNodeForFile(fromFile);
      return resolveFromContainingNode(specifier, containingNode, importKind, conditions);
    };

    graph.resolveInternalImport = (
      specifier: string,
      fromFile: string,
      importKind: ImportKind,
      conditions: string[]
    ): string | undefined => {
      if (!specifier.startsWith("#")) {
        return undefined;
      }

      const containingNode = containingNodeForFile(fromFile);
      const imports = packageImportsByNodeId.get(containingNode.location);
      if (!imports || typeof imports !== "object" || Array.isArray(imports)) {
        return undefined;
      }

      const importsRecord = imports as Record<string, unknown>;
      const seenTargets = new Set([specifier]);
      const resolveNestedImports = (nestedSpecifier: string): string | undefined | null => {
        const nestedMatch = matchImportsKey(importsRecord, nestedSpecifier);
        if (!nestedMatch) {
          return undefined;
        }

        return resolveImportsTarget(
          nestedMatch.value,
          nestedMatch.match,
          conditions,
          (targetSpecifier) => resolveFromContainingNode(targetSpecifier, containingNode, importKind, conditions),
          resolveNestedImports,
          seenTargets
        );
      };

      const matched = matchImportsKey(importsRecord, specifier);
      if (!matched) {
        return undefined;
      }

      const resolved = resolveImportsTarget(
        matched.value,
        matched.match,
        conditions,
        (targetSpecifier) => resolveFromContainingNode(targetSpecifier, containingNode, importKind, conditions),
        resolveNestedImports,
        seenTargets
      );
      return resolved ?? undefined;
    };

    graph.resolvePackageCandidates = (
      specifier: string,
      fromFile?: string,
      importKind?: ImportKind,
      conditions?: string[]
    ): string[] => {
      const direct = graph.resolvePackage(specifier, fromFile, importKind, conditions);
      if (direct === null) {
        return [];
      }
      if (direct) {
        return [direct];
      }

      const normalized = normalizePackageSpecifier(specifier);
      if (!normalized || normalized === specifier) {
        return [];
      }

      const normalizedResolved = graph.resolvePackage(normalized, fromFile, importKind, conditions);
      if (!normalizedResolved || normalizedResolved === null) {
        return [];
      }

      return [normalizedResolved];
    };

    return graph;
  }
}
