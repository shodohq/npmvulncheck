import fs from "node:fs/promises";
import fsSync from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { parse as parseClassicLockfile } from "@yarnpkg/lockfile";
import { DepEdgeType, DepGraph, ImportKind, NodeSource, PackageNode } from "../core/types";
import { normalizePackageSpecifier } from "../reachability/packageResolve";
import { buildEdgesByFrom, makeEmptyDepGraph, makePurl } from "./graph";
import {
  DetectResult,
  LockfileProvider,
  PackageResolver,
  ProviderCapabilities,
  ProviderContext
} from "./provider";
import { PackageJsonImporter, discoverPackageJsonImporters } from "./workspaces";

type DependencyRecord = Record<string, unknown>;

type YarnVariant = "classic" | "berry";

type YarnClassicEntry = {
  version?: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

type YarnBerryEntry = {
  version?: string;
  resolution?: string;
  checksum?: string;
  linkType?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

type ImporterContext = {
  key: string;
  nodeId: string;
  absPath: string;
};

type PnpLocator = {
  name: string;
  reference: string;
};

type PnpApi = {
  resolveRequest: (request: string, issuer: string, opts?: { considerBuiltins?: boolean }) => string | null;
  findPackageLocator: (location: string) => PnpLocator | null;
};

type PackageManifest = {
  name?: string;
  version?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toStringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function toDependencyRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function splitKeyList(value: string): string[] {
  const output: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;

  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if ((ch === "'" || ch === '"') && quote === undefined) {
      quote = ch;
      current += ch;
      continue;
    }
    if (quote && ch === quote) {
      quote = undefined;
      current += ch;
      continue;
    }
    if (!quote && ch === ",") {
      const trimmed = current.trim();
      if (trimmed.length > 0) {
        output.push(trimmed);
      }
      current = "";
      continue;
    }
    current += ch;
  }

  const trimmed = current.trim();
  if (trimmed.length > 0) {
    output.push(trimmed);
  }
  return output;
}

function unquote(value: string): string {
  if (value.length < 2) {
    return value;
  }
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

function parseDescriptor(selector: string): { name: string; range: string } | undefined {
  const cleaned = unquote(selector.trim());
  if (!cleaned) {
    return undefined;
  }

  if (cleaned.startsWith("@")) {
    const slash = cleaned.indexOf("/");
    if (slash < 0) {
      return undefined;
    }
    const at = cleaned.indexOf("@", slash + 1);
    if (at < 0) {
      return undefined;
    }
    const name = cleaned.slice(0, at);
    const range = cleaned.slice(at + 1);
    return name && range ? { name, range } : undefined;
  }

  const at = cleaned.indexOf("@");
  if (at <= 0) {
    return undefined;
  }
  const name = cleaned.slice(0, at);
  const range = cleaned.slice(at + 1);
  return name && range ? { name, range } : undefined;
}

function normalizeRange(range: string): string {
  return range.startsWith("npm:") ? range.slice(4) : range;
}

function sourceFromProtocol(protocolText: string | undefined): NodeSource {
  if (!protocolText) {
    return "unknown";
  }
  if (protocolText.includes("workspace:")) {
    return "workspace";
  }
  if (protocolText.includes("portal:")) {
    return "portal";
  }
  if (protocolText.includes("link:")) {
    return "link";
  }
  if (protocolText.includes("patch:")) {
    return "patch";
  }
  if (protocolText.includes("file:")) {
    return "file";
  }
  if (protocolText.includes("git+") || protocolText.includes("git:") || protocolText.includes("github:")) {
    return "git";
  }
  if (protocolText.includes("npm:") || protocolText.startsWith("http://") || protocolText.startsWith("https://")) {
    return "registry";
  }
  return "unknown";
}

function depTypeForSection(section: "dependencies" | "devDependencies" | "optionalDependencies" | "peerDependencies"): DepEdgeType {
  switch (section) {
    case "devDependencies":
      return "dev";
    case "optionalDependencies":
      return "optional";
    case "peerDependencies":
      return "peer";
    default:
      return "prod";
  }
}

function uniq(values: string[]): string[] {
  return Array.from(new Set(values));
}

function nameVersionKey(name: string, version: string): string {
  return `${name}@${version}`;
}

function makeNodeVersion(version: string | undefined): string {
  return version && version.length > 0 ? version : "0.0.0";
}

function sourceFromRange(range: string): NodeSource | undefined {
  if (range.startsWith("workspace:")) {
    return "workspace";
  }
  if (range.startsWith("portal:")) {
    return "portal";
  }
  if (range.startsWith("link:")) {
    return "link";
  }
  if (range.startsWith("patch:")) {
    return "patch";
  }
  if (range.startsWith("file:")) {
    return "file";
  }
  if (range.startsWith("git+") || range.startsWith("git:") || range.startsWith("github:")) {
    return "git";
  }
  return undefined;
}

function makeClassicSelectorCandidates(depName: string, depRange: string): string[] {
  const candidates = [`${depName}@${depRange}`];
  if (!depRange.startsWith("npm:")) {
    candidates.push(`${depName}@npm:${depRange}`);
  }
  return uniq(candidates);
}

function makeBerryDescriptorCandidates(depName: string, descriptor: string): string[] {
  const candidates = [`${depName}@${descriptor}`];
  if (!descriptor.includes(":")) {
    candidates.push(`${depName}@npm:${descriptor}`);
  }
  return uniq(candidates);
}

function packageRootFromNodeModulesPath(resolvedPath: string): string | undefined {
  const normalized = path.normalize(resolvedPath);
  const segments = normalized.split(path.sep);
  const joinSegments = (parts: string[]): string => {
    if (parts.length === 0) {
      return "";
    }
    if (parts[0] === "") {
      return `${path.sep}${parts.slice(1).join(path.sep)}`;
    }
    return path.join(...parts);
  };
  for (let i = segments.length - 1; i >= 0; i -= 1) {
    if (segments[i] !== "node_modules") {
      continue;
    }
    const first = segments[i + 1];
    if (!first) {
      continue;
    }
    if (first.startsWith("@")) {
      const second = segments[i + 2];
      if (!second) {
        continue;
      }
      return joinSegments(segments.slice(0, i + 3));
    }
    return joinSegments(segments.slice(0, i + 2));
  }
  return undefined;
}

function packageNameFromNodeModulesPath(resolvedPath: string): string | undefined {
  const normalized = path.normalize(resolvedPath);
  const segments = normalized.split(path.sep);
  for (let i = segments.length - 1; i >= 0; i -= 1) {
    if (segments[i] !== "node_modules") {
      continue;
    }
    const first = segments[i + 1];
    if (!first) {
      continue;
    }
    if (first.startsWith("@")) {
      const second = segments[i + 2];
      if (!second) {
        continue;
      }
      return `${first}/${second}`;
    }
    return first;
  }
  return undefined;
}

function readPackageManifestSync(packageRoot: string): PackageManifest | undefined {
  const manifestPath = path.join(packageRoot, "package.json");
  try {
    const text = fsSync.readFileSync(manifestPath, "utf8");
    const parsed = JSON.parse(text) as PackageManifest;
    return parsed;
  } catch {
    return undefined;
  }
}

function registerDescriptor(mapping: Map<string, Set<string>>, descriptor: string, nodeId: string): void {
  const key = unquote(descriptor.trim());
  if (!key) {
    return;
  }
  const current = mapping.get(key);
  if (current) {
    current.add(nodeId);
    return;
  }
  mapping.set(key, new Set([nodeId]));
}

async function loadPnpApi(rootDir: string): Promise<PnpApi | undefined> {
  const pnpPath = path.join(rootDir, ".pnp.cjs");
  const stat = await fs.stat(pnpPath).catch(() => null);
  if (!stat?.isFile()) {
    return undefined;
  }

  try {
    const requireFromRoot = createRequire(path.join(rootDir, "package.json"));
    const loaded = requireFromRoot(pnpPath) as Partial<PnpApi>;
    if (typeof loaded.resolveRequest !== "function" || typeof loaded.findPackageLocator !== "function") {
      return undefined;
    }
    return loaded as PnpApi;
  } catch {
    return undefined;
  }
}

export class YarnLockfileProvider implements LockfileProvider {
  name: "yarn" = "yarn";

  async detect(rootDir: string): Promise<DetectResult | null> {
    const lockfilePath = path.join(rootDir, "yarn.lock");
    const stat = await fs.stat(lockfilePath).catch(() => null);
    if (!stat?.isFile()) {
      return null;
    }

    const raw = await fs.readFile(lockfilePath, "utf8");
    const header = raw.split(/\r?\n/, 2)[0]?.trim();
    if (header === "# yarn lockfile v1") {
      return {
        manager: "yarn",
        lockfilePath,
        details: {
          variant: "classic"
        }
      };
    }

    let variant: YarnVariant = "berry";
    try {
      const parsed = parseYaml(raw);
      if (!isRecord(parsed) || !Object.prototype.hasOwnProperty.call(parsed, "__metadata")) {
        variant = "berry";
      }
    } catch {
      variant = "classic";
    }

    return {
      manager: "yarn",
      lockfilePath,
      details: {
        variant
      }
    };
  }

  async load(rootDir: string): Promise<ProviderContext> {
    const detected = await this.detect(rootDir);
    if (!detected) {
      throw new Error(`yarn lockfile not found in ${rootDir}`);
    }

    const variant = (detected.details?.variant as YarnVariant | undefined) ?? "berry";
    const raw = await fs.readFile(detected.lockfilePath, "utf8");
    const graph = makeEmptyDepGraph();
    graph.manager = "yarn";

    const importers = await discoverPackageJsonImporters(rootDir);
    const effectiveImporters: PackageJsonImporter[] =
      importers.length > 0
        ? importers
        : [
            {
              key: ".",
              absPath: rootDir,
              name: path.basename(rootDir),
              version: "0.0.0",
              dependencies: {},
              devDependencies: {},
              optionalDependencies: {},
              peerDependencies: {}
            }
          ];

    const importerContexts: ImporterContext[] = [];
    for (const importer of effectiveImporters) {
      const nodeId = `importer:${importer.key}`;
      const node: PackageNode = {
        id: nodeId,
        name: importer.name,
        version: makeNodeVersion(importer.version),
        location: importer.key,
        source: "workspace",
        flags: {}
      };
      graph.nodes.set(nodeId, node);
      graph.importers?.set(importer.key, nodeId);
      importerContexts.push({
        key: importer.key,
        nodeId,
        absPath: importer.absPath
      });
    }
    graph.rootId = graph.importers?.get(".") ?? importerContexts[0].nodeId;

    const edges: { from: string; to: string; name: string; type: DepEdgeType }[] = [];
    const edgeKeys = new Set<string>();
    const descriptorToNodeIds = new Map<string, Set<string>>();
    const nodeIdsByName = new Map<string, Set<string>>();
    const nodeIdsByNameVersion = new Map<string, Set<string>>();
    const localNodeByRef = new Map<string, string>();

    const registerNodeNameIndexes = (node: PackageNode): void => {
      const byName = nodeIdsByName.get(node.name);
      if (byName) {
        byName.add(node.id);
      } else {
        nodeIdsByName.set(node.name, new Set([node.id]));
      }
      const byNameVersion = nodeIdsByNameVersion.get(nameVersionKey(node.name, node.version));
      if (byNameVersion) {
        byNameVersion.add(node.id);
      } else {
        nodeIdsByNameVersion.set(nameVersionKey(node.name, node.version), new Set([node.id]));
      }
    };

    const ensureLocalNode = (depName: string, depRange: string): string => {
      const source = sourceFromRange(depRange) ?? "unknown";
      const key = `${source}:${depName}:${depRange}`;
      const existing = localNodeByRef.get(key);
      if (existing) {
        return existing;
      }
      const nodeId = `${source}:${encodeURIComponent(depName)}@${encodeURIComponent(depRange)}`;
      const node: PackageNode = {
        id: nodeId,
        name: depName,
        version: "0.0.0",
        location: depRange,
        source,
        flags: {}
      };
      graph.nodes.set(nodeId, node);
      registerNodeNameIndexes(node);
      localNodeByRef.set(key, nodeId);
      return nodeId;
    };

    const addEdge = (from: string, to: string, name: string, type: DepEdgeType): void => {
      const key = `${from}::${to}::${name}::${type}`;
      if (edgeKeys.has(key)) {
        return;
      }
      edgeKeys.add(key);
      edges.push({ from, to, name, type });
    };

    const resolveByDescriptorCandidates = (candidates: string[]): string[] => {
      const resolved: string[] = [];
      for (const candidate of candidates) {
        for (const nodeId of descriptorToNodeIds.get(candidate) ?? []) {
          resolved.push(nodeId);
        }
      }
      return uniq(resolved);
    };

    if (variant === "classic") {
      const parsed = parseClassicLockfile(raw) as { type: string; object?: Record<string, YarnClassicEntry> };
      if (parsed.type !== "success" || !parsed.object) {
        throw new Error(`Failed to parse yarn classic lockfile at ${detected.lockfilePath}`);
      }

      const lockEntries = parsed.object;
      for (const [entryKeyRaw, entry] of Object.entries(lockEntries)) {
        const selectors = splitKeyList(entryKeyRaw);
        if (selectors.length === 0) {
          continue;
        }
        const descriptor = parseDescriptor(selectors[0]);
        if (!descriptor) {
          continue;
        }

        const version = makeNodeVersion(toStringOrUndefined(entry.version));
        const nodeId = `yarn:${unquote(selectors[0])}=>${version}`;
        const detectedSource = sourceFromProtocol(entry.resolved ?? descriptor.range);
        const source = detectedSource === "unknown" ? "registry" : detectedSource;
        const node: PackageNode = {
          id: nodeId,
          name: descriptor.name,
          version,
          location: unquote(entryKeyRaw),
          purl: source === "registry" ? makePurl(descriptor.name, version) : undefined,
          source,
          integrity: toStringOrUndefined(entry.integrity),
          resolved: toStringOrUndefined(entry.resolved),
          flags: {}
        };
        graph.nodes.set(nodeId, node);
        registerNodeNameIndexes(node);

        for (const selector of selectors) {
          registerDescriptor(descriptorToNodeIds, selector, nodeId);
        }
      }

      for (const [entryKeyRaw, entry] of Object.entries(lockEntries)) {
        const selectors = splitKeyList(entryKeyRaw);
        if (selectors.length === 0) {
          continue;
        }
        const fromNodeIds = resolveByDescriptorCandidates([unquote(selectors[0])]);
        if (fromNodeIds.length === 0) {
          continue;
        }
        const fromNodeId = fromNodeIds[0];

        for (const [depName, depRange] of Object.entries(entry.dependencies ?? {})) {
          const toNodeIds = resolveByDescriptorCandidates(makeClassicSelectorCandidates(depName, depRange));
          for (const toNodeId of toNodeIds) {
            addEdge(fromNodeId, toNodeId, depName, "prod");
          }
        }
        for (const [depName, depRange] of Object.entries(entry.optionalDependencies ?? {})) {
          const toNodeIds = resolveByDescriptorCandidates(makeClassicSelectorCandidates(depName, depRange));
          for (const toNodeId of toNodeIds) {
            addEdge(fromNodeId, toNodeId, depName, "optional");
          }
        }
      }
    } else {
      const parsed = parseYaml(raw);
      if (!isRecord(parsed)) {
        throw new Error(`Failed to parse yarn berry lockfile at ${detected.lockfilePath}`);
      }

      const lockEntries = parsed as Record<string, YarnBerryEntry>;
      for (const [entryKeyRaw, entryRaw] of Object.entries(lockEntries)) {
        if (entryKeyRaw === "__metadata") {
          continue;
        }
        const entry = toDependencyRecord(entryRaw) as YarnBerryEntry;
        const descriptors = splitKeyList(entryKeyRaw).map((item) => unquote(item));
        if (descriptors.length === 0) {
          continue;
        }
        const descriptor = parseDescriptor(descriptors[0]);
        if (!descriptor) {
          continue;
        }

        const resolution = toStringOrUndefined(entry.resolution) ?? descriptors[0];
        const version = makeNodeVersion(toStringOrUndefined(entry.version));
        const detectedSource = sourceFromProtocol(resolution);
        const source = detectedSource === "unknown" ? "registry" : detectedSource;
        const nodeId = `yarn:${resolution}`;
        if (!graph.nodes.has(nodeId)) {
          const node: PackageNode = {
            id: nodeId,
            name: descriptor.name,
            version,
            location: descriptors[0],
            purl: source === "registry" ? makePurl(descriptor.name, version) : undefined,
            source,
            integrity: toStringOrUndefined(entry.checksum),
            resolved: resolution,
            meta: {
              linkType: toStringOrUndefined(entry.linkType)
            },
            flags: {}
          };
          graph.nodes.set(nodeId, node);
          registerNodeNameIndexes(node);
        }

        registerDescriptor(descriptorToNodeIds, resolution, nodeId);
        for (const depDescriptor of descriptors) {
          registerDescriptor(descriptorToNodeIds, depDescriptor, nodeId);
        }
      }

      for (const [entryKeyRaw, entryRaw] of Object.entries(lockEntries)) {
        if (entryKeyRaw === "__metadata") {
          continue;
        }
        const entry = toDependencyRecord(entryRaw) as YarnBerryEntry;
        const descriptors = splitKeyList(entryKeyRaw).map((item) => unquote(item));
        if (descriptors.length === 0) {
          continue;
        }

        const fromCandidates = resolveByDescriptorCandidates([descriptors[0]]);
        if (fromCandidates.length === 0) {
          continue;
        }
        const fromNodeId = fromCandidates[0];

        for (const [depName, depDescriptor] of Object.entries(entry.dependencies ?? {})) {
          const toNodeIds = resolveByDescriptorCandidates(makeBerryDescriptorCandidates(depName, depDescriptor));
          for (const toNodeId of toNodeIds) {
            addEdge(fromNodeId, toNodeId, depName, "prod");
          }
        }
        for (const [depName, depDescriptor] of Object.entries(entry.optionalDependencies ?? {})) {
          const toNodeIds = resolveByDescriptorCandidates(makeBerryDescriptorCandidates(depName, depDescriptor));
          for (const toNodeId of toNodeIds) {
            addEdge(fromNodeId, toNodeId, depName, "optional");
          }
        }
        for (const [depName, depDescriptor] of Object.entries(entry.peerDependencies ?? {})) {
          const toNodeIds = resolveByDescriptorCandidates(makeBerryDescriptorCandidates(depName, depDescriptor));
          for (const toNodeId of toNodeIds) {
            addEdge(fromNodeId, toNodeId, depName, "peer");
          }
        }
      }
    }

    const resolveFromImporterRange = (depName: string, depRange: string): string[] => {
      const localSource = sourceFromRange(depRange);
      if (localSource) {
        return [ensureLocalNode(depName, depRange)];
      }

      const candidates =
        variant === "classic"
          ? makeClassicSelectorCandidates(depName, depRange)
          : makeBerryDescriptorCandidates(depName, depRange);
      const byDescriptor = resolveByDescriptorCandidates(candidates);
      if (byDescriptor.length > 0) {
        return byDescriptor;
      }

      const byNameVersion = nodeIdsByNameVersion.get(nameVersionKey(depName, normalizeRange(depRange)));
      if (byNameVersion && byNameVersion.size > 0) {
        return Array.from(byNameVersion);
      }

      return Array.from(nodeIdsByName.get(depName) ?? []);
    };

    for (const importer of effectiveImporters) {
      const importerNodeId = graph.importers?.get(importer.key);
      if (!importerNodeId) {
        continue;
      }

      const addImporterEdges = (
        section: "dependencies" | "devDependencies" | "optionalDependencies" | "peerDependencies",
        values: Record<string, string>
      ): void => {
        for (const [depName, depRange] of Object.entries(values)) {
          const targets = resolveFromImporterRange(depName, depRange);
          const edgeType = depTypeForSection(section);
          for (const target of targets) {
            addEdge(importerNodeId, target, depName, edgeType);
          }
        }
      };

      addImporterEdges("dependencies", importer.dependencies);
      addImporterEdges("devDependencies", importer.devDependencies);
      addImporterEdges("optionalDependencies", importer.optionalDependencies);
      addImporterEdges("peerDependencies", importer.peerDependencies);
    }

    graph.edges = edges;
    graph.edgesByFrom = buildEdgesByFrom(edges);
    for (const edge of graph.edgesByFrom.get(graph.rootId) ?? []) {
      graph.rootDirectNodeIds.add(edge.to);
    }

    const sortedImporterContexts = importerContexts.sort((a, b) => b.absPath.length - a.absPath.length);
    const findImporterForFile = (filePath?: string): string => {
      if (!filePath) {
        return graph.rootId;
      }
      const absolute = path.resolve(filePath);
      for (const importer of sortedImporterContexts) {
        const rel = path.relative(importer.absPath, absolute);
        if (rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))) {
          return importer.nodeId;
        }
      }
      return graph.rootId;
    };

    const fallbackResolve = (packageName: string, issuerFile: string): string[] => {
      const importerNodeId = findImporterForFile(issuerFile);
      const direct = (graph.edgesByFrom.get(importerNodeId) ?? [])
        .filter((edge) => edge.name === packageName)
        .map((edge) => edge.to);
      if (direct.length > 0) {
        return uniq(direct);
      }
      return Array.from(nodeIdsByName.get(packageName) ?? []);
    };

    const pnpApi = variant === "berry" ? await loadPnpApi(rootDir) : undefined;
    const requireFromRoot = createRequire(path.join(rootDir, "package.json"));
    const hasNodeModules = await fs
      .stat(path.join(rootDir, "node_modules"))
      .then((stat) => stat.isDirectory())
      .catch(() => false);
    const fsResolve = (request: string, packageName: string, issuerFile: string): string[] => {
      if (!hasNodeModules) {
        return [];
      }

      const issuerDir = path.dirname(path.resolve(issuerFile));
      let resolvedPath: string | undefined;
      try {
        resolvedPath = requireFromRoot.resolve(request, { paths: [issuerDir] });
      } catch {
        return [];
      }
      if (!resolvedPath || !path.isAbsolute(resolvedPath)) {
        return [];
      }

      const packageRoot = packageRootFromNodeModulesPath(resolvedPath);
      const fromPathName = packageNameFromNodeModulesPath(resolvedPath) ?? packageName;
      if (!packageRoot || !fromPathName) {
        return [];
      }

      const manifest = readPackageManifestSync(packageRoot);
      const manifestName = typeof manifest?.name === "string" && manifest.name.length > 0 ? manifest.name : fromPathName;
      const manifestVersion =
        typeof manifest?.version === "string" && manifest.version.length > 0 ? manifest.version : undefined;

      if (manifestVersion) {
        const byNameVersion = nodeIdsByNameVersion.get(nameVersionKey(manifestName, manifestVersion));
        if (byNameVersion && byNameVersion.size > 0) {
          return Array.from(byNameVersion);
        }
      }
      return Array.from(nodeIdsByName.get(manifestName) ?? []);
    };

    const resolver: PackageResolver = {
      resolve: (request: string, issuerFile: string): string[] => {
        const packageName = normalizePackageSpecifier(request) ?? request;
        if (!packageName || packageName.startsWith(".") || packageName.startsWith("/") || packageName.startsWith("node:")) {
          return [];
        }

        if (pnpApi) {
          try {
            const resolvedPath = pnpApi.resolveRequest(request, issuerFile, { considerBuiltins: true });
            if (resolvedPath) {
              const locator = pnpApi.findPackageLocator(resolvedPath);
              if (locator?.name && locator.reference) {
                const locatorKey = `${locator.name}@${locator.reference}`;
                const mapped = resolveByDescriptorCandidates([locatorKey]);
                if (mapped.length > 0) {
                  return mapped;
                }
                const byLocatorName = Array.from(nodeIdsByName.get(locator.name) ?? []);
                if (byLocatorName.length > 0) {
                  return byLocatorName;
                }
              }
            }
          } catch {
            // fall through to lockfile graph resolver
          }
        }

        const fsCandidates = fsResolve(request, packageName, issuerFile);
        if (fsCandidates.length > 0) {
          return fsCandidates;
        }

        return fallbackResolve(packageName, issuerFile);
      }
    };

    graph.resolvePackageCandidates = (
      specifier: string,
      fromFile?: string,
      _importKind?: ImportKind,
      _conditions?: string[]
    ): string[] => resolver.resolve(specifier, fromFile ?? path.join(rootDir, "package.json"));

    graph.resolvePackage = (
      specifier: string,
      fromFile?: string,
      importKind?: ImportKind,
      conditions?: string[]
    ): string | undefined => {
      const candidates = graph.resolvePackageCandidates?.(specifier, fromFile, importKind, conditions) ?? [];
      return candidates[0];
    };

    const capabilities: ProviderCapabilities = {
      lockfileGraph: true,
      lockfileResolver: variant === "berry",
      fsResolver: hasNodeModules,
      pnpResolver: Boolean(pnpApi)
    };

    return {
      detect: detected,
      graph,
      capabilities,
      resolver
    };
  }
}
