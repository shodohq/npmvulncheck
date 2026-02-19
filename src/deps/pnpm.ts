import fs from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml } from "yaml";
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

type DependencyRecord = Record<string, unknown>;

type PnpmLockfile = {
  lockfileVersion?: string | number;
  importers?: Record<string, DependencyRecord>;
  packages?: Record<string, DependencyRecord>;
  snapshots?: Record<string, DependencyRecord>;
};

type ImporterContext = {
  key: string;
  nodeId: string;
  absPath: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toDependencyRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function toStringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function lockfileMajorVersion(lockfileVersion: string | number | undefined): number {
  if (typeof lockfileVersion === "number") {
    return Math.floor(lockfileVersion);
  }
  if (typeof lockfileVersion === "string") {
    const parsed = Number.parseInt(lockfileVersion, 10);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function normalizePnpmKey(key: string): string {
  return key.startsWith("/") ? key.slice(1) : key;
}

function stripPeerSuffix(version: string): string {
  let out = version;
  if (out.startsWith("npm:")) {
    out = out.slice(4);
  }
  const underscoreIndex = out.indexOf("_");
  if (underscoreIndex >= 0) {
    out = out.slice(0, underscoreIndex);
  }
  const parenIndex = out.indexOf("(");
  if (parenIndex >= 0) {
    out = out.slice(0, parenIndex);
  }
  return out;
}

function parseNameVersionFromAt(descriptor: string): { name: string; version: string } | undefined {
  const normalized = normalizePnpmKey(descriptor);
  const atIndex = normalized.lastIndexOf("@");
  if (atIndex <= 0) {
    return undefined;
  }
  const name = normalized.slice(0, atIndex);
  const version = stripPeerSuffix(normalized.slice(atIndex + 1));
  if (!name || !version) {
    return undefined;
  }
  return { name, version };
}

function parsePnpmV5PackageKey(key: string): { name: string; version: string } | undefined {
  const normalized = normalizePnpmKey(key);
  const segments = normalized.split("/");
  if (segments.length < 2) {
    return parseNameVersionFromAt(normalized);
  }

  if (normalized.startsWith("@")) {
    if (segments.length < 3) {
      return parseNameVersionFromAt(normalized);
    }
    const name = `${segments[0]}/${segments[1]}`;
    const version = stripPeerSuffix(segments.slice(2).join("/"));
    return name && version ? { name, version } : undefined;
  }

  const name = segments[0];
  const version = stripPeerSuffix(segments.slice(1).join("/"));
  return name && version ? { name, version } : undefined;
}

function sourceFromRef(ref: string): NodeSource | undefined {
  if (ref.startsWith("workspace:")) {
    return "workspace";
  }
  if (ref.startsWith("link:")) {
    return "link";
  }
  if (ref.startsWith("file:")) {
    return "file";
  }
  if (ref.startsWith("patch:")) {
    return "patch";
  }
  if (ref.startsWith("portal:")) {
    return "portal";
  }
  if (ref.startsWith("git+") || ref.startsWith("git:") || ref.startsWith("github:")) {
    return "git";
  }
  return undefined;
}

function makeNodeVersion(version: string | undefined): string {
  return version && version.length > 0 ? version : "0.0.0";
}

function parseDependencyRef(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  if (!isRecord(value)) {
    return undefined;
  }
  if (typeof value.version === "string") {
    return value.version;
  }
  if (typeof value.resolution === "string") {
    return value.resolution;
  }
  return undefined;
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

function uniqStrings(values: string[]): string[] {
  return Array.from(new Set(values));
}

function nameVersionKey(name: string, version: string): string {
  return `${name}@${version}`;
}

async function readRootOrImporterPackageJson(
  rootDir: string,
  importerKey: string
): Promise<{ name: string; version: string }> {
  const importerDir = importerKey === "." ? rootDir : path.resolve(rootDir, importerKey);
  const manifestPath = path.join(importerDir, "package.json");
  const raw = await fs.readFile(manifestPath, "utf8").catch(() => undefined);
  if (!raw) {
    return {
      name: importerKey === "." ? path.basename(rootDir) : path.basename(importerDir),
      version: "0.0.0"
    };
  }

  try {
    const manifest = JSON.parse(raw) as { name?: string; version?: string };
    return {
      name: typeof manifest.name === "string" && manifest.name.length > 0 ? manifest.name : path.basename(importerDir),
      version: typeof manifest.version === "string" && manifest.version.length > 0 ? manifest.version : "0.0.0"
    };
  } catch {
    return {
      name: importerKey === "." ? path.basename(rootDir) : path.basename(importerDir),
      version: "0.0.0"
    };
  }
}

export class PnpmLockfileProvider implements LockfileProvider {
  name: "pnpm" = "pnpm";

  async detect(rootDir: string): Promise<DetectResult | null> {
    const lockfilePath = path.join(rootDir, "pnpm-lock.yaml");
    const stat = await fs.stat(lockfilePath).catch(() => null);
    if (!stat?.isFile()) {
      return null;
    }

    const raw = await fs.readFile(lockfilePath, "utf8");
    let version: string | number | undefined;
    try {
      const parsed = parseYaml(raw) as PnpmLockfile;
      version = parsed.lockfileVersion;
    } catch {
      version = undefined;
    }

    return {
      manager: "pnpm",
      lockfilePath,
      details: {
        lockfileVersion: version
      }
    };
  }

  async load(rootDir: string): Promise<ProviderContext> {
    const detected = await this.detect(rootDir);
    if (!detected) {
      throw new Error(`pnpm lockfile not found in ${rootDir}`);
    }

    const raw = await fs.readFile(detected.lockfilePath, "utf8");
    const parsed = parseYaml(raw) as PnpmLockfile;
    const graph = makeEmptyDepGraph();
    graph.manager = "pnpm";

    const importers = toDependencyRecord(parsed.importers) as Record<string, DependencyRecord>;
    const packages = toDependencyRecord(parsed.packages) as Record<string, DependencyRecord>;
    const snapshots = toDependencyRecord(parsed.snapshots) as Record<string, DependencyRecord>;
    const isV9 = lockfileMajorVersion(parsed.lockfileVersion) >= 9 || Object.keys(snapshots).length > 0;

    const importerContexts: ImporterContext[] = [];
    const importerKeys = Object.keys(importers).sort((a, b) => a.localeCompare(b));
    for (const importerKey of importerKeys) {
      const importerNodeId = `importer:${importerKey}`;
      const manifest = await readRootOrImporterPackageJson(rootDir, importerKey);
      const importerNode: PackageNode = {
        id: importerNodeId,
        name: manifest.name,
        version: makeNodeVersion(manifest.version),
        location: importerKey,
        source: "workspace",
        flags: {}
      };
      graph.nodes.set(importerNodeId, importerNode);
      graph.importers?.set(importerKey, importerNodeId);
      importerContexts.push({
        key: importerKey,
        nodeId: importerNodeId,
        absPath: importerKey === "." ? rootDir : path.resolve(rootDir, importerKey)
      });
    }

    if (importerKeys.length === 0) {
      const fallbackRootId = "importer:.";
      graph.nodes.set(fallbackRootId, {
        id: fallbackRootId,
        name: path.basename(rootDir),
        version: "0.0.0",
        location: ".",
        source: "workspace",
        flags: {}
      });
      graph.importers?.set(".", fallbackRootId);
      importerContexts.push({ key: ".", nodeId: fallbackRootId, absPath: rootDir });
    }

    graph.rootId = graph.importers?.get(".") ?? importerContexts[0].nodeId;

    const localNodeByRef = new Map<string, string>();
    const nodeIdByInstanceKey = new Map<string, string>();
    const nodeIdsByName = new Map<string, Set<string>>();
    const nodeIdsByNameVersion = new Map<string, Set<string>>();
    const edgeKeys = new Set<string>();
    const edges: { from: string; to: string; name: string; type: DepEdgeType }[] = [];

    const registerNode = (instanceKey: string, node: PackageNode): void => {
      graph.nodes.set(node.id, node);
      nodeIdByInstanceKey.set(instanceKey, node.id);
      const byName = nodeIdsByName.get(node.name);
      if (byName) {
        byName.add(node.id);
      } else {
        nodeIdsByName.set(node.name, new Set([node.id]));
      }
      const byNameVersionKey = nameVersionKey(node.name, node.version);
      const byNameVersion = nodeIdsByNameVersion.get(byNameVersionKey);
      if (byNameVersion) {
        byNameVersion.add(node.id);
      } else {
        nodeIdsByNameVersion.set(byNameVersionKey, new Set([node.id]));
      }
    };

    const ensureLocalNode = (depName: string, ref: string): string => {
      const source = sourceFromRef(ref) ?? "unknown";
      const localKey = `${source}:${depName}:${ref}`;
      const existing = localNodeByRef.get(localKey);
      if (existing) {
        return existing;
      }
      const nodeId = `${source}:${encodeURIComponent(depName)}@${encodeURIComponent(ref)}`;
      const node: PackageNode = {
        id: nodeId,
        name: depName,
        version: "0.0.0",
        location: ref,
        source,
        flags: {}
      };
      graph.nodes.set(nodeId, node);
      localNodeByRef.set(localKey, nodeId);
      const byName = nodeIdsByName.get(depName);
      if (byName) {
        byName.add(nodeId);
      } else {
        nodeIdsByName.set(depName, new Set([nodeId]));
      }
      return nodeId;
    };

    const findByNameVersion = (name: string, rawVersion: string): string[] => {
      const version = stripPeerSuffix(rawVersion);
      if (!version) {
        return [];
      }
      return Array.from(nodeIdsByNameVersion.get(nameVersionKey(name, version)) ?? []);
    };

    if (isV9) {
      const packageInfoByBaseKey = new Map<string, DependencyRecord>();
      for (const [packageKey, packageEntry] of Object.entries(packages)) {
        packageInfoByBaseKey.set(normalizePnpmKey(packageKey), toDependencyRecord(packageEntry));
      }

      for (const [snapshotKeyRaw, snapshotEntryRaw] of Object.entries(snapshots)) {
        const snapshotKey = normalizePnpmKey(snapshotKeyRaw);
        const snapshotEntry = toDependencyRecord(snapshotEntryRaw);
        const baseKey = snapshotKey.split("(")[0] ?? snapshotKey;
        const parsedNameVersion = parseNameVersionFromAt(baseKey);
        if (!parsedNameVersion) {
          continue;
        }

        const packageInfo = packageInfoByBaseKey.get(baseKey) ?? {};
        const resolution = toDependencyRecord(packageInfo.resolution);
        const integrity = toStringOrUndefined(resolution.integrity);
        const tarball = toStringOrUndefined(resolution.tarball);

        const nodeId = `pnpm:${snapshotKey}`;
        const node: PackageNode = {
          id: nodeId,
          name: parsedNameVersion.name,
          version: makeNodeVersion(parsedNameVersion.version),
          location: snapshotKeyRaw,
          purl: makePurl(parsedNameVersion.name, makeNodeVersion(parsedNameVersion.version)),
          source: "registry",
          integrity,
          resolved: tarball,
          meta: {
            snapshotKey,
            baseKey
          },
          flags: {
            dev: Boolean(snapshotEntry.dev)
          }
        };
        registerNode(snapshotKey, node);
      }
    } else {
      for (const [packageKeyRaw, packageEntryRaw] of Object.entries(packages)) {
        const packageKey = normalizePnpmKey(packageKeyRaw);
        const packageEntry = toDependencyRecord(packageEntryRaw);
        const parsedNameVersion = parsePnpmV5PackageKey(packageKey);
        if (!parsedNameVersion) {
          continue;
        }
        const resolution = toDependencyRecord(packageEntry.resolution);
        const integrity = toStringOrUndefined(resolution.integrity);
        const tarball = toStringOrUndefined(resolution.tarball);
        const nodeId = `pnpm:${packageKey}`;
        const node: PackageNode = {
          id: nodeId,
          name: parsedNameVersion.name,
          version: makeNodeVersion(parsedNameVersion.version),
          location: packageKeyRaw,
          purl: makePurl(parsedNameVersion.name, makeNodeVersion(parsedNameVersion.version)),
          source: "registry",
          integrity,
          resolved: tarball,
          meta: {
            packageKey
          },
          flags: {
            dev: Boolean(packageEntry.dev),
            optional: Boolean(packageEntry.optional)
          }
        };
        registerNode(packageKey, node);
      }
    }

    const resolveV5Ref = (depName: string, ref: string): string[] => {
      const localSource = sourceFromRef(ref);
      if (localSource) {
        return [ensureLocalNode(depName, ref)];
      }

      const normalizedRef = normalizePnpmKey(ref.startsWith("npm:") ? ref.slice(4) : ref);
      const candidates = uniqStrings([
        normalizedRef,
        `${depName}/${normalizedRef}`,
        `${depName}@${normalizedRef}`
      ]);
      const hits: string[] = [];
      for (const candidate of candidates) {
        const hit = nodeIdByInstanceKey.get(candidate);
        if (hit) {
          hits.push(hit);
        }
      }

      if (hits.length > 0) {
        return uniqStrings(hits);
      }

      return findByNameVersion(depName, normalizedRef);
    };

    const resolveV9Ref = (depName: string, ref: string): string[] => {
      const localSource = sourceFromRef(ref);
      if (localSource) {
        return [ensureLocalNode(depName, ref)];
      }

      const normalizedRef = normalizePnpmKey(ref.startsWith("npm:") ? ref.slice(4) : ref);
      const candidates = uniqStrings([
        `${depName}@${normalizedRef}`,
        normalizedRef
      ]);
      const hits: string[] = [];
      for (const candidate of candidates) {
        const hit = nodeIdByInstanceKey.get(candidate);
        if (hit) {
          hits.push(hit);
        }
      }

      if (hits.length > 0) {
        return uniqStrings(hits);
      }

      return findByNameVersion(depName, normalizedRef);
    };

    const resolveRef = isV9 ? resolveV9Ref : resolveV5Ref;

    const addEdgesFromDependencyRecord = (
      from: string,
      sectionName: "dependencies" | "devDependencies" | "optionalDependencies" | "peerDependencies",
      deps: Record<string, unknown>
    ): void => {
      for (const [depName, depValue] of Object.entries(deps)) {
        const ref = parseDependencyRef(depValue);
        if (!ref) {
          continue;
        }
        const toNodeIds = resolveRef(depName, ref);
        const edgeType = depTypeForSection(sectionName);
        for (const to of toNodeIds) {
          const edgeKey = `${from}::${to}::${depName}::${edgeType}`;
          if (edgeKeys.has(edgeKey)) {
            continue;
          }
          edgeKeys.add(edgeKey);
          edges.push({
            from,
            to,
            name: depName,
            type: edgeType
          });
        }
      }
    };

    for (const importerKey of importerKeys) {
      const importerNodeId = graph.importers?.get(importerKey);
      if (!importerNodeId) {
        continue;
      }
      const importerEntry = toDependencyRecord(importers[importerKey]);
      addEdgesFromDependencyRecord(importerNodeId, "dependencies", toDependencyRecord(importerEntry.dependencies));
      addEdgesFromDependencyRecord(importerNodeId, "devDependencies", toDependencyRecord(importerEntry.devDependencies));
      addEdgesFromDependencyRecord(
        importerNodeId,
        "optionalDependencies",
        toDependencyRecord(importerEntry.optionalDependencies)
      );
      addEdgesFromDependencyRecord(importerNodeId, "peerDependencies", toDependencyRecord(importerEntry.peerDependencies));
    }

    if (isV9) {
      for (const [snapshotKeyRaw, snapshotEntryRaw] of Object.entries(snapshots)) {
        const snapshotNodeId = nodeIdByInstanceKey.get(normalizePnpmKey(snapshotKeyRaw));
        if (!snapshotNodeId) {
          continue;
        }
        const snapshotEntry = toDependencyRecord(snapshotEntryRaw);
        addEdgesFromDependencyRecord(snapshotNodeId, "dependencies", toDependencyRecord(snapshotEntry.dependencies));
        addEdgesFromDependencyRecord(
          snapshotNodeId,
          "optionalDependencies",
          toDependencyRecord(snapshotEntry.optionalDependencies)
        );
        addEdgesFromDependencyRecord(snapshotNodeId, "peerDependencies", toDependencyRecord(snapshotEntry.peerDependencies));
      }
    } else {
      for (const [packageKeyRaw, packageEntryRaw] of Object.entries(packages)) {
        const packageNodeId = nodeIdByInstanceKey.get(normalizePnpmKey(packageKeyRaw));
        if (!packageNodeId) {
          continue;
        }
        const packageEntry = toDependencyRecord(packageEntryRaw);
        addEdgesFromDependencyRecord(packageNodeId, "dependencies", toDependencyRecord(packageEntry.dependencies));
        addEdgesFromDependencyRecord(
          packageNodeId,
          "optionalDependencies",
          toDependencyRecord(packageEntry.optionalDependencies)
        );
        addEdgesFromDependencyRecord(packageNodeId, "peerDependencies", toDependencyRecord(packageEntry.peerDependencies));
      }
    }

    graph.edges = edges;
    graph.edgesByFrom = buildEdgesByFrom(edges);
    for (const edge of graph.edgesByFrom.get(graph.rootId) ?? []) {
      graph.rootDirectNodeIds.add(edge.to);
    }

    const sortedImporterContexts = importerContexts.sort((a, b) => b.absPath.length - a.absPath.length);
    const findImporterNodeId = (issuerFile?: string): string => {
      if (!issuerFile) {
        return graph.rootId;
      }
      const absolute = path.resolve(issuerFile);
      for (const importer of sortedImporterContexts) {
        const rel = path.relative(importer.absPath, absolute);
        if (rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))) {
          return importer.nodeId;
        }
      }
      return graph.rootId;
    };

    const resolver: PackageResolver = {
      resolve: (request: string, issuerFile: string): string[] => {
        const packageName = normalizePackageSpecifier(request) ?? request;
        if (!packageName || packageName.startsWith(".") || packageName.startsWith("/") || packageName.startsWith("node:")) {
          return [];
        }
        const importerNodeId = findImporterNodeId(issuerFile);
        const direct = (graph.edgesByFrom.get(importerNodeId) ?? [])
          .filter((edge) => edge.name === packageName)
          .map((edge) => edge.to);
        if (direct.length > 0) {
          return uniqStrings(direct);
        }
        return Array.from(nodeIdsByName.get(packageName) ?? []);
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
      lockfileResolver: true,
      fsResolver: false,
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
