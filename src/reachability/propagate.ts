import path from "node:path";
import { builtinModules } from "node:module";
import { DepGraph, Evidence, ImportKind, ReachabilityRecord, ReachabilityResult, UnresolvedImport } from "../core/types";
import { discoverEntries } from "./entrypoints";
import { normalizePackageSpecifier, resolveLocalModule } from "./packageResolve";
import { createModuleResolver, isNodeModulesPath, isSourceCodePath } from "./moduleResolver";
import { parseImportsFromFile } from "./sourceParse";

type QueueItem = {
  nodeId: string;
  trace: string[];
};

export type ReachabilityOptions = {
  conditions?: string[];
  includeTypeImports?: boolean;
  explainResolve?: boolean;
};

const BUILTIN_MODULES = new Set(
  builtinModules.flatMap((name) => (name.startsWith("node:") ? [name, name.slice(5)] : [name, `node:${name}`]))
);

function evidenceKey(evidence: Evidence): string {
  return [
    evidence.file,
    String(evidence.line),
    String(evidence.column),
    evidence.importKind ?? "",
    evidence.specifier,
    evidence.importText,
    evidence.resolvedPackageNodeId ?? "",
    evidence.viaNodeId ?? "",
    evidence.viaEdgeName ?? "",
    evidence.viaEdgeType ?? ""
  ].join("::");
}

function pushEvidence(map: Map<string, Evidence[]>, nodeId: string, evidence: Evidence): void {
  const list = map.get(nodeId);
  if (list) {
    list.push(evidence);
    return;
  }
  map.set(nodeId, [evidence]);
}

function pushTrace(record: ReachabilityRecord, trace: string[]): void {
  if (record.traces.length >= 5) {
    return;
  }
  if (!record.traces.some((existing) => existing.join("->") === trace.join("->"))) {
    record.traces.push(trace);
  }
}

function pushUniqueEvidence(record: ReachabilityRecord, evidence: Evidence): void {
  if (!record.evidences.some((current) => evidenceKey(current) === evidenceKey(evidence))) {
    record.evidences.push(evidence);
  }
}

function defaultConditions(importKind: ImportKind): string[] {
  if (importKind === "cjs-require") {
    return ["node", "require", "default"];
  }
  return ["node", "import", "default"];
}

function resolvePackageNodeId(
  graph: DepGraph,
  specifier: string,
  fromFile: string,
  importKind: ImportKind,
  conditions: string[]
): string | undefined {
  const direct = graph.resolvePackage(specifier, fromFile, importKind, conditions);
  if (direct === null) {
    return undefined;
  }
  if (direct) {
    return direct;
  }

  const packageName = normalizePackageSpecifier(specifier);
  if (!packageName || packageName === specifier) {
    return undefined;
  }

  const normalized = graph.resolvePackage(packageName, fromFile, importKind, conditions);
  return normalized ?? undefined;
}

async function collectSeedEvidences(
  projectRoot: string,
  graph: DepGraph,
  entries: string[],
  options: Required<ReachabilityOptions>
): Promise<{ nodeEvidences: Map<string, Evidence[]>; hasUnknownImports: boolean; unresolvedImports: UnresolvedImport[] }> {
  const moduleResolver = createModuleResolver(projectRoot);
  const queue = entries.map((entry) => path.resolve(entry));
  const visited = new Set<string>();
  const nodeEvidences = new Map<string, Evidence[]>();
  const unresolvedImports: UnresolvedImport[] = [];
  let hasUnknownImports = false;

  while (queue.length > 0) {
    const file = queue.shift();
    if (!file || visited.has(file)) {
      continue;
    }
    visited.add(file);

    let imports = [] as Awaited<ReturnType<typeof parseImportsFromFile>>;
    try {
      imports = await parseImportsFromFile(file);
    } catch {
      hasUnknownImports = true;
      continue;
    }

    for (const parsedImport of imports) {
      if (parsedImport.typeOnly && !options.includeTypeImports) {
        continue;
      }

      if (parsedImport.unknown || !parsedImport.specifier) {
        hasUnknownImports = true;
        if (options.explainResolve) {
          unresolvedImports.push({
            file: path.relative(projectRoot, file),
            line: parsedImport.line,
            column: parsedImport.column,
            importKind: parsedImport.kind,
            specifier: parsedImport.specifier ?? "(dynamic)",
            importText: parsedImport.importText,
            candidates: []
          });
        }
        continue;
      }

      const specifier = parsedImport.specifier;
      const conditions = options.conditions.length > 0 ? options.conditions : defaultConditions(parsedImport.kind);

      if (BUILTIN_MODULES.has(specifier)) {
        continue;
      }

      const resolvedByTs = moduleResolver.resolveToFile(specifier, file, parsedImport.kind, conditions);
      const localTarget =
        resolvedByTs.filePath && isSourceCodePath(resolvedByTs.filePath) && !isNodeModulesPath(resolvedByTs.filePath)
          ? resolvedByTs.filePath
          : resolveLocalModule(file, specifier);
      if (localTarget) {
        queue.push(path.resolve(localTarget));
        continue;
      }

      const internalNodeId =
        specifier.startsWith("#") && graph.resolveInternalImport
          ? graph.resolveInternalImport(specifier, file, parsedImport.kind, conditions)
          : undefined;
      if (internalNodeId) {
        pushEvidence(nodeEvidences, internalNodeId, {
          kind: "import",
          importKind: parsedImport.kind,
          file: path.relative(projectRoot, file),
          line: parsedImport.line,
          column: parsedImport.column,
          specifier,
          importText: parsedImport.importText
        });
        continue;
      }

      const packageNodeId = resolvePackageNodeId(graph, specifier, file, parsedImport.kind, conditions);
      if (packageNodeId) {
        pushEvidence(nodeEvidences, packageNodeId, {
          kind: "import",
          importKind: parsedImport.kind,
          file: path.relative(projectRoot, file),
          line: parsedImport.line,
          column: parsedImport.column,
          specifier,
          importText: parsedImport.importText
        });
        continue;
      }

      if (specifier.startsWith(".") || specifier.startsWith("/") || specifier.startsWith("#") || normalizePackageSpecifier(specifier)) {
        hasUnknownImports = true;
        if (options.explainResolve) {
          unresolvedImports.push({
            file: path.relative(projectRoot, file),
            line: parsedImport.line,
            column: parsedImport.column,
            importKind: parsedImport.kind,
            specifier,
            importText: parsedImport.importText,
            candidates: resolvedByTs.failedLookupLocations
          });
        }
      }
    }
  }

  return { nodeEvidences, hasUnknownImports, unresolvedImports };
}

export async function computeReachability(
  projectRoot: string,
  graph: DepGraph,
  explicitEntries: string[],
  options: ReachabilityOptions = {}
): Promise<ReachabilityResult> {
  const opts: Required<ReachabilityOptions> = {
    conditions: options.conditions ?? [],
    includeTypeImports: options.includeTypeImports ?? false,
    explainResolve: options.explainResolve ?? false
  };

  const entries = await discoverEntries(projectRoot, explicitEntries);
  const collected = await collectSeedEvidences(projectRoot, graph, entries, opts);
  let hasUnknownImports = collected.hasUnknownImports;

  const byNodeId = new Map<string, ReachabilityRecord>();
  const queue: QueueItem[] = [];
  const visited = new Set<string>();

  for (const [nodeId, evidences] of collected.nodeEvidences.entries()) {
    const node = graph.nodes.get(nodeId);
    if (!node) {
      hasUnknownImports = true;
      continue;
    }

    const trace = [`${evidences[0].file}:${evidences[0].line}:${evidences[0].column}`, node.name];
    const existing = byNodeId.get(nodeId);
    if (existing) {
      for (const evidence of evidences) {
        pushUniqueEvidence(existing, {
          ...evidence,
          resolvedPackageNodeId: nodeId
        });
      }
      pushTrace(existing, trace);
      continue;
    }

    byNodeId.set(nodeId, {
      level: "import",
      evidences: evidences.map((evidence) => ({
        ...evidence,
        resolvedPackageNodeId: nodeId
      })),
      traces: [trace]
    });
    queue.push({ nodeId, trace });
  }

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) {
      continue;
    }

    if (!visited.has(current.nodeId)) {
      visited.add(current.nodeId);
    }

    const edges = graph.edgesByFrom.get(current.nodeId) ?? [];
    for (const edge of edges) {
      const child = graph.nodes.get(edge.to);
      if (!child) {
        continue;
      }

      const trace = [...current.trace, child.name];
      const parentRecord = byNodeId.get(current.nodeId);
      const parentEvidence = parentRecord?.evidences[0];
      const viaEvidence: Evidence = {
        kind: "import",
        importKind: parentEvidence?.importKind,
        file: parentEvidence?.file ?? "(dependency-graph)",
        line: parentEvidence?.line ?? 1,
        column: parentEvidence?.column ?? 1,
        specifier: edge.name,
        importText: parentEvidence?.importText ?? `${current.nodeId} -> ${edge.name}`,
        resolvedPackageNodeId: child.id,
        viaNodeId: current.nodeId,
        viaEdgeName: edge.name,
        viaEdgeType: edge.type
      };

      const existing = byNodeId.get(child.id);
      if (!existing) {
        byNodeId.set(child.id, {
          level: "transitive",
          evidences: [viaEvidence],
          traces: [trace]
        });

        if (!visited.has(child.id)) {
          queue.push({ nodeId: child.id, trace });
        }
        continue;
      }

      pushUniqueEvidence(existing, viaEvidence);
      pushTrace(existing, trace);

      if (!visited.has(child.id)) {
        queue.push({ nodeId: child.id, trace });
      }
    }
  }

  return {
    byNodeId,
    entriesScanned: entries.length,
    hasUnknownImports,
    unresolvedImports: collected.unresolvedImports
  };
}
