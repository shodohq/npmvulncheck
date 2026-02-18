import path from "node:path";
import { DepGraph, Evidence, ReachabilityRecord, ReachabilityResult } from "../core/types";
import { discoverEntries } from "./entrypoints";
import { normalizePackageSpecifier, resolveLocalModule } from "./packageResolve";
import { parseImportsFromFile } from "./sourceParse";

type QueueItem = {
  nodeId: string;
  trace: string[];
};

function evidenceKey(evidence: Evidence): string {
  return [
    evidence.file,
    String(evidence.line),
    String(evidence.column),
    evidence.specifier,
    evidence.importText,
    evidence.resolvedPackageNodeId ?? "",
    evidence.viaNodeId ?? "",
    evidence.viaEdgeName ?? "",
    evidence.viaEdgeType ?? ""
  ].join("::");
}

function pushEvidence(map: Map<string, Evidence[]>, packageName: string, evidence: Evidence): void {
  const list = map.get(packageName);
  if (list) {
    list.push(evidence);
    return;
  }
  map.set(packageName, [evidence]);
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

async function collectSeedEvidences(
  projectRoot: string,
  entries: string[]
): Promise<{ packageEvidences: Map<string, Evidence[]>; hasUnknownImports: boolean }> {
  const queue = [...entries];
  const visited = new Set<string>();
  const packageEvidences = new Map<string, Evidence[]>();
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
      if (parsedImport.unknown || !parsedImport.specifier) {
        hasUnknownImports = true;
        continue;
      }

      const packageName = normalizePackageSpecifier(parsedImport.specifier);
      if (packageName) {
        pushEvidence(packageEvidences, packageName, {
          kind: "import",
          file: path.relative(projectRoot, file),
          line: parsedImport.line,
          column: parsedImport.column,
          specifier: parsedImport.specifier,
          importText: parsedImport.importText
        });
        continue;
      }

      const localTarget = resolveLocalModule(file, parsedImport.specifier);
      if (localTarget) {
        queue.push(localTarget);
      } else {
        hasUnknownImports = true;
      }
    }
  }

  return { packageEvidences, hasUnknownImports };
}

export async function computeReachability(
  projectRoot: string,
  graph: DepGraph,
  explicitEntries: string[]
): Promise<ReachabilityResult> {
  const entries = await discoverEntries(projectRoot, explicitEntries);
  const collected = await collectSeedEvidences(projectRoot, entries);
  const evidencesByPackage = collected.packageEvidences;
  let hasUnknownImports = collected.hasUnknownImports;

  const byNodeId = new Map<string, ReachabilityRecord>();
  const queue: QueueItem[] = [];
  const visited = new Set<string>();

  for (const [packageName, evidences] of evidencesByPackage.entries()) {
    const nodeId = graph.resolvePackage(packageName);
    if (!nodeId) {
      hasUnknownImports = true;
      continue;
    }

    const node = graph.nodes.get(nodeId);
    if (!node) {
      hasUnknownImports = true;
      continue;
    }

    const trace = [
      `${evidences[0].file}:${evidences[0].line}:${evidences[0].column}`,
      node.name
    ];

    const record = byNodeId.get(nodeId);
    if (record) {
      for (const evidence of evidences) {
        pushUniqueEvidence(record, {
          ...evidence,
          resolvedPackageNodeId: nodeId
        });
      }
      pushTrace(record, trace);
    } else {
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
    hasUnknownImports
  };
}
