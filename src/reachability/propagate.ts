import path from "node:path";
import { DepGraph, Evidence, ReachabilityRecord, ReachabilityResult } from "../core/types";
import { discoverEntries } from "./entrypoints";
import { normalizePackageSpecifier, resolveLocalModule } from "./packageResolve";
import { parseImportsFromFile } from "./sourceParse";

type QueueItem = {
  nodeId: string;
  trace: string[];
};

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

async function collectSeedEvidences(
  projectRoot: string,
  entries: string[]
): Promise<Map<string, Evidence[]>> {
  const queue = [...entries];
  const visited = new Set<string>();
  const packageEvidences = new Map<string, Evidence[]>();

  while (queue.length > 0) {
    const file = queue.shift();
    if (!file || visited.has(file)) {
      continue;
    }
    visited.add(file);

    const imports = await parseImportsFromFile(file).catch(() => []);
    for (const parsedImport of imports) {
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
      }
    }
  }

  return packageEvidences;
}

export async function computeReachability(
  projectRoot: string,
  graph: DepGraph,
  explicitEntries: string[]
): Promise<ReachabilityResult> {
  const entries = await discoverEntries(projectRoot, explicitEntries);
  const evidencesByPackage = await collectSeedEvidences(projectRoot, entries);

  const byNodeId = new Map<string, ReachabilityRecord>();
  const queue: QueueItem[] = [];
  const visited = new Set<string>();

  for (const [packageName, evidences] of evidencesByPackage.entries()) {
    const nodeId = graph.resolvePackage(packageName);
    if (!nodeId) {
      continue;
    }

    const node = graph.nodes.get(nodeId);
    if (!node) {
      continue;
    }

    const trace = [
      `${evidences[0].file}:${evidences[0].line}:${evidences[0].column}`,
      node.name
    ];

    const record = byNodeId.get(nodeId);
    if (record) {
      record.evidences.push(...evidences);
      pushTrace(record, trace);
    } else {
      byNodeId.set(nodeId, {
        level: "import",
        evidences: [...evidences],
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
      const existing = byNodeId.get(child.id);
      if (!existing) {
        byNodeId.set(child.id, {
          level: "transitive",
          evidences: [],
          traces: [trace]
        });

        if (!visited.has(child.id)) {
          queue.push({ nodeId: child.id, trace });
        }
        continue;
      }

      pushTrace(existing, trace);

      if (!visited.has(child.id)) {
        queue.push({ nodeId: child.id, trace });
      }
    }
  }

  return { byNodeId };
}
