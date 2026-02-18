import { computeReachability } from "../reachability/propagate";
import { includeNodeByDependencyType, passesSeverityThreshold } from "../policy/filters";
import { isIgnored, loadIgnorePolicy } from "../policy/ignore";
import { VulnerabilityProvider } from "../osv/provider";
import { DependencyGraphProvider } from "../deps/provider";
import {
  DepGraph,
  Finding,
  FixSuggestion,
  OsvBatchMatch,
  OsvVulnerability,
  PackageNode,
  Reachability,
  ReachabilityRecord,
  ScanMeta,
  ScanOptions,
  ScanResult
} from "./types";

function packageKey(name: string, version: string): string {
  return `${name}@${version}`;
}

function dedupeInventory(
  graph: DepGraph,
  includeDev: boolean,
  reachableNodeIds?: Set<string>
): {
  inventory: Array<{ name: string; version: string }>;
  packageToNodes: Map<string, PackageNode[]>;
} {
  const inventoryMap = new Map<string, { name: string; version: string }>();
  const packageToNodes = new Map<string, PackageNode[]>();

  for (const node of graph.nodes.values()) {
    if (node.id === graph.rootId) {
      continue;
    }
    if (reachableNodeIds && !reachableNodeIds.has(node.id)) {
      continue;
    }
    if (!includeNodeByDependencyType(node, includeDev)) {
      continue;
    }

    const key = packageKey(node.name, node.version);
    if (!inventoryMap.has(key)) {
      inventoryMap.set(key, { name: node.name, version: node.version });
    }

    const list = packageToNodes.get(key);
    if (list) {
      list.push(node);
    } else {
      packageToNodes.set(key, [node]);
    }
  }

  return { inventory: Array.from(inventoryMap.values()), packageToNodes };
}

function collectFixedVersion(vuln: OsvVulnerability, packageName: string): string | undefined {
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name !== packageName) {
      continue;
    }

    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) {
          return event.fixed;
        }
      }
    }
  }

  return undefined;
}

function toFixSuggestion(vuln: OsvVulnerability, packageName: string): FixSuggestion | undefined {
  const fixedVersion = collectFixedVersion(vuln, packageName);
  if (!fixedVersion) {
    return undefined;
  }
  return {
    fixedVersion
  };
}

function toReachability(
  nodeId: string,
  reachabilityResult: ReachabilityRecord | undefined,
  mode: ScanOptions["mode"]
): Reachability | undefined {
  if (mode !== "source") {
    return undefined;
  }

  if (!reachabilityResult) {
    return {
      reachable: false,
      level: "unknown",
      evidences: [],
      traces: [[`unreachable:${nodeId}`]]
    };
  }

  return {
    reachable: true,
    level: reachabilityResult.level,
    evidences: reachabilityResult.evidences,
    traces: reachabilityResult.traces
  };
}

function findDependencyPaths(graph: DepGraph, targetNodeId: string, maxPaths = 3): string[][] {
  if (targetNodeId === graph.rootId) {
    return [[graph.nodes.get(graph.rootId)?.name ?? "(root)"]];
  }

  const queue: string[][] = [[graph.rootId]];
  const output: string[][] = [];

  while (queue.length > 0 && output.length < maxPaths) {
    const nodePath = queue.shift();
    if (!nodePath) {
      continue;
    }

    const current = nodePath[nodePath.length - 1];
    if (current === targetNodeId) {
      output.push(
        nodePath.map((nodeId) => {
          const node = graph.nodes.get(nodeId);
          if (!node) {
            return nodeId;
          }
          return `${node.name}@${node.version}`;
        })
      );
      continue;
    }

    const edges = graph.edgesByFrom.get(current) ?? [];
    for (const edge of edges) {
      if (nodePath.includes(edge.to)) {
        continue;
      }
      queue.push([...nodePath, edge.to]);
    }
  }

  return output;
}

function mergeAffected(
  finding: Finding,
  node: PackageNode,
  paths: string[][],
  reachability: Reachability | undefined,
  fix: FixSuggestion | undefined
): void {
  const existing = finding.affected.find((entry) => entry.package.id === node.id);
  if (!existing) {
    finding.affected.push({ package: node, paths, reachability, fix });
    return;
  }

  for (const path of paths) {
    if (!existing.paths.some((currentPath) => currentPath.join("->") === path.join("->"))) {
      existing.paths.push(path);
    }
  }

  if (!existing.reachability && reachability) {
    existing.reachability = reachability;
  }

  if (!existing.fix && fix) {
    existing.fix = fix;
  }
}

function createFinding(vuln: OsvVulnerability): Finding {
  return {
    vulnId: vuln.id,
    aliases: vuln.aliases ?? [],
    summary: vuln.summary ?? "(no summary)",
    details: vuln.details,
    severity: vuln.severity,
    affected: [],
    references: (vuln.references ?? [])
      .filter((ref) => Boolean(ref.url))
      .map((ref) => ({
        type: ref.type ?? "WEB",
        url: ref.url as string
      })),
    modified: vuln.modified,
    published: vuln.published
  };
}

function calculateDbLastUpdated(findings: Finding[]): string | undefined {
  let best: string | undefined;
  for (const finding of findings) {
    if (!finding.modified) {
      continue;
    }
    if (!best || new Date(finding.modified) > new Date(best)) {
      best = finding.modified;
    }
  }
  return best;
}

function ensureRootNode(graph: DepGraph): void {
  if (graph.nodes.has(graph.rootId)) {
    return;
  }

  graph.nodes.set(graph.rootId, {
    id: graph.rootId,
    name: "(root)",
    version: "0.0.0",
    location: graph.rootId,
    flags: {}
  });
}

export async function runScan(
  opts: ScanOptions,
  depsProvider: DependencyGraphProvider,
  vulnProvider: VulnerabilityProvider,
  toolVersion: string
): Promise<ScanResult> {
  const graph = await depsProvider.load(
    opts.root,
    opts.mode === "installed" ? "installed" : "lockfile"
  );
  ensureRootNode(graph);

  const reachability =
    opts.mode === "source"
      ? await computeReachability(opts.root, graph, opts.entries)
      : undefined;

  let reachableNodeIds: Set<string> | undefined;
  if (opts.mode === "source") {
    const resolved = Array.from(reachability?.byNodeId.keys() ?? []);
    const hasUnknownImports = Boolean(reachability?.hasUnknownImports);
    const entriesScanned = reachability?.entriesScanned ?? 0;

    if (entriesScanned === 0 || hasUnknownImports) {
      // If source analysis has unresolved signals, fall back to full inventory to avoid false negatives.
      reachableNodeIds = undefined;
    } else if (resolved.length > 0) {
      reachableNodeIds = new Set(resolved);
    } else {
      // No package imports were observed and analysis was complete.
      reachableNodeIds = new Set();
    }
  }

  const { inventory, packageToNodes } = dedupeInventory(graph, opts.includeDev, reachableNodeIds);
  const matchesByPackage = await vulnProvider.queryPackages(inventory);
  const ignorePolicy = await loadIgnorePolicy(opts.root, opts.ignoreFile);

  const vulnDetailCache = new Map<string, OsvVulnerability>();
  const dependencyPathCache = new Map<string, string[][]>();
  const findingById = new Map<string, Finding>();

  for (const pkg of inventory) {
    const matches = matchesByPackage.get(packageKey(pkg.name, pkg.version)) ?? [];
    const nodes = packageToNodes.get(packageKey(pkg.name, pkg.version)) ?? [];

    for (const match of matches) {
      const detail = await getVulnDetail(vulnProvider, vulnDetailCache, match);
      if (isIgnored(detail.id, ignorePolicy)) {
        continue;
      }

      let finding = findingById.get(detail.id);
      if (!finding) {
        finding = createFinding(detail);
        findingById.set(detail.id, finding);
      }

      for (const node of nodes) {
        let paths = dependencyPathCache.get(node.id);
        if (!paths) {
          paths = findDependencyPaths(graph, node.id);
          dependencyPathCache.set(node.id, paths);
        }
        const reach = toReachability(node.id, reachability?.byNodeId.get(node.id), opts.mode);
        const fix = toFixSuggestion(detail, node.name);
        mergeAffected(finding, node, paths, reach, fix);
      }
    }
  }

  let findings = Array.from(findingById.values()).filter((finding) => passesSeverityThreshold(finding, opts.severityThreshold));

  findings = findings.sort((a, b) => a.vulnId.localeCompare(b.vulnId));

  const meta: ScanMeta = {
    tool: {
      name: "npmvulncheck",
      version: toolVersion
    },
    mode: opts.mode,
    format: opts.format,
    db: {
      name: vulnProvider.name,
      lastUpdated: calculateDbLastUpdated(findings)
    },
    timestamp: new Date().toISOString()
  };

  return {
    meta,
    findings,
    stats: {
      nodes: graph.nodes.size,
      edges: graph.edges.length,
      queriedPackages: inventory.length,
      vulnerabilities: findings.length
    }
  };
}

async function getVulnDetail(
  provider: VulnerabilityProvider,
  cache: Map<string, OsvVulnerability>,
  match: OsvBatchMatch
): Promise<OsvVulnerability> {
  const cacheKey = `${match.id}::${match.modified ?? ""}`;
  const fromCache = cache.get(cacheKey);
  if (fromCache) {
    return fromCache;
  }

  const detail = await provider.getVuln(match.id, match.modified);
  cache.set(cacheKey, detail);
  return detail;
}
