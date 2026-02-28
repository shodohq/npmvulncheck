import { computeReachability } from "../reachability/propagate";
import { includeNodeByDependencyType, passesSeverityThreshold } from "../policy/filters";
import { isIgnored, loadIgnorePolicy } from "../policy/ignore";
import { compareFindingsByPriority, evaluateFindingPriority } from "../policy/priority";
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
  includeDev: boolean
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
    if (node.source && node.source !== "registry") {
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

type SemverParts = {
  major: number;
  minor: number;
  patch: number;
};

type FixResolutionContext = {
  allowRegistryLookup: boolean;
  vulnProvider: VulnerabilityProvider;
  versionVulnIdsCache: Map<string, Promise<Set<string> | undefined>>;
  registryVersionsCache: Map<string, Promise<string[] | undefined>>;
};

function parseSemverParts(version: string): SemverParts | undefined {
  const normalized = version.trim().replace(/^v/i, "").split("-")[0].split("+")[0];
  const match = normalized.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) {
    return undefined;
  }

  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if ([major, minor, patch].some((value) => Number.isNaN(value) || value < 0)) {
    return undefined;
  }

  return { major, minor, patch };
}

function compareVersion(a: string, b: string): number {
  const parsedA = parseSemverParts(a);
  const parsedB = parseSemverParts(b);

  if (parsedA && parsedB) {
    if (parsedA.major !== parsedB.major) {
      return parsedA.major - parsedB.major;
    }
    if (parsedA.minor !== parsedB.minor) {
      return parsedA.minor - parsedB.minor;
    }
    return parsedA.patch - parsedB.patch;
  }

  return a.localeCompare(b);
}

function isSameOrNewerVersion(candidate: string, current: string): boolean {
  const parsedCandidate = parseSemverParts(candidate);
  const parsedCurrent = parseSemverParts(current);

  if (parsedCandidate && parsedCurrent) {
    return compareVersion(candidate, current) >= 0;
  }

  return candidate !== current;
}

function collectFixedVersions(vuln: OsvVulnerability, packageName: string): string[] {
  const versions = new Set<string>();

  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name !== packageName) {
      continue;
    }

    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) {
          versions.add(event.fixed.trim());
        }
      }
    }
  }

  return Array.from(versions).filter(Boolean).sort(compareVersion);
}

async function getVulnIdsByVersion(
  context: FixResolutionContext,
  packageName: string,
  version: string
): Promise<Set<string> | undefined> {
  const key = packageKey(packageName, version);
  const fromCache = context.versionVulnIdsCache.get(key);
  if (fromCache) {
    return fromCache;
  }

  const query = (async () => {
    const result = await context.vulnProvider.queryPackages([{ name: packageName, version }]).catch(() => undefined);
    if (!result) {
      return undefined;
    }
    const matches = result.get(key) ?? [];
    return new Set(matches.map((match) => match.id));
  })();

  context.versionVulnIdsCache.set(key, query);
  return query;
}

async function pickVerifiedCandidate(
  context: FixResolutionContext,
  vulnId: string,
  packageName: string,
  candidates: string[]
): Promise<{ version?: string; verified: boolean }> {
  let verified = false;

  for (const candidate of candidates) {
    const vulnIds = await getVulnIdsByVersion(context, packageName, candidate);
    if (!vulnIds) {
      continue;
    }
    verified = true;

    if (!vulnIds.has(vulnId)) {
      return {
        version: candidate,
        verified
      };
    }
  }

  return {
    verified
  };
}

async function listRegistryVersions(
  context: FixResolutionContext,
  packageName: string
): Promise<string[] | undefined> {
  if (!context.allowRegistryLookup || !context.vulnProvider.listPackageVersions) {
    return undefined;
  }

  const fromCache = context.registryVersionsCache.get(packageName);
  if (fromCache) {
    return fromCache;
  }

  const loaded = context.vulnProvider
    .listPackageVersions(packageName)
    .then((versions) => {
      if (!versions) {
        return undefined;
      }
      const deduped = Array.from(new Set(versions.map((value) => value.trim()).filter(Boolean)));
      deduped.sort(compareVersion);
      return deduped;
    })
    .catch(() => undefined);

  context.registryVersionsCache.set(packageName, loaded);
  return loaded;
}

async function toFixSuggestion(
  vuln: OsvVulnerability,
  packageName: string,
  currentVersion: string,
  context: FixResolutionContext
): Promise<FixSuggestion | undefined> {
  const fixedCandidates = collectFixedVersions(vuln, packageName).filter((version) =>
    isSameOrNewerVersion(version, currentVersion)
  );
  let fixedCandidatesChecked = false;

  if (fixedCandidates.length > 0) {
    const selected = await pickVerifiedCandidate(context, vuln.id, packageName, fixedCandidates);
    fixedCandidatesChecked = selected.verified;

    if (selected.version) {
      return {
        fixedVersion: selected.version
      };
    }
  }

  if (fixedCandidates.length === 0 || fixedCandidatesChecked) {
    const registryVersions = await listRegistryVersions(context, packageName);
    if (registryVersions && registryVersions.length > 0) {
      const candidates = registryVersions.filter((version) => isSameOrNewerVersion(version, currentVersion));
      const selected = await pickVerifiedCandidate(context, vuln.id, packageName, candidates);
      if (selected.version) {
        return {
          fixedVersion: selected.version
        };
      }
    }
  }

  if (fixedCandidates.length > 0 && !fixedCandidatesChecked) {
    return {
      fixedVersion: fixedCandidates[0]
    };
  }

  return undefined;
}

type FixSuggestionCacheKey = string;

function buildFixSuggestionCacheKey(vulnId: string, packageName: string, packageVersion: string): FixSuggestionCacheKey {
  return `${vulnId}::${packageName}::${packageVersion}`;
}

async function getFixSuggestion(
  cache: Map<FixSuggestionCacheKey, Promise<FixSuggestion | undefined>>,
  vuln: OsvVulnerability,
  packageName: string,
  packageVersion: string,
  context: FixResolutionContext
): Promise<FixSuggestion | undefined> {
  const cacheKey = buildFixSuggestionCacheKey(vuln.id, packageName, packageVersion);
  const fromCache = cache.get(cacheKey);
  if (fromCache) {
    return fromCache;
  }

  const resolved = toFixSuggestion(vuln, packageName, packageVersion, context);
  cache.set(cacheKey, resolved);
  return resolved;
}

function toReachability(
  nodeId: string,
  reachabilityResult: ReachabilityRecord | undefined,
  mode: ScanOptions["mode"],
  hasCompleteSourceCoverage: boolean
): Reachability | undefined {
  if (mode !== "source") {
    return undefined;
  }

  if (!reachabilityResult) {
    return {
      reachable: false,
      level: hasCompleteSourceCoverage ? "transitive" : "unknown",
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
      ? await computeReachability(opts.root, graph, opts.entries, {
          conditions: opts.conditions,
          includeTypeImports: opts.includeTypeImports,
          explainResolve: Boolean(opts.explainResolve)
        })
      : undefined;

  const hasCompleteSourceCoverage =
    opts.mode === "source" &&
    (reachability?.entriesScanned ?? 0) > 0 &&
    !Boolean(reachability?.hasUnknownImports);

  const { inventory, packageToNodes } = dedupeInventory(graph, opts.includeDev);
  const matchesByPackage = await vulnProvider.queryPackages(inventory);
  const ignorePolicy = await loadIgnorePolicy(opts.root, opts.ignoreFile);

  const vulnDetailCache = new Map<string, OsvVulnerability>();
  const dependencyPathCache = new Map<string, string[][]>();
  const findingById = new Map<string, Finding>();
  const fixSuggestionCache = new Map<FixSuggestionCacheKey, Promise<FixSuggestion | undefined>>();
  const fixResolutionContext: FixResolutionContext = {
    allowRegistryLookup: !opts.offline,
    vulnProvider,
    versionVulnIdsCache: new Map<string, Promise<Set<string> | undefined>>(),
    registryVersionsCache: new Map<string, Promise<string[] | undefined>>()
  };

  for (const pkg of inventory) {
    const matches = matchesByPackage.get(packageKey(pkg.name, pkg.version)) ?? [];
    const nodes = packageToNodes.get(packageKey(pkg.name, pkg.version)) ?? [];

    for (const match of matches) {
      const detail = await getVulnDetail(vulnProvider, vulnDetailCache, match);
      if (isIgnored(detail.id, ignorePolicy)) {
        continue;
      }
      const fix = await getFixSuggestion(
        fixSuggestionCache,
        detail,
        pkg.name,
        pkg.version,
        fixResolutionContext
      );

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
        const reach = toReachability(node.id, reachability?.byNodeId.get(node.id), opts.mode, hasCompleteSourceCoverage);
        mergeAffected(finding, node, paths, reach, fix);
      }
    }
  }

  let findings = Array.from(findingById.values()).filter((finding) => passesSeverityThreshold(finding, opts.severityThreshold));

  for (const finding of findings) {
    finding.priority = evaluateFindingPriority(finding, opts.mode);
  }

  findings = findings.sort(compareFindingsByPriority);

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
    sourceAnalysis:
      opts.mode === "source" && opts.explainResolve
        ? {
            unresolvedImports: reachability?.unresolvedImports ?? []
          }
        : undefined,
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
