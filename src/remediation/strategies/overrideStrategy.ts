import { DependencyManager, Finding } from "../../core/types";
import { isReachableFinding, passesSeverityThreshold } from "../../policy/filters";
import { RemediationPlan, RemediationPolicy, RemediationScopeSelector } from "../types";

type OverrideStrategyInput = {
  manager: DependencyManager;
  findings: Finding[];
  rootDirectNodeIds: Set<string>;
  policy: RemediationPolicy;
};

type SemverParts = {
  major: number;
  minor: number;
  patch: number;
};

type Candidate = {
  pkg: string;
  scope: RemediationScopeSelector;
  fromVersions: Set<string>;
  toVersion: string;
  vulnIds: Set<string>;
  reachable: boolean;
};

type VulnStatus = {
  planned: boolean;
  blocked: boolean;
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
  if ([major, minor, patch].some((n) => Number.isNaN(n) || n < 0)) {
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

function isUpgradeAllowed(current: string, target: string, level: RemediationPolicy["upgradeLevel"]): boolean {
  const from = parseSemverParts(current);
  const to = parseSemverParts(target);
  if (from && to) {
    if (
      to.major < from.major ||
      (to.major === from.major && to.minor < from.minor) ||
      (to.major === from.major && to.minor === from.minor && to.patch < from.patch)
    ) {
      return false;
    }
  }

  if (level === "any") {
    return true;
  }

  if (!from || !to) {
    return true;
  }

  if (level === "major") {
    return true;
  }

  if (level === "minor") {
    return to.major === from.major;
  }

  return to.major === from.major && to.minor === from.minor;
}

function parsePathSegment(spec: string): { name: string; version?: string } {
  const idx = spec.lastIndexOf("@");
  if (idx <= 0 || idx === spec.length - 1) {
    return { name: spec };
  }
  return {
    name: spec.slice(0, idx),
    version: spec.slice(idx + 1)
  };
}

function inferScopedParents(paths: string[][]): Array<{ parent: string; parentVersion?: string }> {
  const out: Array<{ parent: string; parentVersion?: string }> = [];
  const seen = new Set<string>();

  for (const path of paths) {
    if (path.length < 3) {
      continue;
    }

    const parentSpec = path[path.length - 2];
    const parsed = parsePathSegment(parentSpec);
    if (!parsed.name || parsed.name === "(root)" || parsed.name === "root") {
      continue;
    }

    const key = `${parsed.name}@${parsed.version ?? ""}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);

    out.push({
      parent: parsed.name,
      parentVersion: parsed.version
    });
  }

  return out;
}

function scopeKey(scope: RemediationScopeSelector): string {
  if (scope === "global") {
    return "global";
  }
  return `${scope.parent}@${scope.parentVersion ?? ""}`;
}

function cloneScope(scope: RemediationScopeSelector): RemediationScopeSelector {
  if (scope === "global") {
    return "global";
  }
  return {
    parent: scope.parent,
    parentVersion: scope.parentVersion
  };
}

function shouldConsiderFinding(finding: Finding, policy: RemediationPolicy): boolean {
  if (!passesSeverityThreshold(finding, policy.severityThreshold)) {
    return false;
  }

  if (policy.onlyReachable && !policy.includeUnreachable && !isReachableFinding(finding)) {
    return false;
  }

  return true;
}

function collectOperationRisk(policy: RemediationPolicy, candidateCount: number): "low" | "medium" | "high" {
  if (candidateCount === 0) {
    return "high";
  }
  if (policy.scope === "by-parent") {
    return "low";
  }
  return "medium";
}

export function buildOverridePlan(input: OverrideStrategyInput): RemediationPlan {
  const { findings, rootDirectNodeIds, policy } = input;

  const candidateByKey = new Map<string, Candidate>();
  const vulnStatus = new Map<string, VulnStatus>();
  const directOnlyVulns = new Set<string>();

  for (const finding of findings) {
    if (!shouldConsiderFinding(finding, policy)) {
      continue;
    }

    vulnStatus.set(finding.vulnId, {
      planned: false,
      blocked: false
    });

    for (const affected of finding.affected) {
      if (!policy.includeDev && affected.package.flags.dev) {
        continue;
      }

      if (policy.onlyReachable && !policy.includeUnreachable && !affected.reachability?.reachable) {
        continue;
      }

      const direct = rootDirectNodeIds.has(affected.package.id);
      if (direct) {
        const status = vulnStatus.get(finding.vulnId);
        if (status) {
          status.blocked = true;
        }
        directOnlyVulns.add(finding.vulnId);
        continue;
      }

      const fixedVersion = affected.fix?.fixedVersion;
      if (!fixedVersion) {
        const status = vulnStatus.get(finding.vulnId);
        if (status) {
          status.blocked = true;
        }
        continue;
      }

      if (!isUpgradeAllowed(affected.package.version, fixedVersion, policy.upgradeLevel)) {
        const status = vulnStatus.get(finding.vulnId);
        if (status) {
          status.blocked = true;
        }
        continue;
      }

      const scopes: RemediationScopeSelector[] =
        policy.scope === "by-parent"
          ? (() => {
              const parents = inferScopedParents(affected.paths);
              if (parents.length === 0) {
                return ["global"];
              }
              return parents.map((parent) => ({
                parent: parent.parent,
                parentVersion: parent.parentVersion
              }));
            })()
          : ["global"];

      for (const scope of scopes) {
        const key = `${affected.package.name}::${scopeKey(scope)}`;

        const existing = candidateByKey.get(key);
        if (!existing) {
          candidateByKey.set(key, {
            pkg: affected.package.name,
            scope: cloneScope(scope),
            fromVersions: new Set([affected.package.version]),
            toVersion: fixedVersion,
            vulnIds: new Set([finding.vulnId]),
            reachable: Boolean(affected.reachability?.reachable)
          });
          continue;
        }

        existing.fromVersions.add(affected.package.version);
        if (compareVersion(fixedVersion, existing.toVersion) > 0) {
          existing.toVersion = fixedVersion;
        }
        existing.vulnIds.add(finding.vulnId);
        existing.reachable = existing.reachable || Boolean(affected.reachability?.reachable);
      }

      const status = vulnStatus.get(finding.vulnId);
      if (status) {
        status.planned = true;
      }
    }
  }

  const candidates = Array.from(candidateByKey.values()).sort((a, b) => {
    if (a.pkg !== b.pkg) {
      return a.pkg.localeCompare(b.pkg);
    }
    return scopeKey(a.scope).localeCompare(scopeKey(b.scope));
  });

  const changes = candidates.map((candidate) => {
    const fromVersions = Array.from(candidate.fromVersions).sort(compareVersion);
    const why = `Fixes ${Array.from(candidate.vulnIds).sort().join(", ")}${candidate.reachable ? " (reachable)" : ""}`;
    return {
      package: candidate.pkg,
      from: fromVersions.length > 0 ? fromVersions.join(",") : undefined,
      to: candidate.toVersion,
      scope: cloneScope(candidate.scope),
      why
    };
  });

  const operations: RemediationPlan["operations"] = [];
  if (changes.length > 0) {
    operations.push({
      id: "op-manifest-override-1",
      kind: "manifest-override",
      manager: input.manager,
      file: "package.json",
      changes
    });
  }

  const fixedVulnerabilities: string[] = [];
  const remainingVulnerabilities: string[] = [];
  for (const [vulnId, status] of vulnStatus.entries()) {
    if (status.planned && !status.blocked) {
      fixedVulnerabilities.push(vulnId);
    } else {
      remainingVulnerabilities.push(vulnId);
    }
  }

  fixedVulnerabilities.sort();
  remainingVulnerabilities.sort();

  const summaryLines: string[] = [];
  if (changes.length > 0) {
    summaryLines.push(`Generated ${changes.length} override change(s) for ${fixedVulnerabilities.length} vulnerability record(s).`);
  } else {
    summaryLines.push("No applicable transitive overrides were generated from current findings.");
  }
  if (directOnlyVulns.size > 0) {
    summaryLines.push(
      `${directOnlyVulns.size} vulnerability record(s) include direct dependencies and remain unresolved under override strategy.`
    );
  }

  const summary: RemediationPlan["summary"] = {
    reasonedTopChoices: [
      {
        opId:
          operations[0]?.id ??
          (directOnlyVulns.size > 0 ? "op-direct-upgrade-required" : "op-no-applicable-override"),
        rationale: summaryLines.join(" "),
        risk: collectOperationRisk(policy, changes.length)
      }
    ]
  };

  return {
    tool: "npmvulncheck",
    strategy: "override",
    packageManager: input.manager,
    target: {
      onlyReachable: policy.onlyReachable,
      includeDev: policy.includeDev,
      severityThreshold: policy.severityThreshold
    },
    operations,
    fixes: {
      fixedVulnerabilities,
      remainingVulnerabilities
    },
    summary
  };
}
