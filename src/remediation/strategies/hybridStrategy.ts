import { DependencyManager, Finding } from "../../core/types";
import { isReachableFinding, passesSeverityThreshold } from "../../policy/filters";
import { RemediationPlan, RemediationPolicy, RemediationScopeSelector } from "../types";

type HybridStrategyInput = {
  manager: DependencyManager;
  findings: Finding[];
  rootDirectNodeIds: Set<string>;
  policy: RemediationPolicy;
  includeDirect: boolean;
  includeTransitive: boolean;
  strategyLabel: "direct" | "auto";
};

type SemverParts = {
  major: number;
  minor: number;
  patch: number;
};

type VulnStatus = {
  covered: boolean;
  unresolved: boolean;
};

type DirectCandidate = {
  pkg: string;
  depField: "dependencies" | "devDependencies" | "optionalDependencies";
  fromVersions: Set<string>;
  toVersion: string;
  vulnIds: Set<string>;
  reachable: boolean;
};

type OverrideCandidate = {
  pkg: string;
  scope: RemediationScopeSelector;
  fromVersions: Set<string>;
  toVersion: string;
  vulnIds: Set<string>;
  reachable: boolean;
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

function directDependencyField(flags: { dev?: boolean; optional?: boolean }): "dependencies" | "devDependencies" | "optionalDependencies" {
  if (flags.optional) {
    return "optionalDependencies";
  }
  if (flags.dev) {
    return "devDependencies";
  }
  return "dependencies";
}

function collectOperationRisk(
  policy: RemediationPolicy,
  directChangeCount: number,
  overrideChangeCount: number
): "low" | "medium" | "high" {
  if (directChangeCount + overrideChangeCount === 0) {
    return "high";
  }
  if (overrideChangeCount > 0 && policy.scope === "global") {
    return "medium";
  }
  return "low";
}

export function buildHybridPlan(input: HybridStrategyInput): RemediationPlan {
  const { findings, rootDirectNodeIds, policy, includeDirect, includeTransitive } = input;

  const directCandidateByKey = new Map<string, DirectCandidate>();
  const overrideCandidateByKey = new Map<string, OverrideCandidate>();
  const vulnStatus = new Map<string, VulnStatus>();

  for (const finding of findings) {
    if (!shouldConsiderFinding(finding, policy)) {
      continue;
    }

    const findingStatus: VulnStatus = {
      covered: false,
      unresolved: false
    };
    let consideredAffected = false;

    for (const affected of finding.affected) {
      if (!policy.includeDev && affected.package.flags.dev) {
        continue;
      }

      if (policy.onlyReachable && !policy.includeUnreachable && !affected.reachability?.reachable) {
        continue;
      }
      consideredAffected = true;

      const fixedVersion = affected.fix?.fixedVersion;
      const canUseVersion =
        Boolean(fixedVersion) &&
        isUpgradeAllowed(affected.package.version, fixedVersion as string, policy.upgradeLevel);
      const direct = rootDirectNodeIds.has(affected.package.id);

      let covered = false;
      if (direct && includeDirect && canUseVersion) {
        const depField = directDependencyField(affected.package.flags);
        const key = `${depField}::${affected.package.name}`;
        const existing = directCandidateByKey.get(key);

        if (!existing) {
          directCandidateByKey.set(key, {
            pkg: affected.package.name,
            depField,
            fromVersions: new Set([affected.package.version]),
            toVersion: fixedVersion as string,
            vulnIds: new Set([finding.vulnId]),
            reachable: Boolean(affected.reachability?.reachable)
          });
        } else {
          existing.fromVersions.add(affected.package.version);
          if (compareVersion(fixedVersion as string, existing.toVersion) > 0) {
            existing.toVersion = fixedVersion as string;
          }
          existing.vulnIds.add(finding.vulnId);
          existing.reachable = existing.reachable || Boolean(affected.reachability?.reachable);
        }
        covered = true;
      }

      if (!direct && includeTransitive && canUseVersion) {
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
          const existing = overrideCandidateByKey.get(key);
          if (!existing) {
            overrideCandidateByKey.set(key, {
              pkg: affected.package.name,
              scope: cloneScope(scope),
              fromVersions: new Set([affected.package.version]),
              toVersion: fixedVersion as string,
              vulnIds: new Set([finding.vulnId]),
              reachable: Boolean(affected.reachability?.reachable)
            });
            continue;
          }

          existing.fromVersions.add(affected.package.version);
          if (compareVersion(fixedVersion as string, existing.toVersion) > 0) {
            existing.toVersion = fixedVersion as string;
          }
          existing.vulnIds.add(finding.vulnId);
          existing.reachable = existing.reachable || Boolean(affected.reachability?.reachable);
        }
        covered = true;
      }

      if (covered) {
        findingStatus.covered = true;
      } else {
        findingStatus.unresolved = true;
      }
    }

    if (consideredAffected) {
      vulnStatus.set(finding.vulnId, findingStatus);
    }
  }

  const directCandidates = Array.from(directCandidateByKey.values()).sort((a, b) => {
    if (a.depField !== b.depField) {
      return a.depField.localeCompare(b.depField);
    }
    return a.pkg.localeCompare(b.pkg);
  });
  const overrideCandidates = Array.from(overrideCandidateByKey.values()).sort((a, b) => {
    if (a.pkg !== b.pkg) {
      return a.pkg.localeCompare(b.pkg);
    }
    return scopeKey(a.scope).localeCompare(scopeKey(b.scope));
  });

  const operations: RemediationPlan["operations"] = [];
  let directIndex = 1;
  for (const candidate of directCandidates) {
    const fromVersions = Array.from(candidate.fromVersions).sort(compareVersion);
    const why = `Fixes ${Array.from(candidate.vulnIds).sort().join(", ")}${candidate.reachable ? " (reachable)" : ""}`;
    operations.push({
      id: `op-manifest-direct-upgrade-${directIndex}`,
      kind: "manifest-direct-upgrade",
      file: "package.json",
      depField: candidate.depField,
      package: candidate.pkg,
      fromRange: fromVersions.length > 0 ? fromVersions.join(",") : candidate.toVersion,
      toRange: candidate.toVersion,
      why
    });
    directIndex += 1;
  }

  if (overrideCandidates.length > 0) {
    const changes = overrideCandidates.map((candidate) => {
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
    if (status.covered && !status.unresolved) {
      fixedVulnerabilities.push(vulnId);
    } else {
      remainingVulnerabilities.push(vulnId);
    }
  }
  fixedVulnerabilities.sort();
  remainingVulnerabilities.sort();

  const summaryLines: string[] = [];
  if (input.strategyLabel === "direct") {
    if (directCandidates.length > 0) {
      summaryLines.push(
        `Generated ${directCandidates.length} direct dependency upgrade(s) for ${fixedVulnerabilities.length} vulnerability record(s).`
      );
    } else {
      summaryLines.push("No applicable direct dependency upgrades were generated from current findings.");
    }
  } else {
    if (directCandidates.length > 0 || overrideCandidates.length > 0) {
      summaryLines.push(
        `Generated ${directCandidates.length} direct upgrade(s) and ${overrideCandidates.length > 0 ? 1 : 0} override operation(s).`
      );
    } else {
      summaryLines.push("No applicable direct or transitive remediation operations were generated from current findings.");
    }
  }

  const summary: RemediationPlan["summary"] = {
    reasonedTopChoices: [
      {
        opId: operations[0]?.id ?? "op-no-applicable-remediation",
        rationale: summaryLines.join(" "),
        risk: collectOperationRisk(policy, directCandidates.length, overrideCandidates.length)
      }
    ]
  };

  return {
    tool: "npmvulncheck",
    strategy: input.strategyLabel,
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
