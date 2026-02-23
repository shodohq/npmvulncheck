import { DependencyManager, ScanOptions } from "../core/types";

export type RemediationStrategy = "override" | "direct" | "in-place" | "auto";
export type RemediationScope = "global" | "by-parent";
export type UpgradeLevel = "patch" | "minor" | "major" | "any";
export type RemediationFormat = "text" | "json";

export type RemediationTarget = {
  onlyReachable: boolean;
  includeDev: boolean;
  severityThreshold?: string;
};

export type RemediationScopeSelector = "global" | { parent: string; parentVersion?: string };

export type RemediationPlan = {
  tool: "npmvulncheck";
  strategy: RemediationStrategy;
  packageManager: DependencyManager;
  target: RemediationTarget;
  operations: RemediationOperation[];
  fixes: {
    fixedVulnerabilities: string[];
    remainingVulnerabilities: string[];
    introducedVulnerabilities?: string[];
  };
  summary: {
    reasonedTopChoices: Array<{
      opId: string;
      rationale: string;
      risk: "low" | "medium" | "high";
    }>;
  };
};

export type RemediationOperation =
  | {
      id: string;
      kind: "manifest-override";
      manager: DependencyManager;
      file: "package.json";
      changes: Array<{
        package: string;
        from?: string;
        to: string;
        scope: RemediationScopeSelector;
        why: string;
      }>;
    }
  | {
      id: string;
      kind: "manifest-direct-upgrade";
      file: "package.json";
      depField: "dependencies" | "devDependencies" | "optionalDependencies";
      package: string;
      fromRange: string;
      toRange: string;
      why: string;
    }
  | {
      id: string;
      kind: "relock";
      manager: DependencyManager;
      command: string;
      args: string[];
    }
  | {
      id: string;
      kind: "verify";
      note: string;
    };

export type RemediationPolicy = {
  scope: RemediationScope;
  upgradeLevel: UpgradeLevel;
  onlyReachable: boolean;
  includeUnreachable: boolean;
  includeDev: boolean;
  severityThreshold?: ScanOptions["severityThreshold"];
};

export type BuildRemediationPlanOptions = {
  strategy: RemediationStrategy;
  manager: DependencyManager;
  policy: RemediationPolicy;
  relock: boolean;
  verify: boolean;
};

export type ApplyRemediationOptions = {
  projectRoot: string;
  lockfilePath?: string;
  rollbackOnFail: boolean;
  verify?: VerifyContext;
};

export type VerifyContext = {
  scanOptions: ScanOptions;
  expectedFixedVulnIds: string[];
  baselineVulnIds: string[];
  noIntroduce: boolean;
  toolVersion: string;
};

export type VerifyOutcome = {
  ok: boolean;
  fixedVulnerabilities: string[];
  remainingVulnerabilities: string[];
  introducedVulnerabilities: string[];
};

export type ApplyRemediationResult = {
  verify?: VerifyOutcome;
};
