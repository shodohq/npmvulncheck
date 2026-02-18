export type ScanMode = "lockfile" | "installed" | "source";
export type OutputFormat = "text" | "json" | "sarif" | "openvex";
export type DepEdgeType = "prod" | "dev" | "optional" | "peer";

export type PackageNode = {
  id: string;
  name: string;
  version: string;
  location: string;
  purl?: string;
  flags: {
    dev?: boolean;
    optional?: boolean;
    peer?: boolean;
  };
};

export type DependencyEdge = {
  from: string;
  to: string;
  name: string;
  type: DepEdgeType;
};

export type Evidence = {
  kind: "import";
  file: string;
  line: number;
  column: number;
  specifier: string;
  importText: string;
};

export type Reachability = {
  reachable: boolean;
  level: "import" | "transitive" | "unknown";
  evidences: Evidence[];
  traces: string[][];
};

export type FixSuggestion = {
  fixedVersion?: string;
  note?: string;
};

export type Finding = {
  vulnId: string;
  aliases: string[];
  summary: string;
  details?: string;
  severity?: {
    type: string;
    score: string;
  }[];
  affected: {
    package: PackageNode;
    paths: string[][];
    reachability?: Reachability;
    fix?: FixSuggestion;
  }[];
  references: { type: string; url: string }[];
  modified?: string;
  published?: string;
};

export type ReachabilityRecord = {
  level: "import" | "transitive";
  evidences: Evidence[];
  traces: string[][];
};

export type ReachabilityResult = {
  byNodeId: Map<string, ReachabilityRecord>;
};

export type DepGraph = {
  ecosystem: "npm";
  rootId: string;
  nodes: Map<string, PackageNode>;
  edges: DependencyEdge[];
  edgesByFrom: Map<string, DependencyEdge[]>;
  rootDirectNodeIds: Set<string>;
  resolvePackage: (name: string) => string | undefined;
};

export type OsvBatchMatch = {
  id: string;
  modified?: string;
};

export type OsvReference = {
  type?: string;
  url?: string;
};

export type OsvSeverity = {
  type: string;
  score: string;
};

export type OsvVulnerability = {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  modified?: string;
  published?: string;
  severity?: OsvSeverity[];
  affected?: Array<{
    package?: {
      ecosystem?: string;
      name?: string;
      purl?: string;
    };
    ranges?: Array<{
      type?: string;
      events?: Array<{
        introduced?: string;
        fixed?: string;
        last_affected?: string;
        limit?: string;
      }>;
    }>;
  }>;
  references?: OsvReference[];
};

export type ScanOptions = {
  root: string;
  mode: ScanMode;
  format: OutputFormat;
  entries: string[];
  showTraces: boolean;
  showVerbose: boolean;
  includeDev: boolean;
  cacheDir?: string;
  exitCodeOn: "none" | "findings" | "reachable-findings";
  severityThreshold?: "low" | "medium" | "high" | "critical";
  failOn: "all" | "reachable" | "direct";
  ignoreFile?: string;
  offline: boolean;
};

export type ScanMeta = {
  tool: {
    name: string;
    version: string;
  };
  mode: ScanMode;
  format: OutputFormat;
  db: {
    name: string;
    lastUpdated?: string;
  };
  timestamp: string;
};

export type ScanResult = {
  meta: ScanMeta;
  findings: Finding[];
  stats: {
    nodes: number;
    edges: number;
    queriedPackages: number;
    vulnerabilities: number;
  };
};

export type IgnoreRule = {
  id: string;
  until?: string;
  reason?: string;
};

export type IgnorePolicy = {
  ignore: IgnoreRule[];
};
