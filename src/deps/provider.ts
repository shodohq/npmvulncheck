import { DepGraph, DependencyManager, ScanMode } from "../core/types";

export interface DetectResult {
  manager: DependencyManager;
  lockfilePath: string;
  details?: Record<string, unknown>;
}

export interface ProviderCapabilities {
  lockfileGraph: true;
  lockfileResolver: boolean;
  fsResolver: boolean;
  pnpResolver: boolean;
}

export interface PackageResolver {
  resolve(request: string, issuerFile: string): string[];
}

export interface ProviderContext {
  detect: DetectResult;
  graph: DepGraph;
  capabilities: ProviderCapabilities;
  resolver?: PackageResolver;
}

export interface LockfileProvider {
  name: DependencyManager;
  detect(rootDir: string): Promise<DetectResult | null>;
  load(rootDir: string): Promise<ProviderContext>;
}

export interface DependencyGraphProvider {
  detect(projectRoot: string, mode?: ScanMode): Promise<boolean>;
  load(projectRoot: string, mode: Extract<ScanMode, "lockfile" | "installed">): Promise<DepGraph>;
}
