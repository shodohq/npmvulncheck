import { DepGraph, ScanMode } from "../core/types";

export interface DependencyGraphProvider {
  detect(projectRoot: string, mode?: ScanMode): Promise<boolean>;
  load(projectRoot: string, mode: Extract<ScanMode, "lockfile" | "installed">): Promise<DepGraph>;
}
