import path from "node:path";
import { OutputFormat, ScanMode, ScanOptions } from "../core/types";

type RawScanOptions = {
  mode?: string;
  format?: string;
  root?: string;
  entry?: string[];
  conditions?: string[];
  includeTypeImports?: boolean;
  explainResolve?: boolean;
  show?: string[];
  include?: string[];
  includeDev?: boolean;
  omit?: string[];
  omitDev?: boolean;
  cacheDir?: string;
  exitCodeOn?: "none" | "findings" | "reachable-findings";
  severityThreshold?: "low" | "medium" | "high" | "critical";
  failOn?: "all" | "reachable" | "direct";
  ignoreFile?: string;
  offline?: boolean;
};

function parseMode(value: string | undefined): ScanMode {
  if (value === "lockfile" || value === "installed" || value === "source") {
    return value;
  }
  return "lockfile";
}

function parseFormat(value: string | undefined): OutputFormat {
  if (value === "text" || value === "json" || value === "sarif" || value === "openvex") {
    return value;
  }
  return "text";
}

function parseShow(values: string[] | undefined): { showTraces: boolean; showVerbose: boolean } {
  const normalized = new Set((values ?? []).flatMap((value) => value.split(",")).map((value) => value.trim()));
  return {
    showTraces: normalized.has("traces"),
    showVerbose: normalized.has("verbose")
  };
}

function parseIncludeDev(raw: RawScanOptions): boolean {
  if (raw.includeDev) {
    return true;
  }

  const includeSet = new Set((raw.include ?? []).flatMap((value) => value.split(",")).map((value) => value.trim()));
  if (includeSet.has("dev")) {
    return true;
  }

  if (raw.omitDev) {
    return false;
  }

  const omitSet = new Set((raw.omit ?? ["dev"]).flatMap((value) => value.split(",")).map((value) => value.trim()));
  return !omitSet.has("dev");
}

function defaultExitCodeOn(format: OutputFormat): "none" | "findings" | "reachable-findings" {
  if (format === "text") {
    return "findings";
  }
  return "none";
}

function parseConditions(values: string[] | undefined): string[] {
  return Array.from(
    new Set((values ?? []).flatMap((value) => value.split(",")).map((value) => value.trim()).filter(Boolean))
  );
}

export function resolveScanOptions(raw: RawScanOptions, cwd: string): ScanOptions {
  const mode = parseMode(raw.mode);
  const format = parseFormat(raw.format);
  const show = parseShow(raw.show);

  return {
    root: path.resolve(cwd, raw.root ?? "."),
    mode,
    format,
    entries: raw.entry ?? [],
    conditions: parseConditions(raw.conditions),
    includeTypeImports: Boolean(raw.includeTypeImports),
    explainResolve: Boolean(raw.explainResolve),
    showTraces: show.showTraces,
    showVerbose: show.showVerbose,
    includeDev: parseIncludeDev(raw),
    cacheDir: raw.cacheDir,
    exitCodeOn: raw.exitCodeOn ?? defaultExitCodeOn(format),
    severityThreshold: raw.severityThreshold,
    failOn: raw.failOn ?? "all",
    ignoreFile: raw.ignoreFile,
    offline: Boolean(raw.offline)
  };
}

export function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}
