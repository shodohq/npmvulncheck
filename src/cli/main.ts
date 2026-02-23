#!/usr/bin/env node
import { Command } from "commander";
import packageJson from "../../package.json";
import { resolveScanOptions, collect } from "./args";
import { runScan } from "../core/scan";
import { ProviderRegistry } from "../deps/registry";
import { OsvCache } from "../osv/cache";
import { OsvClient } from "../osv/client";
import { OsvProvider } from "../osv/provider";
import { renderJson } from "../report/json";
import { renderOpenVex } from "../report/openvex";
import { renderSarif } from "../report/sarif";
import { renderText } from "../report/text";
import { ScanOptions, ScanResult } from "../core/types";
import { determineExitCode } from "./exitCode";
import { buildRemediationPlan } from "../remediation";
import { RemediationPlan, RemediationScope, RemediationStrategy, UpgradeLevel } from "../remediation/types";

function renderResult(result: ScanResult, opts: ScanOptions, remediationPlan: RemediationPlan): string {
  switch (opts.format) {
    case "json":
      return renderJson(result, { remediationPlan });
    case "sarif":
      return renderSarif(result, {
        remediationPlan,
        projectRoot: opts.root
      });
    case "openvex":
      return renderOpenVex(result, { remediationPlan });
    case "text":
    default:
      return renderText(result, opts.showTraces, opts.showVerbose, remediationPlan);
  }
}

function renderExplainText(vuln: {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  references?: Array<{ url?: string }>;
}): string {
  const lines: string[] = [];
  lines.push(`${vuln.id} ${vuln.summary ?? ""}`.trim());
  if (vuln.aliases && vuln.aliases.length > 0) {
    lines.push(`aliases: ${vuln.aliases.join(", ")}`);
  }
  if (vuln.modified) {
    lines.push(`modified: ${vuln.modified}`);
  }
  if (vuln.details) {
    lines.push("");
    lines.push(vuln.details);
  }
  if (vuln.references && vuln.references.length > 0) {
    lines.push("");
    lines.push("references:");
    for (const ref of vuln.references) {
      if (ref.url) {
        lines.push(`  - ${ref.url}`);
      }
    }
  }
  return `${lines.join("\n")}\n`;
}

function parseFixStrategy(value: string | undefined): RemediationStrategy {
  if (value === "override" || value === "direct" || value === "in-place" || value === "auto") {
    return value;
  }
  return "auto";
}

function parseFixScope(value: string | undefined): RemediationScope {
  if (value === "global" || value === "by-parent") {
    return value;
  }
  return "global";
}

function parseFixUpgradeLevel(value: string | undefined): UpgradeLevel {
  if (value === "patch" || value === "minor" || value === "major" || value === "any") {
    return value;
  }
  return "any";
}

type ScanCommandOptions = {
  strategy?: string;
  scope?: string;
  upgradeLevel?: string;
  onlyReachable?: boolean;
  includeUnreachable?: boolean;
};

async function detectOrThrow(registry: ProviderRegistry, opts: ScanOptions): Promise<{
  manager: "npm" | "pnpm" | "yarn";
}> {
  const detectMode = opts.mode === "installed" ? "installed" : "lockfile";
  const detected = await registry.detectContext(opts.root, detectMode);

  if (!detected) {
    if (opts.mode === "installed") {
      throw new Error(
        `No installed dependency tree found in ${opts.root}. Installed mode currently requires node_modules/.`
      );
    }
    throw new Error(
      `No supported lockfile found in ${opts.root}. Expected one of: pnpm-lock.yaml, yarn.lock, package-lock.json, npm-shrinkwrap.json.`
    );
  }

  const warnings = detected.details?.warnings;
  if (Array.isArray(warnings)) {
    for (const warning of warnings) {
      if (typeof warning === "string" && warning.length > 0) {
        process.stderr.write(`Warning: ${warning}\n`);
      }
    }
  }

  return {
    manager: detected.manager
  };
}

function buildScanRemediationPlan(
  result: ScanResult,
  graph: Awaited<ReturnType<ProviderRegistry["load"]>>,
  manager: "npm" | "pnpm" | "yarn",
  opts: ScanOptions,
  raw: ScanCommandOptions
): RemediationPlan {
  return buildRemediationPlan(result, graph, {
    strategy: parseFixStrategy(raw.strategy),
    manager,
    policy: {
      scope: parseFixScope(raw.scope),
      upgradeLevel: parseFixUpgradeLevel(raw.upgradeLevel),
      onlyReachable: Boolean(raw.onlyReachable),
      includeUnreachable: Boolean(raw.includeUnreachable),
      includeDev: opts.includeDev,
      severityThreshold: opts.severityThreshold
    },
    relock: false,
    verify: false
  });
}

async function runDefaultScan(raw: Record<string, unknown>): Promise<void> {
  const opts = resolveScanOptions(raw as never, process.cwd());
  const remediationOptions = raw as ScanCommandOptions;
  const depsProvider = new ProviderRegistry();
  const detected = await detectOrThrow(depsProvider, opts);

  const osvProvider = new OsvProvider(new OsvClient(), new OsvCache(opts.cacheDir), opts.offline);
  const detectMode = opts.mode === "installed" ? "installed" : "lockfile";
  const [result, graph] = await Promise.all([
    runScan(opts, depsProvider, osvProvider, packageJson.version),
    depsProvider.load(opts.root, detectMode)
  ]);
  const remediationPlan = buildScanRemediationPlan(result, graph, detected.manager, opts, remediationOptions);
  process.stdout.write(renderResult(result, opts, remediationPlan));
  process.exitCode = determineExitCode(result, opts);
}

async function runExplain(vulnId: string, options: { cacheDir?: string; offline?: boolean; format?: string }): Promise<void> {
  const provider = new OsvProvider(
    new OsvClient(),
    new OsvCache(options.cacheDir),
    Boolean(options.offline)
  );

  const vuln = await provider.getVuln(vulnId);

  if (options.format === "json") {
    process.stdout.write(`${JSON.stringify(vuln, null, 2)}\n`);
    return;
  }

  process.stdout.write(renderExplainText(vuln));
}

const program = new Command();
program
  .name("npmvulncheck")
  .description("govulncheck-compatible vulnerability scanner for npm")
  .version(packageJson.version, "--version", "Show version")
  .option("--mode <mode>", "scan mode: lockfile|installed|source", "lockfile")
  .option("--format <format>", "output format: text|json|sarif|openvex", "text")
  .option("--strategy <strategy>", "remediation strategy: override|direct|in-place(alias:auto)|auto", "auto")
  .option("--scope <scope>", "remediation scope: global|by-parent", "global")
  .option("--upgrade-level <level>", "remediation upgrade level: patch|minor|major|any", "any")
  .option("--only-reachable", "plan remediation only for reachable findings")
  .option("--include-unreachable", "include unreachable findings in remediation planning")
  .option("--root <dir>", "project root", ".")
  .option("--entry <file>", "entry file (repeatable)", collect, [])
  .option("--conditions <condition>", "module resolution condition (repeatable)", collect, [])
  .option("--include-type-imports", "include TypeScript type-only imports in reachability")
  .option("--explain-resolve", "show unresolved import resolution candidates in source mode")
  .option("--show <item>", "show extra sections: traces,verbose", collect, [])
  .option("--include <type>", "include dependency types (e.g. dev)", collect, [])
  .option("--omit <type>", "omit dependency types (default: dev)", collect, ["dev"])
  .option("--include-dev", "include dev dependencies")
  .option("--omit-dev", "omit dev dependencies")
  .option("--cache-dir <dir>", "OSV cache directory")
  .option("--offline", "use cached vulnerability records only")
  .option("--ignore-file <path>", "ignore policy file path")
  .option("--exit-code-on <mode>", "none|findings|reachable-findings")
  .option("--severity-threshold <level>", "low|medium|high|critical")
  .option("--fail-on <scope>", "all|reachable|direct", "all")
  .action(async (rawOptions) => {
    await runDefaultScan(rawOptions as Record<string, unknown>);
  });

program
  .command("explain")
  .description("show vulnerability details by ID")
  .argument("<vulnId>")
  .option("--cache-dir <dir>", "OSV cache directory")
  .option("--offline", "use cached vulnerability records only")
  .option("--format <format>", "text|json", "text")
  .action(async (vulnId, _options, command) => {
    await runExplain(vulnId, command.optsWithGlobals() as { cacheDir?: string; offline?: boolean; format?: string });
  });

program
  .command("version")
  .description("show tool and database metadata")
  .option("--cache-dir <dir>", "OSV cache directory")
  .action(async (options) => {
    const cache = new OsvCache(options.cacheDir);
    const summary = await cache.getVulnSummary();
    process.stdout.write(
      [
        `npmvulncheck ${packageJson.version}`,
        "db: osv",
        `db records: ${summary.count}`,
        `db last-updated: ${summary.lastUpdated ?? "unknown"}`,
        `osv cache: ${cache.dir}`
      ].join("\n") + "\n"
    );
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`Error: ${message}\n`);
  process.exitCode = 2;
});
