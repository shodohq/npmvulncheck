import { execFile as execFileCb } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { NpmArboristProvider } from "../src/deps/npmArborist";
import { cleanupTempDirs, copyFixtureToTemp, makeTempDir } from "./helpers";

const execFile = promisify(execFileCb);

afterEach(async () => {
  await cleanupTempDirs();
});

function toInventorySet(graph: Awaited<ReturnType<NpmArboristProvider["load"]>>): Set<string> {
  return new Set(Array.from(graph.nodes.values()).map((node) => `${node.name}@${node.version}`));
}

describe("NpmArboristProvider", () => {
  it("detects npm lockfiles and npm-shrinkwrap.json", async () => {
    const provider = new NpmArboristProvider();
    const fixture = await copyFixtureToTemp("dep-graph-local", "npmvulncheck-dep-detect-");

    expect(await provider.detect(fixture)).toBe(true);

    const lockPath = path.join(fixture, "package-lock.json");
    const shrinkwrapPath = path.join(fixture, "npm-shrinkwrap.json");
    await fs.rename(lockPath, shrinkwrapPath);

    expect(await provider.detect(fixture)).toBe(true);
  });

  it("allows installed-mode detection with node_modules even without lockfile", async () => {
    const provider = new NpmArboristProvider();
    const fixture = await makeTempDir("npmvulncheck-dep-installed-detect-");
    await fs.mkdir(path.join(fixture, "node_modules"), { recursive: true });

    expect(await provider.detect(fixture, "installed")).toBe(true);
    expect(await provider.detect(fixture, "lockfile")).toBe(false);
    expect(await provider.detect(fixture, "source")).toBe(false);
  });

  it("does not detect installed mode when only lockfile exists", async () => {
    const provider = new NpmArboristProvider();
    const fixture = await copyFixtureToTemp("dep-graph-local", "npmvulncheck-dep-installed-lock-only-");

    expect(await provider.detect(fixture, "installed")).toBe(false);
    await expect(provider.load(fixture, "installed")).rejects.toThrow("installed mode requires node_modules");
  });

  it("loads lockfile virtual graph with expected dependency classes", async () => {
    const provider = new NpmArboristProvider();
    const fixture = await copyFixtureToTemp("dep-graph-local", "npmvulncheck-dep-virtual-");
    const graph = await provider.load(fixture, "lockfile");

    const inventory = toInventorySet(graph);
    expect(Array.from(graph.nodes.values()).some((node) => node.id === "" && node.version === "1.0.0")).toBe(true);
    expect(inventory.has("prod-a@1.0.0")).toBe(true);
    expect(inventory.has("dev-a@1.0.0")).toBe(true);
    expect(inventory.has("opt-a@1.0.0")).toBe(true);
    expect(inventory.has("peer-a@1.0.0")).toBe(true);

    const edgeTypes = new Set(graph.edges.map((edge) => `${edge.name}:${edge.type}`));
    expect(edgeTypes.has("dev-a:dev")).toBe(true);
    expect(edgeTypes.has("opt-a:optional")).toBe(true);
    expect(edgeTypes.has("peer-a:peer")).toBe(true);
    expect(edgeTypes.has("prod-a:prod")).toBe(true);

    expect(graph.resolvePackage("prod-a")).toBeTypeOf("string");
  });

  it("loads installed graph and matches lockfile inventory when node_modules exists", async () => {
    const provider = new NpmArboristProvider();
    const fixture = await copyFixtureToTemp("dep-graph-local", "npmvulncheck-dep-installed-");

    await execFile("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund"], {
      cwd: fixture,
      env: { ...process.env, npm_config_update_notifier: "false" }
    });

    const lockGraph = await provider.load(fixture, "lockfile");
    const actualGraph = await provider.load(fixture, "installed");

    const lockInventory = toInventorySet(lockGraph);
    const actualInventory = toInventorySet(actualGraph);

    for (const pkg of ["prod-a@1.0.0", "dev-a@1.0.0", "opt-a@1.0.0", "peer-a@1.0.0"]) {
      expect(lockInventory.has(pkg)).toBe(true);
      expect(actualInventory.has(pkg)).toBe(true);
    }

    expect(actualGraph.edges.length).toBeGreaterThan(0);
  });
});
