import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DepGraph } from "../src/core/types";
import { YarnLockfileProvider } from "../src/deps/yarn";
import { cleanupTempDirs, copyFixtureToTemp } from "./helpers";

afterEach(async () => {
  await cleanupTempDirs();
});

function registryInventory(graph: Awaited<ReturnType<YarnLockfileProvider["load"]>>["graph"]): Set<string> {
  return new Set(
    Array.from(graph.nodes.values())
      .filter((node) => node.source === "registry")
      .map((node) => `${node.name}@${node.version}`)
  );
}

function normalizeGraph(graph: DepGraph): Record<string, unknown> {
  const nodes = Array.from(graph.nodes.values())
    .map((node) => ({
      id: node.id,
      name: node.name,
      version: node.version,
      source: node.source ?? "unknown",
      purl: node.purl,
      location: node.location
    }))
    .sort((a, b) => a.id.localeCompare(b.id));
  const edges = graph.edges
    .map((edge) => ({
      from: edge.from,
      to: edge.to,
      name: edge.name,
      type: edge.type
    }))
    .sort((a, b) => {
      const left = `${a.from}|${a.to}|${a.name}|${a.type}`;
      const right = `${b.from}|${b.to}|${b.name}|${b.type}`;
      return left.localeCompare(right);
    });
  const importers = Array.from(graph.importers?.entries() ?? []).sort(([a], [b]) => a.localeCompare(b));
  return {
    rootId: graph.rootId,
    manager: graph.manager,
    importers,
    nodes,
    edges
  };
}

describe("YarnLockfileProvider", () => {
  it("detects and loads classic lockfile entries", async () => {
    const provider = new YarnLockfileProvider();
    const fixture = await copyFixtureToTemp("yarn-classic", "npmvulncheck-yarn-classic-");

    const detected = await provider.detect(fixture);
    expect(detected?.manager).toBe("yarn");
    expect(detected?.details?.variant).toBe("classic");

    const context = await provider.load(fixture);
    const graph = context.graph;
    expect(graph.manager).toBe("yarn");
    expect(context.capabilities.lockfileResolver).toBe(false);

    const inventory = registryInventory(graph);
    expect(inventory.has("dep-a@1.2.0")).toBe(true);
    expect(inventory.has("trans-a@2.3.0")).toBe(true);

    const rootEdges = graph.edgesByFrom.get(graph.rootId) ?? [];
    expect(rootEdges.some((edge) => edge.name === "dep-a" && edge.type === "prod")).toBe(true);
    expect(normalizeGraph(graph)).toMatchSnapshot();
  });

  it("detects and loads berry lockfile entries", async () => {
    const provider = new YarnLockfileProvider();
    const fixture = await copyFixtureToTemp("yarn-berry", "npmvulncheck-yarn-berry-");

    const detected = await provider.detect(fixture);
    expect(detected?.details?.variant).toBe("berry");

    const context = await provider.load(fixture);
    const graph = context.graph;
    expect(graph.manager).toBe("yarn");
    expect(context.capabilities.lockfileResolver).toBe(true);

    const inventory = registryInventory(graph);
    expect(inventory.has("dep-b@1.4.0")).toBe(true);
    expect(inventory.has("trans-b@2.1.0")).toBe(true);

    const fromFile = path.join(fixture, "src", "index.ts");
    const candidates = graph.resolvePackageCandidates?.("dep-b", fromFile, "esm-import", ["node", "import", "default"]) ?? [];
    expect(candidates.length).toBeGreaterThan(0);
    expect(graph.nodes.get(candidates[0])?.name).toBe("dep-b");
    expect(normalizeGraph(graph)).toMatchSnapshot();
  });

  it("uses node_modules fallback resolver when lockfile candidates are ambiguous", async () => {
    const provider = new YarnLockfileProvider();
    const fixture = await copyFixtureToTemp("yarn-classic-fs", "npmvulncheck-yarn-classic-fs-");
    await fs.mkdir(path.join(fixture, "node_modules", "foo"), { recursive: true });
    await fs.writeFile(
      path.join(fixture, "node_modules", "foo", "package.json"),
      JSON.stringify({ name: "foo", version: "2.0.1" }, null, 2),
      "utf8"
    );
    await fs.writeFile(path.join(fixture, "node_modules", "foo", "index.js"), "module.exports = {};\n", "utf8");

    const context = await provider.load(fixture);
    expect(context.capabilities.lockfileResolver).toBe(false);
    expect(context.capabilities.fsResolver).toBe(true);

    const fromFile = path.join(fixture, "src", "index.ts");
    const candidates = context.graph.resolvePackageCandidates?.("foo", fromFile, "esm-import", ["node", "import", "default"]) ?? [];
    expect(candidates).toHaveLength(1);
    expect(context.graph.nodes.get(candidates[0])?.version).toBe("2.0.1");
  });

  it("uses .pnp.cjs resolver for berry projects", async () => {
    const provider = new YarnLockfileProvider();
    const fixture = await copyFixtureToTemp("yarn-berry-pnp", "npmvulncheck-yarn-berry-pnp-");

    const context = await provider.load(fixture);
    expect(context.capabilities.lockfileResolver).toBe(true);
    expect(context.capabilities.pnpResolver).toBe(true);

    const fromFile = path.join(fixture, "src", "index.ts");
    const candidates =
      context.graph.resolvePackageCandidates?.("dep-c", fromFile, "esm-import", ["node", "import", "default"]) ?? [];
    expect(candidates).toHaveLength(1);
    expect(context.graph.nodes.get(candidates[0])?.name).toBe("dep-c");
    expect(context.graph.nodes.get(candidates[0])?.version).toBe("2.2.0");
  });
});
