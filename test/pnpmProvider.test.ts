import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DepGraph } from "../src/core/types";
import { PnpmLockfileProvider } from "../src/deps/pnpm";
import { cleanupTempDirs, copyFixtureToTemp } from "./helpers";

afterEach(async () => {
  await cleanupTempDirs();
});

function registryInventory(graph: Awaited<ReturnType<PnpmLockfileProvider["load"]>>["graph"]): Set<string> {
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

describe("PnpmLockfileProvider", () => {
  it("detects pnpm-lock.yaml and loads v5 importer/package graph", async () => {
    const provider = new PnpmLockfileProvider();
    const fixture = await copyFixtureToTemp("pnpm-v5", "npmvulncheck-pnpm-v5-");
    const detected = await provider.detect(fixture);

    expect(detected?.manager).toBe("pnpm");

    const context = await provider.load(fixture);
    const graph = context.graph;

    expect(context.capabilities.lockfileResolver).toBe(true);
    expect(graph.manager).toBe("pnpm");
    expect(graph.rootId).toBe("importer:.");
    expect(graph.importers?.get(".")).toBe("importer:.");

    const inventory = registryInventory(graph);
    expect(inventory.has("dep-a@1.0.0")).toBe(true);
    expect(inventory.has("trans-a@2.0.0")).toBe(true);
    expect(inventory.has("dev-a@1.0.0")).toBe(true);

    const edgeTypes = new Set(graph.edges.map((edge) => `${edge.from}|${edge.name}:${edge.type}`));
    expect(edgeTypes.has("importer:.|dep-a:prod")).toBe(true);
    expect(edgeTypes.has("importer:.|dev-a:dev")).toBe(true);
    expect(edgeTypes.has("pnpm:dep-a/1.0.0|trans-a:prod")).toBe(true);

    const fromFile = path.join(fixture, "src", "index.ts");
    const candidates = graph.resolvePackageCandidates?.("dep-a", fromFile, "esm-import", ["node", "import", "default"]) ?? [];
    expect(candidates.length).toBeGreaterThan(0);
    expect(graph.nodes.get(candidates[0])?.name).toBe("dep-a");
    expect(normalizeGraph(graph)).toMatchSnapshot();
  });

  it("loads v9 packages+snapshots graph", async () => {
    const provider = new PnpmLockfileProvider();
    const fixture = await copyFixtureToTemp("pnpm-v9", "npmvulncheck-pnpm-v9-");
    const context = await provider.load(fixture);
    const graph = context.graph;

    expect(graph.manager).toBe("pnpm");

    const inventory = registryInventory(graph);
    expect(inventory.has("dep-b@1.0.0")).toBe(true);
    expect(inventory.has("trans-b@2.0.0")).toBe(true);

    const depSnapshotNode = Array.from(graph.nodes.values()).find((node) => node.name === "dep-b");
    expect(depSnapshotNode).toBeDefined();
    if (depSnapshotNode) {
      const downstream = graph.edgesByFrom.get(depSnapshotNode.id) ?? [];
      expect(downstream.some((edge) => graph.nodes.get(edge.to)?.name === "trans-b")).toBe(true);
    }
    expect(normalizeGraph(graph)).toMatchSnapshot();
  });
});
