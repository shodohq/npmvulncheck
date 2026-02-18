import fs from "node:fs/promises";
import path from "node:path";
import Arborist from "@npmcli/arborist";
import { DepEdgeType, DepGraph, DependencyEdge, PackageNode } from "../core/types";
import { buildEdgesByFrom, makeEmptyDepGraph, makePurl } from "./graph";
import { DependencyGraphProvider } from "./provider";

type ArboristEdge = {
  name?: string;
  type?: string;
  to?: ArboristNode | null;
};

type ArboristNode = {
  location: string;
  name?: string;
  version?: string;
  dev?: boolean;
  optional?: boolean;
  peer?: boolean;
  edgesOut?: Map<string, ArboristEdge>;
  inventory?: {
    values: () => IterableIterator<ArboristNode>;
  };
  resolve?: (name: string) => ArboristNode | null;
};

function mapEdgeType(edgeType: string | undefined): DepEdgeType {
  switch (edgeType) {
    case "dev":
      return "dev";
    case "peer":
    case "peerOptional":
      return "peer";
    case "optional":
      return "optional";
    default:
      return "prod";
  }
}

function packageNameFromNode(node: ArboristNode, projectRoot: string): string {
  if (node.name && node.name.length > 0) {
    return node.name;
  }
  return path.basename(projectRoot);
}

function packageVersionFromNode(node: ArboristNode): string {
  if (node.version && node.version.length > 0) {
    return node.version;
  }
  return "0.0.0";
}

function toPackageNode(node: ArboristNode, projectRoot: string): PackageNode {
  const name = packageNameFromNode(node, projectRoot);
  const version = packageVersionFromNode(node);
  return {
    id: node.location,
    name,
    version,
    location: node.location,
    purl: makePurl(name, version),
    flags: {
      dev: node.dev,
      optional: node.optional,
      peer: node.peer
    }
  };
}

export class NpmArboristProvider implements DependencyGraphProvider {
  async detect(projectRoot: string): Promise<boolean> {
    const lockPath = path.join(projectRoot, "package-lock.json");
    const shrinkwrapPath = path.join(projectRoot, "npm-shrinkwrap.json");

    const [lockStat, shrinkStat] = await Promise.all([
      fs.stat(lockPath).catch(() => null),
      fs.stat(shrinkwrapPath).catch(() => null)
    ]);

    return Boolean(lockStat?.isFile() || shrinkStat?.isFile());
  }

  async load(projectRoot: string, mode: "lockfile" | "installed"): Promise<DepGraph> {
    const graph = makeEmptyDepGraph();
    const arb = new Arborist({ path: projectRoot });
    const rootNode: ArboristNode =
      mode === "installed"
        ? ((await arb.loadActual()) as ArboristNode)
        : ((await arb.loadVirtual()) as ArboristNode);

    const inventory = rootNode.inventory ? Array.from(rootNode.inventory.values()) : [rootNode];

    for (const node of inventory) {
      const pkgNode = toPackageNode(node, projectRoot);
      graph.nodes.set(pkgNode.id, pkgNode);
    }

    const edges: DependencyEdge[] = [];
    for (const node of inventory) {
      const fromId = node.location;
      if (!graph.nodes.has(fromId) || !node.edgesOut) {
        continue;
      }

      for (const edge of node.edgesOut.values()) {
        const toNode = edge.to;
        if (!toNode || !toNode.location || !graph.nodes.has(toNode.location)) {
          continue;
        }
        const depEdge: DependencyEdge = {
          from: fromId,
          to: toNode.location,
          name: edge.name ?? graph.nodes.get(toNode.location)?.name ?? "unknown",
          type: mapEdgeType(edge.type)
        };
        edges.push(depEdge);
      }
    }

    graph.rootId = rootNode.location;
    graph.edges = edges;
    graph.edgesByFrom = buildEdgesByFrom(edges);

    for (const edge of graph.edgesByFrom.get(graph.rootId) ?? []) {
      graph.rootDirectNodeIds.add(edge.to);
    }

    graph.resolvePackage = (name: string): string | undefined => {
      if (!rootNode.resolve) {
        return undefined;
      }
      const resolved = rootNode.resolve(name);
      return resolved?.location;
    };

    return graph;
  }
}
