import { DepGraph, DependencyEdge, PackageNode } from "../core/types";

export function buildEdgesByFrom(edges: DependencyEdge[]): Map<string, DependencyEdge[]> {
  const byFrom = new Map<string, DependencyEdge[]>();
  for (const edge of edges) {
    const list = byFrom.get(edge.from);
    if (list) {
      list.push(edge);
      continue;
    }
    byFrom.set(edge.from, [edge]);
  }
  return byFrom;
}

export function makePurl(name: string, version: string): string {
  return `pkg:npm/${encodeURIComponent(name)}@${version}`;
}

export function clonePackageNode(node: PackageNode): PackageNode {
  return {
    id: node.id,
    name: node.name,
    version: node.version,
    location: node.location,
    purl: node.purl,
    flags: { ...node.flags }
  };
}

export function makeEmptyDepGraph(): DepGraph {
  return {
    ecosystem: "npm",
    rootId: "",
    nodes: new Map(),
    edges: [],
    edgesByFrom: new Map(),
    rootDirectNodeIds: new Set(),
    resolvePackage: () => undefined
  };
}
