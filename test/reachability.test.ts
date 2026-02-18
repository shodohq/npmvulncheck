import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DepGraph } from "../src/core/types";
import { computeReachability } from "../src/reachability/propagate";

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe("computeReachability", () => {
  it("marks imported package and its transitive dependency reachable", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-reach-"));
    tempDirs.push(tempDir);

    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(path.join(srcDir, "index.ts"), 'import "express";\n', "utf8");

    const graph: DepGraph = {
      ecosystem: "npm",
      rootId: "",
      nodes: new Map([
        ["", { id: "", name: "root", version: "1.0.0", location: "", flags: {} }],
        ["node_modules/express", { id: "node_modules/express", name: "express", version: "4.0.0", location: "node_modules/express", flags: {} }],
        ["node_modules/body-parser", { id: "node_modules/body-parser", name: "body-parser", version: "1.0.0", location: "node_modules/body-parser", flags: {} }]
      ]),
      edges: [
        { from: "", to: "node_modules/express", name: "express", type: "prod" },
        { from: "node_modules/express", to: "node_modules/body-parser", name: "body-parser", type: "prod" }
      ],
      edgesByFrom: new Map([
        ["", [{ from: "", to: "node_modules/express", name: "express", type: "prod" }]],
        [
          "node_modules/express",
          [{ from: "node_modules/express", to: "node_modules/body-parser", name: "body-parser", type: "prod" }]
        ]
      ]),
      rootDirectNodeIds: new Set(["node_modules/express"]),
      resolvePackage: (name: string) => {
        if (name === "express") {
          return "node_modules/express";
        }
        return undefined;
      }
    };

    const reachability = await computeReachability(tempDir, graph, ["src/index.ts"]);
    const express = reachability.byNodeId.get("node_modules/express");
    const bodyParser = reachability.byNodeId.get("node_modules/body-parser");

    expect(express?.level).toBe("import");
    expect(express?.evidences[0].resolvedPackageNodeId).toBe("node_modules/express");
    expect(bodyParser?.level).toBe("transitive");
    expect(bodyParser?.evidences[0].viaNodeId).toBe("node_modules/express");
    expect(bodyParser?.evidences[0].viaEdgeName).toBe("body-parser");
    expect(bodyParser?.evidences[0].viaEdgeType).toBe("prod");
  });

  it("keeps unique traces when a node is reachable through multiple import seeds", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-reach-"));
    tempDirs.push(tempDir);

    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(path.join(srcDir, "index.ts"), 'import "alpha";\nimport "beta";\n', "utf8");

    const graph: DepGraph = {
      ecosystem: "npm",
      rootId: "",
      nodes: new Map([
        ["", { id: "", name: "root", version: "1.0.0", location: "", flags: {} }],
        ["node_modules/alpha", { id: "node_modules/alpha", name: "alpha", version: "1.0.0", location: "node_modules/alpha", flags: {} }],
        ["node_modules/beta", { id: "node_modules/beta", name: "beta", version: "1.0.0", location: "node_modules/beta", flags: {} }],
        ["node_modules/shared", { id: "node_modules/shared", name: "shared", version: "1.0.0", location: "node_modules/shared", flags: {} }]
      ]),
      edges: [
        { from: "", to: "node_modules/alpha", name: "alpha", type: "prod" },
        { from: "", to: "node_modules/beta", name: "beta", type: "prod" },
        { from: "node_modules/alpha", to: "node_modules/shared", name: "shared", type: "prod" },
        { from: "node_modules/beta", to: "node_modules/shared", name: "shared", type: "prod" }
      ],
      edgesByFrom: new Map([
        [
          "",
          [
            { from: "", to: "node_modules/alpha", name: "alpha", type: "prod" },
            { from: "", to: "node_modules/beta", name: "beta", type: "prod" }
          ]
        ],
        ["node_modules/alpha", [{ from: "node_modules/alpha", to: "node_modules/shared", name: "shared", type: "prod" }]],
        ["node_modules/beta", [{ from: "node_modules/beta", to: "node_modules/shared", name: "shared", type: "prod" }]]
      ]),
      rootDirectNodeIds: new Set(["node_modules/alpha", "node_modules/beta"]),
      resolvePackage: (name: string) => {
        if (name === "alpha") {
          return "node_modules/alpha";
        }
        if (name === "beta") {
          return "node_modules/beta";
        }
        return undefined;
      }
    };

    const reachability = await computeReachability(tempDir, graph, ["src/index.ts"]);
    const shared = reachability.byNodeId.get("node_modules/shared");
    expect(shared?.level).toBe("transitive");
    expect(shared?.traces).toHaveLength(2);
    expect(new Set(shared?.traces.map((trace) => trace.join("->"))).size).toBe(2);
  });

  it("resolves the same package name from different containing packages", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-reach-workspace-"));
    tempDirs.push(tempDir);

    const aFile = path.join(tempDir, "packages", "a", "src", "index.ts");
    const bFile = path.join(tempDir, "packages", "b", "src", "index.ts");
    await fs.mkdir(path.dirname(aFile), { recursive: true });
    await fs.mkdir(path.dirname(bFile), { recursive: true });
    await fs.writeFile(aFile, 'import "x";\n', "utf8");
    await fs.writeFile(bFile, 'import "x";\n', "utf8");

    const resolveCalls: Array<{ fromFile?: string; kind?: string; conditions?: string[] }> = [];
    const graph: DepGraph = {
      ecosystem: "npm",
      rootId: "",
      nodes: new Map([
        ["", { id: "", name: "root", version: "1.0.0", location: "", flags: {} }],
        ["node_modules/x", { id: "node_modules/x", name: "x", version: "1.0.0", location: "node_modules/x", flags: {} }],
        ["packages/b/node_modules/x", { id: "packages/b/node_modules/x", name: "x", version: "2.0.0", location: "packages/b/node_modules/x", flags: {} }]
      ]),
      edges: [],
      edgesByFrom: new Map(),
      rootDirectNodeIds: new Set(),
      resolvePackage: (_specifier, fromFile, kind, conditions) => {
        resolveCalls.push({ fromFile, kind, conditions });
        if (fromFile?.includes(`${path.sep}packages${path.sep}a${path.sep}`)) {
          return "node_modules/x";
        }
        if (fromFile?.includes(`${path.sep}packages${path.sep}b${path.sep}`)) {
          return "packages/b/node_modules/x";
        }
        return undefined;
      }
    };

    const reachability = await computeReachability(tempDir, graph, [aFile, bFile]);
    expect(reachability.byNodeId.get("node_modules/x")?.level).toBe("import");
    expect(reachability.byNodeId.get("packages/b/node_modules/x")?.level).toBe("import");
    expect(resolveCalls.every((call) => call.kind === "esm-import")).toBe(true);
    expect(resolveCalls.every((call) => call.conditions?.join(",") === "node,import,default")).toBe(true);
  });

  it("ignores type-only imports by default and includes them when requested", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-reach-type-"));
    tempDirs.push(tempDir);

    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(
      path.join(srcDir, "index.ts"),
      ['import type { T } from "types-only";', 'import { type U } from "types-only-inline";', 'import "runtime";'].join("\n"),
      "utf8"
    );

    const graph: DepGraph = {
      ecosystem: "npm",
      rootId: "",
      nodes: new Map([
        ["", { id: "", name: "root", version: "1.0.0", location: "", flags: {} }],
        ["node_modules/runtime", { id: "node_modules/runtime", name: "runtime", version: "1.0.0", location: "node_modules/runtime", flags: {} }],
        ["node_modules/types-only", { id: "node_modules/types-only", name: "types-only", version: "1.0.0", location: "node_modules/types-only", flags: {} }],
        ["node_modules/types-only-inline", { id: "node_modules/types-only-inline", name: "types-only-inline", version: "1.0.0", location: "node_modules/types-only-inline", flags: {} }]
      ]),
      edges: [],
      edgesByFrom: new Map(),
      rootDirectNodeIds: new Set(),
      resolvePackage: (specifier) => {
        if (specifier === "runtime") {
          return "node_modules/runtime";
        }
        if (specifier === "types-only") {
          return "node_modules/types-only";
        }
        if (specifier === "types-only-inline") {
          return "node_modules/types-only-inline";
        }
        return undefined;
      }
    };

    const defaultReachability = await computeReachability(tempDir, graph, ["src/index.ts"]);
    expect(defaultReachability.byNodeId.has("node_modules/runtime")).toBe(true);
    expect(defaultReachability.byNodeId.has("node_modules/types-only")).toBe(false);
    expect(defaultReachability.byNodeId.has("node_modules/types-only-inline")).toBe(false);

    const includeTypeReachability = await computeReachability(tempDir, graph, ["src/index.ts"], {
      includeTypeImports: true
    });
    expect(includeTypeReachability.byNodeId.has("node_modules/types-only")).toBe(true);
    expect(includeTypeReachability.byNodeId.has("node_modules/types-only-inline")).toBe(true);
  });

  it("applies custom conditions when resolving #imports", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-reach-conditions-"));
    tempDirs.push(tempDir);

    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(path.join(srcDir, "index.ts"), 'import "#dep";\n', "utf8");

    const graph: DepGraph = {
      ecosystem: "npm",
      rootId: "",
      nodes: new Map([
        ["", { id: "", name: "root", version: "1.0.0", location: "", flags: {} }],
        ["node_modules/pkg-a", { id: "node_modules/pkg-a", name: "pkg-a", version: "1.0.0", location: "node_modules/pkg-a", flags: {} }]
      ]),
      edges: [],
      edgesByFrom: new Map(),
      rootDirectNodeIds: new Set(),
      resolvePackage: () => undefined,
      resolveInternalImport: (specifier, _fromFile, _kind, conditions) => {
        if (specifier === "#dep" && conditions.includes("custom")) {
          return "node_modules/pkg-a";
        }
        return undefined;
      }
    };

    const reachability = await computeReachability(tempDir, graph, ["src/index.ts"], {
      conditions: ["custom"]
    });
    expect(reachability.byNodeId.get("node_modules/pkg-a")?.evidences[0].importKind).toBe("esm-import");
  });

  it("follows local #imports mappings through TS module resolution", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-reach-imports-local-"));
    tempDirs.push(tempDir);

    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(
      path.join(tempDir, "package.json"),
      JSON.stringify(
        {
          name: "imports-local",
          version: "1.0.0",
          imports: {
            "#local": "./src/helper.ts"
          }
        },
        null,
        2
      ),
      "utf8"
    );
    await fs.writeFile(path.join(srcDir, "index.ts"), 'import "#local";\n', "utf8");
    await fs.writeFile(path.join(srcDir, "helper.ts"), 'import "runtime";\n', "utf8");

    const graph: DepGraph = {
      ecosystem: "npm",
      rootId: "",
      nodes: new Map([
        ["", { id: "", name: "root", version: "1.0.0", location: "", flags: {} }],
        ["node_modules/runtime", { id: "node_modules/runtime", name: "runtime", version: "1.0.0", location: "node_modules/runtime", flags: {} }]
      ]),
      edges: [],
      edgesByFrom: new Map(),
      rootDirectNodeIds: new Set(),
      resolvePackage: (specifier) => (specifier === "runtime" ? "node_modules/runtime" : undefined),
      resolveInternalImport: () => undefined
    };

    const reachability = await computeReachability(tempDir, graph, ["src/index.ts"]);
    expect(reachability.byNodeId.has("node_modules/runtime")).toBe(true);
  });

  it("passes custom conditions to TS module resolution for #imports", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-reach-imports-conditions-"));
    tempDirs.push(tempDir);

    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(
      path.join(tempDir, "package.json"),
      JSON.stringify(
        {
          name: "imports-conditions",
          version: "1.0.0",
          imports: {
            "#local": {
              custom: "./src/helper.ts",
              default: null
            }
          }
        },
        null,
        2
      ),
      "utf8"
    );
    await fs.writeFile(path.join(srcDir, "index.ts"), 'import "#local";\n', "utf8");
    await fs.writeFile(path.join(srcDir, "helper.ts"), 'import "runtime";\n', "utf8");

    const graph: DepGraph = {
      ecosystem: "npm",
      rootId: "",
      nodes: new Map([
        ["", { id: "", name: "root", version: "1.0.0", location: "", flags: {} }],
        ["node_modules/runtime", { id: "node_modules/runtime", name: "runtime", version: "1.0.0", location: "node_modules/runtime", flags: {} }]
      ]),
      edges: [],
      edgesByFrom: new Map(),
      rootDirectNodeIds: new Set(),
      resolvePackage: (specifier) => (specifier === "runtime" ? "node_modules/runtime" : undefined),
      resolveInternalImport: () => undefined
    };

    const defaultReachability = await computeReachability(tempDir, graph, ["src/index.ts"]);
    expect(defaultReachability.byNodeId.has("node_modules/runtime")).toBe(false);

    const customReachability = await computeReachability(tempDir, graph, ["src/index.ts"], {
      conditions: ["custom"]
    });
    expect(customReachability.byNodeId.has("node_modules/runtime")).toBe(true);
  });

  it("collects unresolved import candidates in explain-resolve mode", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-reach-explain-"));
    tempDirs.push(tempDir);

    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });
    await fs.writeFile(path.join(srcDir, "index.ts"), 'import "pkg-missing";\n', "utf8");

    const graph: DepGraph = {
      ecosystem: "npm",
      rootId: "",
      nodes: new Map([["", { id: "", name: "root", version: "1.0.0", location: "", flags: {} }]]),
      edges: [],
      edgesByFrom: new Map(),
      rootDirectNodeIds: new Set(),
      resolvePackage: () => undefined
    };

    const reachability = await computeReachability(tempDir, graph, ["src/index.ts"], {
      explainResolve: true
    });

    expect(reachability.hasUnknownImports).toBe(true);
    expect(reachability.unresolvedImports.length).toBeGreaterThan(0);
    expect(reachability.unresolvedImports[0].specifier).toBe("pkg-missing");
    expect(Array.isArray(reachability.unresolvedImports[0].candidates)).toBe(true);
  });
});
