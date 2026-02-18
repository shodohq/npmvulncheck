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
    expect(reachability.byNodeId.get("node_modules/express")?.level).toBe("import");
    expect(reachability.byNodeId.get("node_modules/body-parser")?.level).toBe("transitive");
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
});
