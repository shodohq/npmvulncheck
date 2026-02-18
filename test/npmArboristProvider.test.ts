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

  it("resolves dependencies from the containing package context in lockfile mode", async () => {
    const provider = new NpmArboristProvider();
    const fixture = await copyFixtureToTemp("workspace-split-resolve", "npmvulncheck-workspace-resolve-");
    const graph = await provider.load(fixture, "lockfile");

    const fromA = path.join(fixture, "packages", "a", "src", "index.ts");
    const fromB = path.join(fixture, "packages", "b", "src", "index.ts");

    expect(graph.resolvePackage("x", fromA, "esm-import", ["node", "import", "default"])).toBe("node_modules/x");
    expect(graph.resolvePackage("x", fromB, "esm-import", ["node", "import", "default"])).toBe(
      "packages/b/node_modules/x"
    );
  });

  it("resolves package.json imports (#...) with condition selection", async () => {
    const provider = new NpmArboristProvider();
    const fixture = await makeTempDir("npmvulncheck-imports-resolve-");

    await fs.mkdir(path.join(fixture, "packages", "consumer", "src"), { recursive: true });
    await fs.mkdir(path.join(fixture, "packages", "target"), { recursive: true });
    await fs.writeFile(
      path.join(fixture, "package.json"),
      JSON.stringify(
        {
          name: "imports-resolve",
          version: "1.0.0",
          private: true,
          dependencies: {
            consumer: "file:packages/consumer",
            target: "file:packages/target"
          }
        },
        null,
        2
      ),
      "utf8"
    );
    await fs.writeFile(
      path.join(fixture, "package-lock.json"),
      JSON.stringify(
        {
          name: "imports-resolve",
          version: "1.0.0",
          lockfileVersion: 3,
          requires: true,
          packages: {
            "": {
              name: "imports-resolve",
              version: "1.0.0",
              dependencies: {
                consumer: "file:packages/consumer",
                target: "file:packages/target"
              }
            },
            "node_modules/consumer": {
              resolved: "packages/consumer",
              link: true
            },
            "node_modules/target": {
              resolved: "packages/target",
              link: true
            },
            "packages/consumer": {
              version: "1.0.0"
            },
            "packages/target": {
              version: "1.0.0"
            }
          }
        },
        null,
        2
      ),
      "utf8"
    );
    await fs.writeFile(
      path.join(fixture, "packages", "consumer", "package.json"),
      JSON.stringify(
        {
          name: "consumer",
          version: "1.0.0",
          imports: {
            "#dep": {
              custom: "target",
              default: "missing"
            },
            "#blockedByImport": {
              import: null,
              default: "target"
            }
          }
        },
        null,
        2
      ),
      "utf8"
    );
    await fs.writeFile(
      path.join(fixture, "packages", "target", "package.json"),
      JSON.stringify(
        {
          name: "target",
          version: "1.0.0"
        },
        null,
        2
      ),
      "utf8"
    );
    await fs.writeFile(path.join(fixture, "packages", "consumer", "src", "index.ts"), 'import "#dep";\n', "utf8");

    const graph = await provider.load(fixture, "lockfile");
    const fromFile = path.join(fixture, "packages", "consumer", "src", "index.ts");

    expect(graph.resolveInternalImport?.("#dep", fromFile, "esm-import", ["custom"])).toBe("node_modules/target");
    expect(graph.resolveInternalImport?.("#dep", fromFile, "esm-import", ["node", "import", "default"])).toBeUndefined();
    expect(graph.resolveInternalImport?.("#blockedByImport", fromFile, "esm-import", ["node", "import", "default"])).toBeUndefined();
  });

  it("enforces package exports subpath and condition checks when manifests are available", async () => {
    const provider = new NpmArboristProvider();
    const fixture = await makeTempDir("npmvulncheck-exports-resolve-");

    await fs.mkdir(path.join(fixture, "packages", "consumer", "src"), { recursive: true });
    await fs.mkdir(path.join(fixture, "packages", "target"), { recursive: true });
    await fs.writeFile(
      path.join(fixture, "package.json"),
      JSON.stringify(
        {
          name: "exports-resolve",
          version: "1.0.0",
          private: true,
          dependencies: {
            consumer: "file:packages/consumer",
            target: "file:packages/target"
          }
        },
        null,
        2
      ),
      "utf8"
    );
    await fs.writeFile(
      path.join(fixture, "package-lock.json"),
      JSON.stringify(
        {
          name: "exports-resolve",
          version: "1.0.0",
          lockfileVersion: 3,
          requires: true,
          packages: {
            "": {
              name: "exports-resolve",
              version: "1.0.0",
              dependencies: {
                consumer: "file:packages/consumer",
                target: "file:packages/target"
              }
            },
            "node_modules/consumer": {
              resolved: "packages/consumer",
              link: true
            },
            "node_modules/target": {
              resolved: "packages/target",
              link: true
            },
            "packages/consumer": {
              version: "1.0.0",
              dependencies: {
                target: "file:../target"
              }
            },
            "packages/target": {
              version: "1.0.0"
            }
          }
        },
        null,
        2
      ),
      "utf8"
    );
    await fs.writeFile(
      path.join(fixture, "packages", "consumer", "package.json"),
      JSON.stringify(
        {
          name: "consumer",
          version: "1.0.0",
          dependencies: {
            target: "file:../target"
          }
        },
        null,
        2
      ),
      "utf8"
    );
    await fs.writeFile(
      path.join(fixture, "packages", "target", "package.json"),
      JSON.stringify(
        {
          name: "target",
          version: "1.0.0",
          exports: {
            ".": {
              import: "./index.mjs",
              require: null
            },
            "./public": "./public.js",
            "./blocked": null,
            "./custom/*": {
              custom: "./custom/*.js",
              default: null
            },
            "./blocked-by-import": {
              import: null,
              default: "./fallback.js"
            }
          }
        },
        null,
        2
      ),
      "utf8"
    );
    await fs.writeFile(path.join(fixture, "packages", "consumer", "src", "index.ts"), 'import "target";\n', "utf8");

    const graph = await provider.load(fixture, "lockfile");
    const fromFile = path.join(fixture, "packages", "consumer", "src", "index.ts");

    expect(graph.resolvePackage("target", fromFile, "esm-import", ["node", "import", "default"])).toBe(
      "node_modules/target"
    );
    expect(graph.resolvePackage("target", fromFile, "cjs-require", ["node", "require", "default"])).toBeNull();
    expect(graph.resolvePackage("target/public", fromFile, "esm-import", ["node", "import", "default"])).toBe(
      "node_modules/target"
    );
    expect(graph.resolvePackage("target/blocked", fromFile, "esm-import", ["node", "import", "default"])).toBeNull();
    expect(graph.resolvePackage("target/blocked-by-import", fromFile, "esm-import", ["node", "import", "default"])).toBeNull();
    expect(graph.resolvePackage("target/custom/foo", fromFile, "esm-import", ["custom"])).toBe("node_modules/target");
    expect(graph.resolvePackage("target/custom/foo", fromFile, "esm-import", ["node", "import", "default"])).toBeNull();
  });
});
