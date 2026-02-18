import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { NodeResolver, TsResolver, createModuleResolver } from "../src/reachability/moduleResolver";
import { cleanupTempDirs, makeTempDir } from "./helpers";

afterEach(async () => {
  await cleanupTempDirs();
});

describe("module resolver strategy", () => {
  it("uses TsResolver when tsconfig.json exists", async () => {
    const tempDir = await makeTempDir("npmvulncheck-module-resolver-ts-");
    await fs.writeFile(path.join(tempDir, "tsconfig.json"), JSON.stringify({ compilerOptions: {} }, null, 2), "utf8");

    const resolver = createModuleResolver(tempDir);
    expect(resolver).toBeInstanceOf(TsResolver);
  });

  it("uses NodeResolver when tsconfig.json does not exist", async () => {
    const tempDir = await makeTempDir("npmvulncheck-module-resolver-node-");

    const resolver = createModuleResolver(tempDir);
    expect(resolver).toBeInstanceOf(NodeResolver);
  });

  it("honors moduleResolution=bundler for extensionless ESM relative imports", async () => {
    const tempDir = await makeTempDir("npmvulncheck-module-resolver-bundler-");
    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(srcDir, { recursive: true });

    await fs.writeFile(path.join(tempDir, "package.json"), JSON.stringify({ type: "module" }, null, 2), "utf8");
    await fs.writeFile(
      path.join(tempDir, "tsconfig.json"),
      JSON.stringify(
        {
          compilerOptions: {
            module: "ESNext",
            moduleResolution: "bundler"
          }
        },
        null,
        2
      ),
      "utf8"
    );
    const fromFile = path.join(srcDir, "index.ts");
    const helperFile = path.join(srcDir, "helper.ts");
    await fs.writeFile(fromFile, 'import "./helper";\n', "utf8");
    await fs.writeFile(helperFile, "export const helper = true;\n", "utf8");

    const resolver = createModuleResolver(tempDir);
    const resolved = resolver.resolveToFile("./helper", fromFile, "esm-import", ["node", "import", "default"]);
    expect(resolved.filePath).toBe(path.resolve(helperFile));

    const nodeResolver = new NodeResolver(tempDir);
    const nodeResolved = nodeResolver.resolveToFile("./helper", fromFile, "esm-import", ["node", "import", "default"]);
    expect(nodeResolved.filePath).toBeUndefined();
  });
});
