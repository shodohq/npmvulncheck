import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { normalizePackageSpecifier, resolveLocalModule } from "../src/reachability/packageResolve";
import { cleanupTempDirs, makeTempDir } from "./helpers";

afterEach(async () => {
  await cleanupTempDirs();
});

describe("normalizePackageSpecifier", () => {
  it("normalizes scoped and subpath imports to package name", () => {
    expect(normalizePackageSpecifier("lodash/map")).toBe("lodash");
    expect(normalizePackageSpecifier("@scope/pkg/subpath")).toBe("@scope/pkg");
    expect(normalizePackageSpecifier("@scope/pkg")).toBe("@scope/pkg");
  });

  it("returns undefined for relative, absolute and node built-in imports", () => {
    expect(normalizePackageSpecifier("./local")).toBeUndefined();
    expect(normalizePackageSpecifier("/abs/path")).toBeUndefined();
    expect(normalizePackageSpecifier("node:fs")).toBeUndefined();
    expect(normalizePackageSpecifier("@broken-scope")).toBeUndefined();
  });
});

describe("resolveLocalModule", () => {
  it("resolves extensionless and index-based local modules", async () => {
    const tempDir = await makeTempDir("npmvulncheck-resolve-");
    const srcDir = path.join(tempDir, "src");
    await fs.mkdir(path.join(srcDir, "utils"), { recursive: true });

    const fromFile = path.join(srcDir, "index.ts");
    await fs.writeFile(fromFile, "", "utf8");
    await fs.writeFile(path.join(srcDir, "helper.ts"), "export const x = 1;", "utf8");
    await fs.writeFile(path.join(srcDir, "utils", "index.ts"), "export const y = 2;", "utf8");

    expect(resolveLocalModule(fromFile, "./helper")).toBe(path.join(srcDir, "helper.ts"));
    expect(resolveLocalModule(fromFile, "./utils")).toBe(path.join(srcDir, "utils", "index.ts"));
    expect(resolveLocalModule(fromFile, "express")).toBeUndefined();
  });
});
