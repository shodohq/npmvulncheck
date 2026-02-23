import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ProviderRegistry } from "../src/deps/registry";
import { cleanupTempDirs, copyFixtureToTemp } from "./helpers";

afterEach(async () => {
  await cleanupTempDirs();
});

describe("ProviderRegistry", () => {
  it("prefers pnpm when multiple lockfiles exist without packageManager", async () => {
    const fixture = await copyFixtureToTemp("pnpm-v5", "npmvulncheck-provider-registry-pnpm-");
    await fs.writeFile(
      path.join(fixture, "package-lock.json"),
      JSON.stringify({ name: "mixed-lock", lockfileVersion: 3, packages: { "": { version: "1.0.0" } } }, null, 2),
      "utf8"
    );

    const registry = new ProviderRegistry();
    const graph = await registry.load(fixture, "lockfile");
    expect(graph.manager).toBe("pnpm");
  });

  it("honors packageManager preference when matching lockfile exists", async () => {
    const fixture = await copyFixtureToTemp("yarn-berry", "npmvulncheck-provider-registry-yarn-");
    await fs.writeFile(
      path.join(fixture, "package-lock.json"),
      JSON.stringify({ name: "mixed-lock", lockfileVersion: 3, packages: { "": { version: "1.0.0" } } }, null, 2),
      "utf8"
    );

    const registry = new ProviderRegistry();
    const graph = await registry.load(fixture, "lockfile");
    expect(graph.manager).toBe("yarn");
  });

  it("returns mixed-lockfile warnings in detect context", async () => {
    const fixture = await copyFixtureToTemp("pnpm-v5", "npmvulncheck-provider-registry-mixed-warning-");
    await fs.writeFile(
      path.join(fixture, "yarn.lock"),
      ["# yarn lockfile v1", "", "foo@^1.0.0:", '  version "1.0.0"'].join("\n"),
      "utf8"
    );
    await fs.writeFile(
      path.join(fixture, "package-lock.json"),
      JSON.stringify({ name: "mixed-lock", lockfileVersion: 3, packages: { "": { version: "1.0.0" } } }, null, 2),
      "utf8"
    );

    const registry = new ProviderRegistry();
    const detected = await registry.detectContext(fixture, "lockfile");
    expect(detected?.manager).toBe("pnpm");

    const warnings = detected?.details?.warnings;
    expect(Array.isArray(warnings)).toBe(true);
    expect((warnings as string[]).some((message) => message.includes("Multiple lockfiles detected"))).toBe(true);
  });

  it("uses package-lock.json as rollback target in installed mode detect context", async () => {
    const fixture = await copyFixtureToTemp("dep-graph-local", "npmvulncheck-provider-registry-installed-");
    await fs.mkdir(path.join(fixture, "node_modules"), { recursive: true });

    const registry = new ProviderRegistry();
    const detected = await registry.detectContext(fixture, "installed");
    expect(detected?.manager).toBe("npm");
    expect(detected?.lockfilePath).toBe(path.join(fixture, "package-lock.json"));
  });
});
