import { describe, expect, it } from "vitest";
import { resolveScanOptions } from "../src/cli/args";

describe("resolveScanOptions", () => {
  it("defaults exit-code-on to findings for text output", () => {
    const opts = resolveScanOptions({ format: "text" }, "/tmp");
    expect(opts.exitCodeOn).toBe("findings");
  });

  it("defaults exit-code-on to none for machine-readable outputs", () => {
    expect(resolveScanOptions({ format: "json" }, "/tmp").exitCodeOn).toBe("none");
    expect(resolveScanOptions({ format: "sarif" }, "/tmp").exitCodeOn).toBe("none");
    expect(resolveScanOptions({ format: "openvex" }, "/tmp").exitCodeOn).toBe("none");
  });

  it("parses show/include options with comma-separated values", () => {
    const opts = resolveScanOptions(
      {
        show: ["traces,verbose"],
        include: ["dev"],
        conditions: ["import,node", "custom"],
        includeTypeImports: true,
        explainResolve: true
      },
      "/tmp"
    );

    expect(opts.showTraces).toBe(true);
    expect(opts.showVerbose).toBe(true);
    expect(opts.includeDev).toBe(true);
    expect(opts.conditions).toEqual(["import", "node", "custom"]);
    expect(opts.includeTypeImports).toBe(true);
    expect(opts.explainResolve).toBe(true);
  });
});
