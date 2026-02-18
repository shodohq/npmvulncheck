import minimist from "minimist";

export function parseLegacyArgs(argv: string[]): minimist.ParsedArgs {
  return minimist(argv, {
    boolean: ["dry-run"],
    alias: { d: "dry-run" }
  });
}
