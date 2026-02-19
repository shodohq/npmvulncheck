declare module "@yarnpkg/lockfile" {
  export function parse(content: string): {
    type: "success" | "merge" | "conflict";
    object?: Record<string, unknown>;
    parseResultType?: string;
  };
}
