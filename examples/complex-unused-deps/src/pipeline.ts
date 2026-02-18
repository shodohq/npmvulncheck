import _ from "lodash";

const qs = require("qs");

export function runPipeline(values: string[]): string[] {
  const deduped = _.uniq(values.map((value) => value.toLowerCase()));
  return deduped.map((value) => qs.stringify({ value }));
}
