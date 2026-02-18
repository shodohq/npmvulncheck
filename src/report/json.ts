import { ScanResult } from "../core/types";

export function renderJson(result: ScanResult): string {
  return `${JSON.stringify(result, null, 2)}\n`;
}
