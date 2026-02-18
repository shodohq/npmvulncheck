import serialize from "serialize-javascript";

export function renderTemplatePayload(payload: unknown): string {
  return `<script>window.__PAYLOAD__=${serialize(payload)}</script>`;
}
