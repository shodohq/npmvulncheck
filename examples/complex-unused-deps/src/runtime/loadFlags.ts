export async function fetchRemoteFlags(): Promise<Record<string, unknown>> {
  const axios = await import("axios");
  const response = await axios.default.get("https://example.invalid/flags", {
    timeout: 200
  });
  return response.data as Record<string, unknown>;
}
