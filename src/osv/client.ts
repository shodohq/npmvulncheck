const DEFAULT_BASE_URL = "https://api.osv.dev";

export type OsvQuery = {
  package: {
    ecosystem: string;
    name: string;
  };
  version?: string;
  page_token?: string;
};

export type OsvBatchResponse = {
  results: Array<{
    vulns?: Array<{
      id: string;
      modified?: string;
    }>;
    next_page_token?: string;
  }>;
};

export class OsvClient {
  constructor(private readonly baseUrl = DEFAULT_BASE_URL) {}

  async queryBatch(queries: OsvQuery[]): Promise<OsvBatchResponse> {
    const response = await fetch(`${this.baseUrl}/v1/querybatch`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({ queries })
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`OSV querybatch failed (${response.status}): ${body}`);
    }

    return (await response.json()) as OsvBatchResponse;
  }

  async getVulnerability(id: string): Promise<unknown> {
    const response = await fetch(`${this.baseUrl}/v1/vulns/${encodeURIComponent(id)}`);
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`OSV vuln fetch failed for ${id} (${response.status}): ${body}`);
    }

    return response.json();
  }
}
