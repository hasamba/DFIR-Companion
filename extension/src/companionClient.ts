import type { CapturePayload } from "./types.js";

type FetchFn = typeof fetch;

export class CompanionClient {
  constructor(private readonly baseUrl: string, private readonly fetchFn: FetchFn = fetch) {}

  async postCapture(payload: CapturePayload): Promise<boolean> {
    try {
      const res = await this.fetchFn(`${this.baseUrl}/captures`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      return res.status === 201;
    } catch {
      return false;
    }
  }

  async createCase(caseId: string, name: string, investigator: string, aiProvider: string | null): Promise<boolean> {
    try {
      const res = await this.fetchFn(`${this.baseUrl}/cases`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ caseId, name, investigator, aiProvider }),
      });
      return res.status === 201;
    } catch {
      return false;
    }
  }

  async ping(): Promise<boolean> {
    try {
      const res = await this.fetchFn(`${this.baseUrl}/health`, { method: "GET" });
      return res.ok; // 200 from GET /health means the companion is reachable
    } catch {
      return false;
    }
  }
}
