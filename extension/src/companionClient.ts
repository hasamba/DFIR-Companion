import type { CapturePayload } from "./types.js";

type FetchFn = typeof fetch;

export class CompanionClient {
  // The default wraps global fetch in an arrow so it keeps its correct binding.
  // Invoking unbound `fetch` via `this.fetchFn(...)` throws "Illegal invocation"
  // in a service worker context.
  constructor(
    private readonly baseUrl: string,
    private readonly fetchFn: FetchFn = (input, init) => fetch(input, init),
  ) {}

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
