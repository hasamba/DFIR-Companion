import type { CapturePayload, ImportPayload } from "./types.js";

type FetchFn = typeof fetch;

// Outcome of a capture POST. `status` is the HTTP status, or 0 when fetch threw (the
// companion is unreachable). The controller uses it to tell a transient outage (queue
// and retry) apart from a server rejection like 404 case-not-found (don't queue).
export interface PostCaptureResult {
  ok: boolean;
  status: number;
  errorMessage?: string;
}

export class CompanionClient {
  // The default wraps global fetch in an arrow so it keeps its correct binding.
  // Invoking unbound `fetch` via `this.fetchFn(...)` throws "Illegal invocation"
  // in a service worker context.
  constructor(
    private readonly baseUrl: string,
    private readonly fetchFn: FetchFn = (input, init) => fetch(input, init),
  ) {}

  async postCapture(payload: CapturePayload): Promise<PostCaptureResult> {
    try {
      const res = await this.fetchFn(`${this.baseUrl}/captures`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.status === 201) return { ok: true, status: 201 };
      const body = await res.json().catch(() => ({})) as { error?: string };
      return { ok: false, status: res.status, errorMessage: body.error };
    } catch {
      return { ok: false, status: 0 }; // network error — companion unreachable
    }
  }

  // Push an intercepted/scraped tool artifact through the unified import route (issue #102). The
  // companion auto-detects the format and routes it; a successful enqueue is 202 (import runs async).
  async postImport(caseId: string, payload: ImportPayload): Promise<PostCaptureResult> {
    try {
      const res = await this.fetchFn(`${this.baseUrl}/cases/${encodeURIComponent(caseId)}/import`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      return { ok: res.status === 202, status: res.status };
    } catch {
      return { ok: false, status: 0 }; // network error — companion unreachable
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
