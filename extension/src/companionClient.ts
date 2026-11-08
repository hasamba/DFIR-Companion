import { credentialMatches } from "./casePasswordSession.js";
import type { CaseCredential, CapturePayload, ImportPayload } from "./types.js";

type FetchFn = typeof fetch;

// Outcome of a capture POST. `status` is the HTTP status, or 0 when fetch threw (the
// companion is unreachable). The controller uses it to tell a transient outage (queue
// and retry) apart from a server rejection like 404 case-not-found (don't queue).
export interface PostCaptureResult {
  ok: boolean;
  status: number;
  errorMessage?: string;
  errorCode?: string; // the body's machine-readable `code`, when it sent one
  // On success: `analyzed:false, reason:"ai-off"` means saved as evidence but NOT analyzed (#2258).
  analyzed?: boolean;
  reason?: string;
}

/**
 * Longest a capture upload may stay open (#2396). Chrome ends a service worker that waits on one
 * fetch for over 30 s, so the limit sits under that: a stalled companion now answers "unreachable"
 * (the capture stays queued for retry) instead of holding the worker until it is killed.
 */
export const CAPTURE_POST_TIMEOUT_MS = 25_000;

export class CompanionClient {
  // The default wraps global fetch in an arrow so it keeps its correct binding.
  // Invoking unbound `fetch` via `this.fetchFn(...)` throws "Illegal invocation"
  // in a service worker context.
  constructor(
    private readonly baseUrl: string,
    private readonly fetchFn: FetchFn = (input, init) => fetch(input, init),
    private readonly serviceToken = "",
    // The password of a password-locked case (#2135), added to the request body at SEND time for
    // that case on the companion it was entered for only — queued payloads never carry it.
    private readonly caseCredential?: CaseCredential,
    private readonly captureTimeoutMs = CAPTURE_POST_TIMEOUT_MS,
  ) {}

  /** The companion this client talks to — queued captures are bound to it (#2396). */
  get companionUrl(): string {
    return this.baseUrl;
  }

  /** Would a capture for this case carry the stored case password? */
  sendsCredentialFor(caseId: string): boolean {
    const cred = this.caseCredential;
    return Boolean(cred && credentialMatches(cred, caseId, this.baseUrl));
  }

  private withCasePassword<T extends object>(caseId: string, body: T): T | (T & { casePassword: string }) {
    const cred = this.caseCredential;
    return cred && credentialMatches(cred, caseId, this.baseUrl) ? { ...body, casePassword: cred.password } : body;
  }

  private static async errorOf(res: Response): Promise<{ errorMessage?: string; errorCode?: string }> {
    const body = (await res.json().catch(() => ({}))) as { error?: unknown; code?: unknown } | null;
    return {
      ...(typeof body?.error === "string" ? { errorMessage: body.error } : {}),
      // A machine-readable reason, e.g. "capture-log-needs-repair" (#2252, #2254).
      ...(typeof body?.code === "string" ? { errorCode: body.code } : {}),
    };
  }

  // The success body's analyzed/reason (#2258). Best-effort: an unreadable body is still a success.
  private static async successOf(res: Response): Promise<{ analyzed?: boolean; reason?: string }> {
    const body = (await res.json().catch(() => ({}))) as { analyzed?: unknown; reason?: unknown } | null;
    return {
      ...(typeof body?.analyzed === "boolean" ? { analyzed: body.analyzed } : {}),
      ...(typeof body?.reason === "string" ? { reason: body.reason } : {}),
    };
  }

  private headers(contentType = false): Record<string, string> {
    return {
      ...(contentType ? { "content-type": "application/json" } : {}),
      ...(this.serviceToken ? { Authorization: `Bearer ${this.serviceToken}` } : {}),
    };
  }

  async postCapture(payload: CapturePayload): Promise<PostCaptureResult> {
    // The timer covers reading the answer too: a companion that sends headers and then stalls
    // must not hold the upload open either (#2396).
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), this.captureTimeoutMs);
    try {
      const res = await this.fetchFn(`${this.baseUrl}/captures`, {
        method: "POST",
        headers: this.headers(true),
        body: JSON.stringify(this.withCasePassword(payload.caseId, payload)),
        signal: abort.signal,
      });
      if (res.status === 201) return { ok: true, status: 201, ...(await CompanionClient.successOf(res)) };
      return { ok: false, status: res.status, ...(await CompanionClient.errorOf(res)) };
    } catch {
      return { ok: false, status: 0 }; // network error or timed out — companion unreachable
    } finally {
      clearTimeout(timer);
    }
  }

  // Push an intercepted/scraped tool artifact through the unified import route (issue #102). The
  // companion auto-detects the format and routes it; a successful enqueue is 202 (import runs async).
  async postImport(caseId: string, payload: ImportPayload): Promise<PostCaptureResult> {
    try {
      const res = await this.fetchFn(`${this.baseUrl}/cases/${encodeURIComponent(caseId)}/import`, {
        method: "POST",
        headers: this.headers(true),
        body: JSON.stringify(this.withCasePassword(caseId, payload)),
      });
      if (res.status === 202) return { ok: true, status: 202, ...(await CompanionClient.successOf(res)) };
      return { ok: false, status: res.status, ...(await CompanionClient.errorOf(res)) };
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
