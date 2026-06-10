// Minimal typed client for the ClickUp REST API v2 (https://clickup.com/api). Auth is a personal
// API token (pk_…) or OAuth token sent verbatim in the Authorization header (NOT Bearer). We use
// only the handful of endpoints a playbook export needs: GET /user (auth check), GET /list/{id}
// (read the list's custom statuses), POST /list/{id}/task (create), PUT /task/{id} (update).
//
// Like the IRIS/Notion/Timesketch clients, the HTTP transport is an injectable `fetchFn` so the
// orchestrator (clickupPush.ts) is unit-testable with no network.

import type { FetchFn } from "../../enrichment/provider.js";

const CLICKUP_BASE = "https://api.clickup.com/api/v2";

export interface ClickUpClientOptions {
  token: string;            // personal API token (pk_…) or OAuth access token
  baseUrl?: string;         // default https://api.clickup.com/api/v2 (override for tests/proxies)
  fetchFn?: FetchFn;        // injectable transport (tests pass a mock)
  timeoutMs?: number;       // per-request timeout (default 30s)
}

// The subset of a ClickUp task-create/update body we set.
export interface ClickUpTaskBody {
  name: string;
  description?: string;
  status?: string;          // must match one of the list's status names (case-insensitive on ClickUp)
  priority?: number | null; // 1=urgent, 2=high, 3=normal, 4=low; null clears
  due_date?: number;        // Unix epoch ms
  due_date_time?: boolean;
}

export interface ClickUpTaskRef { id: string; url?: string }

export class ClickUpApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly kind: "auth" | "permission" | "notfound" | "ratelimit" | "validation" | "http" | "network",
  ) {
    super(message);
    this.name = "ClickUpApiError";
  }
}

interface ClickUpErrorEnvelope { err?: string; ECODE?: string }

export class ClickUpClient {
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;

  constructor(private readonly opts: ClickUpClientOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = (opts.baseUrl ?? CLICKUP_BASE).replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  private async request<T>(method: "GET" | "POST" | "PUT", path: string, body?: unknown): Promise<T> {
    let res: Response;
    try {
      res = await this.fetchFn(this.base + path, {
        method,
        headers: {
          Authorization: this.opts.token,
          Accept: "application/json",
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new ClickUpApiError(`ClickUp request failed: ${(err as Error).message}`, 0, "network");
    }

    if (!res.ok) {
      const env = (await res.json().catch(() => ({}))) as ClickUpErrorEnvelope;
      const detail = env.err ? `: ${env.err}` : "";
      if (res.status === 401) throw new ClickUpApiError(`ClickUp auth failed (check DFIR_CLICKUP_TOKEN)${detail}`, 401, "auth");
      if (res.status === 403) throw new ClickUpApiError(`ClickUp permission denied — the token can't access this list${detail}`, 403, "permission");
      if (res.status === 404) throw new ClickUpApiError(`ClickUp not found — check the list id${detail}`, 404, "notfound");
      if (res.status === 429) throw new ClickUpApiError(`ClickUp rate limit hit${detail}`, 429, "ratelimit");
      if (res.status === 400) throw new ClickUpApiError(`ClickUp rejected the request${detail}`, 400, "validation");
      throw new ClickUpApiError(`ClickUp HTTP ${res.status} on ${path}${detail}`, res.status, "http");
    }
    return (await res.json().catch(() => ({}))) as T;
  }

  // Auth check — the authorized user.
  async me(): Promise<{ id?: string; username?: string }> {
    const data = await this.request<{ user?: { id?: number; username?: string } }>("GET", "/user");
    return { id: data.user?.id != null ? String(data.user.id) : undefined, username: data.user?.username };
  }

  // The list's custom status NAMES (lowercased) — used to map a playbook status onto whatever
  // statuses this list actually has.
  async listStatuses(listId: string): Promise<string[]> {
    const data = await this.request<{ statuses?: Array<{ status?: string }> }>("GET", `/list/${encodeURIComponent(listId)}`);
    return (data.statuses ?? []).map((s) => String(s.status ?? "").toLowerCase()).filter(Boolean);
  }

  async createTask(listId: string, body: ClickUpTaskBody): Promise<ClickUpTaskRef> {
    const data = await this.request<{ id?: string; url?: string }>("POST", `/list/${encodeURIComponent(listId)}/task`, body);
    return { id: String(data.id ?? ""), url: typeof data.url === "string" ? data.url : undefined };
  }

  async updateTask(taskId: string, body: ClickUpTaskBody): Promise<ClickUpTaskRef> {
    const data = await this.request<{ id?: string; url?: string }>("PUT", `/task/${encodeURIComponent(taskId)}`, body);
    return { id: String(data.id ?? taskId), url: typeof data.url === "string" ? data.url : undefined };
  }
}
