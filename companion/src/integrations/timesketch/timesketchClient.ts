// Minimal typed client for the Timesketch REST API (the surface the official Python api_client
// uses: form-based local login, sketches, timelines, and the JSONL event upload). Timesketch has
// no bearer-token API — auth is a Flask session: GET the login page for the CSRF token, POST the
// credentials, and carry the session cookie + `x-csrftoken` header on every later request. We keep
// a small in-memory cookie jar because Node's fetch does not persist cookies across calls.
//
// Like the IRIS/enrichment clients, the HTTP transport is an injectable `fetchFn` so a self-hosted
// Timesketch with an internal-CA / self-signed cert can supply a custom TLS trust, and so the
// real network is never touched in tests (the push orchestrator is tested against a mock client).
// https://github.com/google/timesketch/tree/master/api_client/python

import type { FetchFn } from "../../enrichment/provider.js";

export interface TimesketchClientOptions {
  baseUrl: string;          // e.g. https://timesketch.example.org
  username: string;         // local-auth username
  password: string;         // local-auth password
  fetchFn?: FetchFn;        // injectable transport (tests pass a mock; TLS-custom in prod)
  timeoutMs?: number;       // per-request timeout (default 60s — uploads can be larger)
}

export interface TimesketchSketchRef { id: number; name: string }
export interface TimesketchTimelineRef { id: number; name: string }

export class TimesketchApiError extends Error {
  constructor(message: string, readonly status: number, readonly kind: "auth" | "notfound" | "http" | "network") {
    super(message);
    this.name = "TimesketchApiError";
  }
}

// Extract the Flask-WTF CSRF token from the login page (a hidden input, or a <meta> tag). Exported
// for unit testing against captured login HTML.
export function scrapeCsrfToken(html: string): string | undefined {
  const patterns = [
    /id="csrf_token"[^>]*\bvalue="([^"]+)"/i,
    /name="csrf_token"[^>]*\bvalue="([^"]+)"/i,
    /name="csrf-token"[^>]*\bcontent="([^"]+)"/i,
  ];
  for (const re of patterns) {
    const m = html.match(re);
    if (m) return m[1];
  }
  return undefined;
}

// Timesketch list endpoints wrap results as { objects: [ [item, …] ] } (a one-element list holding
// the list); single-object endpoints use { objects: [ item ] }. Normalize both to a flat array.
function objectList(json: unknown): Array<Record<string, unknown>> {
  const objects = (json as { objects?: unknown })?.objects;
  if (!Array.isArray(objects)) return [];
  if (objects.length === 1 && Array.isArray(objects[0])) return objects[0] as Array<Record<string, unknown>>;
  return objects as Array<Record<string, unknown>>;
}

function firstObject(json: unknown): Record<string, unknown> | undefined {
  return objectList(json)[0];
}

interface SendOptions {
  body?: BodyInit;
  json?: unknown;
  redirect?: RequestRedirect;
  sendCsrf?: boolean;       // default true — attach the x-csrftoken header
}

export class TimesketchClient {
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly apiRoot: string;
  private readonly timeoutMs: number;
  private readonly jar = new Map<string, string>();
  private csrf?: string;

  constructor(private readonly opts: TimesketchClientOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.apiRoot = `${this.base}/api/v1`;
    this.timeoutMs = opts.timeoutMs ?? 60_000;
  }

  // ---- transport -----------------------------------------------------------

  private cookieHeader(): string {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  private ingestCookies(res: Response): void {
    const getSetCookie = (res.headers as { getSetCookie?: () => string[] }).getSetCookie;
    const cookies = typeof getSetCookie === "function" ? getSetCookie.call(res.headers) : [];
    for (const c of cookies) {
      const pair = c.split(";", 1)[0] ?? "";
      const eq = pair.indexOf("=");
      if (eq > 0) this.jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }

  private async send(method: string, url: string, opts: SendOptions = {}): Promise<Response> {
    const headers: Record<string, string> = { Accept: "application/json, text/html", Referer: `${this.base}/` };
    const cookie = this.cookieHeader();
    if (cookie) headers.Cookie = cookie;
    if (opts.sendCsrf !== false && this.csrf) headers["x-csrftoken"] = this.csrf;
    let body = opts.body;
    if (opts.json !== undefined) {
      body = JSON.stringify(opts.json);
      headers["content-type"] = "application/json";
    }
    let res: Response;
    try {
      res = await this.fetchFn(url, {
        method,
        headers,
        body,
        redirect: opts.redirect ?? "follow",
        signal: AbortSignal.timeout(this.timeoutMs),
      } as RequestInit);
    } catch (err) {
      throw new TimesketchApiError(`Timesketch request failed: ${(err as Error).message}`, 0, "network");
    }
    this.ingestCookies(res);
    return res;
  }

  private async errorFor(res: Response, what: string): Promise<TimesketchApiError> {
    let detail = `HTTP ${res.status}`;
    const text = await res.text().catch(() => "");
    const m = text.match(/"message"\s*:\s*"([^"]+)"/);
    if (m) detail = m[1];
    const kind = res.status === 401 || res.status === 403 ? "auth" : res.status === 404 ? "notfound" : "http";
    return new TimesketchApiError(`Timesketch ${what} failed: ${detail}`, res.status, kind);
  }

  // ---- auth ----------------------------------------------------------------

  // Establish a session: GET the login page (cookie + CSRF token), POST the credentials, then
  // verify by calling an authenticated API endpoint (an unauthenticated server returns the login
  // HTML rather than JSON). Fatal — the orchestrator calls this first.
  async login(): Promise<void> {
    const loginUrl = `${this.base}/login/?local_auth=1`;

    const page = await this.send("GET", loginUrl, { sendCsrf: false });
    this.csrf = scrapeCsrfToken(await page.text().catch(() => ""));
    if (!this.csrf) {
      throw new TimesketchApiError(
        "Timesketch login: no CSRF token on the login page (check DFIR_TIMESKETCH_URL and that local auth is enabled)",
        page.status, "auth",
      );
    }

    const form = new URLSearchParams({
      username: this.opts.username,
      password: this.opts.password,
      csrf_token: this.csrf,
    });
    // redirect: "manual" — a successful login replies 302 and sets the authenticated session
    // cookie on THAT response; following the redirect would discard it before we capture it.
    await this.send("POST", loginUrl, { body: form, redirect: "manual" });

    const check = await this.send("GET", `${this.apiRoot}/sketches/?per_page=1`);
    if (check.status === 401 || check.status === 403) {
      throw new TimesketchApiError("Timesketch auth failed (check DFIR_TIMESKETCH_USER / DFIR_TIMESKETCH_PASSWORD)", check.status, "auth");
    }
    if (!check.ok) throw await this.errorFor(check, "login check");
    if (!(check.headers.get("content-type") ?? "").includes("application/json")) {
      throw new TimesketchApiError(
        "Timesketch auth failed (login did not establish a session — the API returned the login page)",
        check.status, "auth",
      );
    }
  }

  // ---- sketches ------------------------------------------------------------

  // Find a sketch by EXACT (case-insensitive) name, paging through the caller's sketches. Returns
  // the first match or null.
  async findSketchByName(name: string): Promise<TimesketchSketchRef | null> {
    const target = name.trim().toLowerCase();
    for (let page = 1; page <= 50; page += 1) {
      const res = await this.send("GET", `${this.apiRoot}/sketches/?per_page=100&page=${page}`);
      if (!res.ok) throw await this.errorFor(res, "list sketches");
      const rows = objectList(await res.json().catch(() => ({})));
      const hit = rows.find((r) => String(r.name ?? "").trim().toLowerCase() === target);
      if (hit) return { id: Number(hit.id), name: String(hit.name ?? name) };
      if (rows.length < 100) break;
    }
    return null;
  }

  async createSketch(name: string, description: string): Promise<TimesketchSketchRef> {
    const res = await this.send("POST", `${this.apiRoot}/sketches/`, { json: { name, description } });
    if (!res.ok) throw await this.errorFor(res, "create sketch");
    const obj = firstObject(await res.json().catch(() => ({})));
    const id = Number(obj?.id);
    if (!Number.isFinite(id)) throw new TimesketchApiError("Timesketch create sketch: no sketch id in response", res.status, "http");
    return { id, name };
  }

  // ---- timelines -----------------------------------------------------------

  // The sketch's timelines (from the sketch detail). Used to clean-replace the managed timeline.
  async listTimelines(sketchId: number): Promise<TimesketchTimelineRef[]> {
    const res = await this.send("GET", `${this.apiRoot}/sketches/${sketchId}/`);
    if (!res.ok) throw await this.errorFor(res, "get sketch");
    const sketch = firstObject(await res.json().catch(() => ({})));
    const timelines = Array.isArray(sketch?.timelines) ? (sketch!.timelines as Array<Record<string, unknown>>) : [];
    return timelines.map((t) => ({ id: Number(t.id), name: String(t.name ?? "") }));
  }

  async deleteTimeline(sketchId: number, timelineId: number): Promise<void> {
    const res = await this.send("DELETE", `${this.apiRoot}/sketches/${sketchId}/timelines/${timelineId}/`);
    if (!res.ok && res.status !== 404) throw await this.errorFor(res, "delete timeline");
  }

  // ---- upload --------------------------------------------------------------

  // Upload events as an in-memory JSONL string (no file / no chunking — our forensic timelines are
  // well under the importer's 50k-record / 200MB thresholds). Creates a timeline named `timelineName`
  // in the sketch. POST multipart/form-data to /api/v1/upload/ with the `events` field.
  async uploadEvents(sketchId: number, timelineName: string, jsonl: string): Promise<void> {
    const form = new FormData();
    form.set("sketch_id", String(sketchId));
    form.set("name", timelineName.slice(0, 255));
    form.set("events", jsonl);
    form.set("provider", "DFIR Companion");
    form.set("context", "DFIR Companion forensic timeline");
    form.set("data_label", "dfir-companion");
    form.set("enable_stream", "false");
    const res = await this.send("POST", `${this.apiRoot}/upload/`, { body: form });
    if (!res.ok) throw await this.errorFor(res, "upload events");
  }
}
