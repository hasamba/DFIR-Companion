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
import {
  readBoundedJson,
  readBoundedText,
  RESPONSE_SIZE_LIMITS,
  rethrowIfTooLarge,
} from "../../providers/boundedResponse.js";
import { describeFetchError, serverSetFetchError } from "../tlsTrustHint.js";

export interface TimesketchClientOptions {
  baseUrl: string; // e.g. https://timesketch.example.org
  username: string; // local-auth username
  password: string; // local-auth password
  fetchFn?: FetchFn; // injectable transport (tests pass a mock; TLS-custom in prod)
  timeoutMs?: number; // per-request timeout (default 60s — uploads can be larger)
}

export interface TimesketchSketchRef {
  id: number;
  name: string;
}
export interface TimesketchTimelineRef {
  id: number;
  name: string;
}

export class TimesketchApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly kind: "auth" | "notfound" | "http" | "network",
  ) {
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

export { describeFetchError };

interface SendOptions {
  body?: BodyInit;
  json?: unknown;
  redirect?: RequestRedirect;
  sendCsrf?: boolean; // default true — attach the x-csrftoken header
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
    const headers: Record<string, string> = {
      Accept: "application/json, text/html",
      Referer: `${this.base}/`,
    };
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
      });
    } catch (err) {
      // serverSetFetchError keeps the cause chain, but a rejected certificate gets the set's CA
      // bundle instead of Node's --use-system-ca advice. This client is built from a server set only.
      throw new TimesketchApiError(
        `Timesketch request failed: ${serverSetFetchError(err, "Timesketch")}`,
        0,
        "network",
      );
    }
    this.ingestCookies(res);
    return res;
  }

  private async errorFor(res: Response, what: string): Promise<TimesketchApiError> {
    let detail = `HTTP ${res.status}`;
    const text = await readBoundedText(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.text,
      context: "Timesketch",
    }).catch(() => "");
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
    this.csrf = scrapeCsrfToken(
      await readBoundedText(page, { maxBytes: RESPONSE_SIZE_LIMITS.text, context: "Timesketch" }).catch(
        () => "",
      ),
    );
    if (!this.csrf) {
      throw new TimesketchApiError(
        "Timesketch login: no CSRF token on the login page (check the Timesketch URL in this server set and that local auth is enabled)",
        page.status,
        "auth",
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
      throw new TimesketchApiError(
        "Timesketch auth failed (check the Timesketch username and password in this server set)",
        check.status,
        "auth",
      );
    }
    if (!check.ok) throw await this.errorFor(check, "login check");
    if (!(check.headers.get("content-type") ?? "").includes("application/json")) {
      throw new TimesketchApiError(
        "Timesketch auth failed (login did not establish a session — the API returned the login page)",
        check.status,
        "auth",
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
      const rows = objectList(
        await readBoundedJson(res, { maxBytes: RESPONSE_SIZE_LIMITS.json, context: "Timesketch" }).catch(
          (err) => rethrowIfTooLarge(err, {}),
        ),
      );
      const hit = rows.find(
        (r) =>
          String(r.name ?? "")
            .trim()
            .toLowerCase() === target,
      );
      if (hit) return { id: Number(hit.id), name: String(hit.name ?? name) };
      if (rows.length < 100) break;
    }
    return null;
  }

  async createSketch(name: string, description: string): Promise<TimesketchSketchRef> {
    const res = await this.send("POST", `${this.apiRoot}/sketches/`, { json: { name, description } });
    if (!res.ok) throw await this.errorFor(res, "create sketch");
    const obj = firstObject(
      await readBoundedJson(res, { maxBytes: RESPONSE_SIZE_LIMITS.json, context: "Timesketch" }).catch(
        (err) => rethrowIfTooLarge(err, {}),
      ),
    );
    const id = Number(obj?.id);
    if (!Number.isFinite(id))
      throw new TimesketchApiError("Timesketch create sketch: no sketch id in response", res.status, "http");
    return { id, name };
  }

  // ---- timelines -----------------------------------------------------------

  // The sketch's timelines (from the sketch detail). Used to clean-replace the managed timeline.
  async listTimelines(sketchId: number): Promise<TimesketchTimelineRef[]> {
    const res = await this.send("GET", `${this.apiRoot}/sketches/${sketchId}/`);
    if (!res.ok) throw await this.errorFor(res, "get sketch");
    const sketch = firstObject(
      await readBoundedJson(res, { maxBytes: RESPONSE_SIZE_LIMITS.json, context: "Timesketch" }).catch(
        (err) => rethrowIfTooLarge(err, {}),
      ),
    );
    const timelines = Array.isArray(sketch?.timelines)
      ? (sketch.timelines as Array<Record<string, unknown>>)
      : [];
    return timelines.map((t) => ({ id: Number(t.id), name: String(t.name ?? "") }));
  }

  async deleteTimeline(sketchId: number, timelineId: number): Promise<void> {
    const res = await this.send("DELETE", `${this.apiRoot}/sketches/${sketchId}/timelines/${timelineId}/`);
    if (!res.ok && res.status !== 404) throw await this.errorFor(res, "delete timeline");
  }

  // ---- upload --------------------------------------------------------------

  // Upload events as an in-memory JSONL string (no file / no chunking — our forensic timelines are
  // well under the importer's 50k-record / 200MB thresholds). Creates a timeline named `timelineName`
  // in the sketch. The upload resource reads every field from `request.form`, so we send
  // application/x-www-form-urlencoded (URLSearchParams) — exactly what the official Python importer
  // does for the no-file path (`requests.post(..., data=dict)`). A multipart/form-data body is
  // mishandled by some Timesketch deployments (proxy/WSGI), which then see no fields and abort with
  // "Unable to upload data without supplying a sketch to associate it with".
  //
  // Returns the created timeline's id and colour from the 201 body (Timesketch answers with the
  // timeline object) — the upload-first swap (#2414) renames that timeline afterwards. The upload
  // already succeeded when the body is unreadable, so that is not an error: the caller falls back to
  // finding the timeline by name.
  async uploadEvents(
    sketchId: number,
    timelineName: string,
    jsonl: string,
    opts: { dataLabel?: string } = {},
  ): Promise<UploadedTimeline> {
    const res = await this.send("POST", `${this.apiRoot}/upload/`, {
      body: uploadForm(sketchId, timelineName, jsonl, { last: true, dataLabel: opts.dataLabel }),
    });
    if (!res.ok) throw await this.errorFor(res, "upload events");
    const body = await readBoundedJson(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: "Timesketch",
    }).catch(() => undefined);
    return uploadedTimeline(firstObject(body));
  }

  // Rename a timeline in place (#2414 — the last step of the upload-first swap). Upstream
  // TimelineResource.post validates TimelineForm built from the JSON body plus the X-CSRFToken
  // header: `name` (required, ≤255), `description`, and `color` (required, exactly 6 hex digits —
  // no "#"). The colour is the one the upload reported, else read from the sketch detail (not the
  // timeline GET, which runs a datastore count that can fail while the index is still being built),
  // else white. The description is set to the new name, as the upload itself does on create.
  async renameTimeline(
    sketchId: number,
    timelineId: number,
    name: string,
    opts: { color?: string } = {},
  ): Promise<void> {
    const color =
      normalizeColor(opts.color) ??
      (await this.timelineColor(sketchId, timelineId)) ??
      DEFAULT_TIMELINE_COLOR;
    const finalName = name.slice(0, 255);
    const res = await this.send("POST", `${this.apiRoot}/sketches/${sketchId}/timelines/${timelineId}/`, {
      json: { name: finalName, description: finalName, color },
    });
    if (!res.ok) throw await this.errorFor(res, "rename timeline");
  }

  private async timelineColor(sketchId: number, timelineId: number): Promise<string | undefined> {
    const res = await this.send("GET", `${this.apiRoot}/sketches/${sketchId}/`);
    if (!res.ok) return undefined; // the rename still goes ahead with the default colour
    const sketch = firstObject(
      await readBoundedJson(res, { maxBytes: RESPONSE_SIZE_LIMITS.json, context: "Timesketch" }).catch(
        (err) => rethrowIfTooLarge(err, {}),
      ),
    );
    const timelines = Array.isArray(sketch?.timelines)
      ? (sketch.timelines as Array<Record<string, unknown>>)
      : [];
    return normalizeColor(timelines.find((t) => Number(t.id) === timelineId)?.color);
  }

  // One chunk of a streamed upload (#1444) — the official importer's own protocol: every chunk but
  // the last sends `enable_stream=true`, every chunk after the first sends back the `index_name`
  // the first one opened, and the last chunk (`enable_stream=false`, possibly empty) closes the
  // stream so Timesketch indexes the timeline. Same form encoding as uploadEvents, same reason.
  async uploadEventsChunk(
    sketchId: number,
    timelineName: string,
    jsonl: string,
    chunk: { indexName?: string; last: boolean; dataLabel?: string },
  ): Promise<UploadedTimeline & { indexName: string }> {
    const res = await this.send("POST", `${this.apiRoot}/upload/`, {
      body: uploadForm(sketchId, timelineName, jsonl, chunk),
    });
    if (!res.ok) throw await this.errorFor(res, "upload events (chunk)");
    const obj = firstObject(
      await readBoundedJson(res, { maxBytes: RESPONSE_SIZE_LIMITS.json, context: "Timesketch" }).catch(
        (err) => rethrowIfTooLarge(err, {}),
      ),
    );
    const searchindex = obj?.searchindex as Record<string, unknown> | undefined;
    const indexName = typeof searchindex?.index_name === "string" ? searchindex.index_name : chunk.indexName;
    if (!indexName)
      throw new TimesketchApiError(
        "Timesketch upload: no index name in the first chunk's response",
        res.status,
        "http",
      );
    return { ...uploadedTimeline(obj), indexName };
  }
}

export interface UploadedTimeline {
  timelineId?: number;
  color?: string;
}

const DEFAULT_TIMELINE_COLOR = "FFFFFF";
// The default upload label. The push passes its own unique label instead (#2414): Timesketch reuses
// any sketch index that carries the label, so a shared one appends into the old timeline's index.
const DEFAULT_DATA_LABEL = "dfir-companion";

function normalizeColor(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const hex = value.trim().replace(/^#/, "");
  return /^[0-9a-fA-F]{6}$/.test(hex) ? hex : undefined;
}

function uploadedTimeline(obj: Record<string, unknown> | undefined): UploadedTimeline {
  const id = Number(obj?.id);
  return {
    timelineId: Number.isInteger(id) && id > 0 ? id : undefined,
    color: normalizeColor(obj?.color),
  };
}

function uploadForm(
  sketchId: number,
  timelineName: string,
  jsonl: string,
  chunk: { indexName?: string; last: boolean; dataLabel?: string },
): URLSearchParams {
  const form = new URLSearchParams();
  form.set("sketch_id", String(sketchId));
  form.set("name", timelineName.slice(0, 255));
  form.set("events", jsonl);
  form.set("provider", "DFIR Companion");
  form.set("context", "DFIR Companion forensic timeline");
  form.set("data_label", chunk.dataLabel ?? DEFAULT_DATA_LABEL);
  form.set("enable_stream", chunk.last ? "false" : "true");
  if (chunk.indexName) form.set("index_name", chunk.indexName);
  return form;
}
