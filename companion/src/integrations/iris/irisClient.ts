// Minimal typed client for the DFIR-IRIS REST API (v1 "legacy" endpoints — the generation
// that covers cases, assets, IOCs, timeline, notes AND summary; the newer /api/v2 surface
// does not yet expose timeline/notes/summary). Auth is an API key sent as a Bearer token.
// Case-scoped calls take a `cid` query param (and most also expect it in the body). Responses
// use the envelope { status: "success"|"error", data, message }.
//
// Like the enrichment/AI providers, the HTTP transport is an injectable `fetchFn` so the
// orchestrator and mappers can be unit-tested with no network, and a custom TLS trust can be
// supplied for a self-hosted IRIS with an internal-CA / self-signed cert.

import type { FetchFn } from "../../enrichment/provider.js";

export interface IrisClientOptions {
  baseUrl: string;          // e.g. https://iris.example.org
  apiKey: string;           // IRIS API key (My profile > API Key)
  fetchFn?: FetchFn;        // injectable transport (tests pass a mock; TLS-custom in prod)
  timeoutMs?: number;       // per-request timeout (default 30s)
}

// Subset of the IRIS case/asset/ioc objects we read back.
export interface IrisCaseRef { caseId: number; caseName: string }
export interface IrisAssetRef { id: number; name: string }
export interface IrisIocRef { id: number; value: string }
export interface IrisEventRef { id: number; title: string; date: string }
export interface IrisDirRef { id: number; name: string }
export interface IrisTaskRef { id: number; title: string }

export interface IrisCaseCreate {
  case_name: string;
  case_description: string;
  case_customer: number;        // customer id (default seeded customer = 1)
  classification_id: number;    // case classification id (default 1)
  case_soc_id: string;          // may be ""
}

// Bodies are intentionally loose (Record) — the mappers build them and the client just
// forwards, injecting `cid` where the v1 API needs it duplicated in the body.
export type IrisAssetBody = Record<string, unknown>;
export type IrisIocBody = Record<string, unknown>;
export type IrisEventBody = Record<string, unknown>;
export type IrisTaskBody = Record<string, unknown>;

interface Envelope<T = unknown> { status?: string; message?: string; data?: T }

export class IrisApiError extends Error {
  constructor(message: string, readonly status: number, readonly kind: "auth" | "permission" | "notfound" | "http" | "api") {
    super(message);
    this.name = "IrisApiError";
  }
}

export class IrisClient {
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;

  constructor(private readonly opts: IrisClientOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  // ---- transport -----------------------------------------------------------

  private async request<T>(method: "GET" | "POST", path: string, opts: { cid?: number; body?: unknown } = {}): Promise<T> {
    const url = new URL(this.base + path);
    if (opts.cid !== undefined) url.searchParams.set("cid", String(opts.cid));
    let res: Response;
    try {
      res = await this.fetchFn(url.toString(), {
        method,
        headers: {
          Authorization: `Bearer ${this.opts.apiKey}`,
          Accept: "application/json",
          ...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new IrisApiError(`IRIS request failed: ${(err as Error).message}`, 0, "http");
    }
    if (res.status === 401) throw new IrisApiError("IRIS auth failed (check DFIR_IRIS_KEY)", 401, "auth");
    if (res.status === 403) throw new IrisApiError("IRIS permission denied for this API key", 403, "permission");
    if (res.status === 404) throw new IrisApiError(`IRIS endpoint not found: ${path}`, 404, "notfound");
    if (!res.ok) throw new IrisApiError(`IRIS HTTP ${res.status} on ${path}`, res.status, "http");

    const json = (await res.json().catch(() => ({}))) as Envelope<T>;
    if (json.status && json.status !== "success") {
      throw new IrisApiError(`IRIS error on ${path}: ${json.message ?? "unknown"}`, res.status, "api");
    }
    return (json.data ?? (json as unknown)) as T;
  }

  // ---- connectivity --------------------------------------------------------

  async ping(): Promise<void> {
    await this.request<unknown>("GET", "/api/ping", { cid: 1 });
  }

  // ---- cases ---------------------------------------------------------------

  // Find a case by EXACT name (the filter does a substring match server-side, so we
  // narrow to an exact, case-insensitive match here). Returns the first match or null.
  async findCaseByName(name: string): Promise<IrisCaseRef | null> {
    const data = await this.request<{ cases?: Array<Record<string, unknown>> }>(
      "GET", `/manage/cases/filter?case_name=${encodeURIComponent(name)}`,
    );
    const cases = data.cases ?? [];
    const exact = cases.find((c) => String(c.case_name ?? "").toLowerCase() === name.toLowerCase()) ?? cases[0];
    if (!exact) return null;
    return { caseId: Number(exact.case_id), caseName: String(exact.case_name ?? name) };
  }

  async createCase(body: IrisCaseCreate): Promise<IrisCaseRef> {
    const data = await this.request<Record<string, unknown>>("POST", "/manage/cases/add", { body });
    const id = Number(data.case_id ?? (data as { case?: { case_id?: number } }).case?.case_id);
    return { caseId: id, caseName: body.case_name };
  }

  // The collaborative case summary (distinct from case_description metadata). Replaces the
  // whole summary — intended for seeding an exported case.
  async setSummary(caseId: number, markdown: string): Promise<void> {
    await this.request<unknown>("POST", "/case/summary/update", { body: { case_description: markdown, cid: caseId } });
  }

  // ---- type-id resolution (resolve names→ids at runtime; ids vary by install) ----

  async iocTypeMap(): Promise<Map<string, number>> {
    const rows = await this.request<Array<Record<string, unknown>>>("GET", "/manage/ioc-types/list", { cid: 1 });
    const m = new Map<string, number>();
    for (const r of rows ?? []) m.set(String(r.type_name ?? "").toLowerCase(), Number(r.type_id));
    return m;
  }

  async assetTypeMap(): Promise<Map<string, number>> {
    const rows = await this.request<Array<Record<string, unknown>>>("GET", "/manage/asset-type/list");
    const m = new Map<string, number>();
    for (const r of rows ?? []) m.set(String(r.asset_name ?? "").toLowerCase(), Number(r.asset_id));
    return m;
  }

  // Timeline event categories (MITRE tactics) — name (lowercased) → id, for auto-categorizing events.
  async eventCategoryMap(): Promise<Map<string, number>> {
    const rows = await this.request<Array<Record<string, unknown>>>("GET", "/manage/event-categories/list");
    const m = new Map<string, number>();
    for (const r of rows ?? []) m.set(String(r.name ?? "").toLowerCase(), Number(r.id));
    return m;
  }

  // Task statuses — status_name (lowercased) → id (1 = "To do" on a stock install).
  async taskStatusMap(): Promise<Map<string, number>> {
    const rows = await this.request<Array<Record<string, unknown>>>("GET", "/manage/task-status/list");
    const m = new Map<string, number>();
    for (const r of rows ?? []) m.set(String(r.status_name ?? "").toLowerCase(), Number(r.id));
    return m;
  }

  // ---- assets --------------------------------------------------------------

  async listAssets(cid: number): Promise<IrisAssetRef[]> {
    const data = await this.request<{ assets?: Array<Record<string, unknown>> } | Array<Record<string, unknown>>>(
      "GET", "/case/assets/list", { cid },
    );
    const rows = Array.isArray(data) ? data : data.assets ?? [];
    return rows.map((r) => ({ id: Number(r.asset_id), name: String(r.asset_name ?? "") }));
  }

  async addAsset(cid: number, body: IrisAssetBody): Promise<number> {
    const data = await this.request<Record<string, unknown>>("POST", "/case/assets/add", { cid, body: { ...body, cid } });
    return Number(data.asset_id);
  }

  // ---- iocs ----------------------------------------------------------------

  async listIocs(cid: number): Promise<IrisIocRef[]> {
    const data = await this.request<{ ioc?: Array<Record<string, unknown>> } | Array<Record<string, unknown>>>(
      "GET", "/case/ioc/list", { cid },
    );
    const rows = Array.isArray(data) ? data : data.ioc ?? [];
    return rows.map((r) => ({ id: Number(r.ioc_id), value: String(r.ioc_value ?? "") }));
  }

  async addIoc(cid: number, body: IrisIocBody): Promise<number> {
    const data = await this.request<Record<string, unknown>>("POST", "/case/ioc/add", { cid, body: { ...body, cid } });
    return Number(data.ioc_id);
  }

  // ---- timeline ------------------------------------------------------------

  async addEvent(cid: number, body: IrisEventBody): Promise<number> {
    const data = await this.request<Record<string, unknown>>("POST", "/case/timeline/events/add", { cid, body: { ...body, cid } });
    return Number(data.event_id);
  }

  // Best-effort listing of existing events for dedupe. Tolerant of envelope shape; callers
  // should catch errors and proceed (older IRIS may not expose a plain list endpoint).
  async listEvents(cid: number): Promise<IrisEventRef[]> {
    const data = await this.request<{ timeline?: Array<Record<string, unknown>> } | Array<Record<string, unknown>>>(
      "GET", "/case/timeline/events", { cid },
    );
    const rows = Array.isArray(data) ? data : data.timeline ?? [];
    return rows.map((r) => ({ id: Number(r.event_id), title: String(r.event_title ?? ""), date: String(r.event_date ?? "") }));
  }

  // ---- tasks ---------------------------------------------------------------

  async listTasks(cid: number): Promise<IrisTaskRef[]> {
    const data = await this.request<{ tasks?: Array<Record<string, unknown>> } | Array<Record<string, unknown>>>(
      "GET", "/case/tasks/list", { cid },
    );
    const rows = Array.isArray(data) ? data : data.tasks ?? [];
    return rows.map((r) => ({ id: Number(r.task_id), title: String(r.task_title ?? "") }));
  }

  // Add a task. The v1 endpoint requires the `task_assignees_id` KEY to be present, but an empty
  // array is accepted (creates an unassigned task) — so no real user id is needed.
  async addTask(cid: number, body: IrisTaskBody): Promise<number> {
    const data = await this.request<Record<string, unknown>>("POST", "/case/tasks/add", {
      cid, body: { task_assignees_id: [], custom_attributes: {}, ...body, cid },
    });
    return Number(data.task_id);
  }

  // ---- notes (directories are the current API; groups were removed at 2.0.1) ----

  async listDirectories(cid: number): Promise<IrisDirRef[]> {
    const data = await this.request<Array<Record<string, unknown>> | { directories?: Array<Record<string, unknown>> }>(
      "GET", "/case/notes/directories/filter", { cid },
    );
    const rows = Array.isArray(data) ? data : data.directories ?? [];
    return rows.map((r) => ({ id: Number(r.id), name: String(r.name ?? "") }));
  }

  async addDirectory(cid: number, name: string): Promise<number> {
    const data = await this.request<Record<string, unknown>>("POST", "/case/notes/directories/add", { cid, body: { name } });
    return Number(data.id);
  }

  // Deleting a directory removes all notes inside it — used to cleanly replace the
  // Companion-managed notes on re-export (so notes always reflect current state, no dupes).
  async deleteDirectory(cid: number, directoryId: number): Promise<void> {
    await this.request<unknown>("POST", `/case/notes/directories/delete/${directoryId}`, { cid });
  }

  // Find-or-create a top-level notes directory by name, returning its id.
  async ensureDirectory(cid: number, name: string): Promise<number> {
    const existing = (await this.listDirectories(cid)).find((d) => d.name === name);
    return existing ? existing.id : this.addDirectory(cid, name);
  }

  async addNote(cid: number, directoryId: number, title: string, content: string): Promise<number> {
    const data = await this.request<Record<string, unknown>>("POST", "/case/notes/add", {
      cid, body: { note_title: title, note_content: content, directory_id: directoryId },
    });
    return Number(data.note_id ?? (data as { id?: number }).id);
  }
}
