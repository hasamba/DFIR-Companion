// Minimal typed write client for the MISP REST API.
// The read-side (enrichment) is in src/enrichment/misp.ts; this module provides
// the write path (create events, add attributes, tag) needed for case export.
// Like the other integration clients, the HTTP transport is an injectable fetchFn
// so the orchestrator can be unit-tested with no network.

import type { FetchFn } from "../../enrichment/provider.js";

export interface MispPushClientOptions {
  baseUrl: string;     // MISP instance, e.g. https://misp.example.org
  apiKey: string;      // MISP Auth Key (Authorization header)
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

export interface MispEventCreate {
  info: string;             // human-readable title (= case name)
  threat_level_id: string;  // "1"=High, "2"=Medium, "3"=Low, "4"=Undefined
  analysis: string;         // "0"=initial, "1"=ongoing, "2"=complete
  distribution: string;     // "0"=org, "1"=community, "2"=connected, "3"=all
  date?: string;            // YYYY-MM-DD
}

export interface MispAttrRef { type: string; value: string }

export interface MispAttrBody {
  type: string;
  value: string;
  category: string;
  to_ids: boolean;
  comment?: string;      // free-text annotation, separate from `value`
  first_seen?: string;   // ISO8601 — start of the attribute's validity/observation window
  last_seen?: string;    // ISO8601 — end of the window (native MISP attribute fields)
}

// Structural subset of MispPushClient used by the orchestrator — lets tests pass a mock.
export interface MispPushClientLike {
  ping(): Promise<void>;
  findEventByTag(tag: string): Promise<string | null>;
  createEvent(body: MispEventCreate): Promise<string>;
  addTagToEvent(eventId: string, tagName: string): Promise<void>;
  listAttributes(eventId: string): Promise<MispAttrRef[]>;
  addAttribute(eventId: string, body: MispAttrBody): Promise<void>;
}

class MispApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "MispApiError";
  }
}

// Flatten MISP's `errors` field, which is either a bare string ("Invalid Tag.") or a per-field map
// ({"value":["IP address has an invalid format."]}). Returns "" when there's nothing useful to say.
function flattenMispErrors(errors: unknown): string {
  if (typeof errors === "string") return errors.trim();
  if (Array.isArray(errors)) return errors.map((e) => flattenMispErrors(e)).filter(Boolean).join("; ");
  if (errors && typeof errors === "object") {
    return Object.entries(errors as Record<string, unknown>)
      .map(([field, msgs]) => {
        const text = flattenMispErrors(msgs);
        return text ? `${field}: ${text}` : "";
      })
      .filter(Boolean)
      .join("; ");
  }
  return "";
}

// Reason for a 2xx response that actually FAILED. MISP signals several write failures with
// HTTP 200 + `{"saved":false,...}` rather than an error status, so status alone can't be trusted.
function saveFailureReason(data: unknown): string {
  if (!data || typeof data !== "object") return "";
  const d = data as { saved?: unknown; errors?: unknown; message?: unknown; name?: unknown };
  if (d.saved !== false) return "";
  return flattenMispErrors(d.errors)
    || (typeof d.message === "string" && d.message.trim())
    || (typeof d.name === "string" && d.name.trim())
    || "MISP reported saved:false with no reason";
}

// MISP's own explanation for a rejected request, when the body carries one.
async function readErrorDetail(res: Response): Promise<string> {
  try {
    const body = await res.json() as { errors?: unknown; message?: unknown; name?: unknown };
    return flattenMispErrors(body.errors)
      || (typeof body.message === "string" && body.message.trim())
      || (typeof body.name === "string" && body.name.trim())
      || "";
  } catch {
    return "";   // non-JSON body (an HTML error page) — nothing to quote
  }
}

export class MispPushClient implements MispPushClientLike {
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;

  constructor(private readonly opts: MispPushClientOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  private headers(): Record<string, string> {
    return {
      Authorization: this.opts.apiKey,
      Accept: "application/json",
      "content-type": "application/json",
    };
  }

  private async req<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    let res: Response;
    try {
      res = await this.fetchFn(`${this.base}${path}`, {
        method,
        headers: this.headers(),
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new MispApiError(`MISP request failed: ${(err as Error).message}`, 0);
    }
    if (res.status === 401) throw new MispApiError("MISP auth failed — check DFIR_MISP_KEY", res.status);
    if (res.status === 403) {
      // A 403 here is NOT necessarily a permissions problem: MISP also returns 403 when it REJECTS
      // the payload (e.g. `{"errors":{"value":["IP address has an invalid format."]}}` for a value
      // like "10.10.20.15 (DC01)"). Blaming the API key sends the operator hunting through MISP roles
      // for a problem that doesn't exist — especially misleading when other attributes wrote fine
      // with the same key. Surface MISP's own reason when it gives one; only fall back to the
      // permissions hint when the body says nothing useful.
      const detail = await readErrorDetail(res);
      throw new MispApiError(
        detail
          ? `MISP rejected ${method} ${path}: ${detail}`
          : `MISP permission denied on ${method} ${path} — the API key needs write access (Site Admin or Org Admin role; read-only keys work for enrichment but cannot create events or attributes)`,
        res.status,
      );
    }
    if (!res.ok) throw new MispApiError(`MISP HTTP ${res.status} on ${path}`, res.status);
    const data = (await res.json()) as T;
    // MISP reports several write failures as HTTP 200 with the error IN THE BODY —
    // `{"saved":false,"errors":"Invalid Tag."}` is the common one. Treating that as success made
    // every addTag silently no-op while still being counted, which left the idempotency tag off the
    // event and broke re-push dedup entirely (every push created a duplicate event). Any 2xx whose
    // body says `saved:false` is a failure.
    const failure = saveFailureReason(data);
    if (failure) throw new MispApiError(`MISP rejected ${method} ${path}: ${failure}`, res.status);
    return data;
  }

  async ping(): Promise<void> {
    await this.req<unknown>("GET", "/servers/getVersion");
  }

  // Search events by tag to find a prior push's event. Returns the event id or null.
  // Auth errors (401/403) propagate — only network/parse failures fall back to empty.
  //
  // Uses POST /events/restSearch, NOT GET /events/index?searchTag=. Verified against a live MISP:
  // /events/index IGNORES both `searchTag` and `limit` (it returned the entire 8800-event index) and
  // returns events FLAT — so reading `[0].Event.id` was always undefined. The net effect was that a
  // prior event could never be found, and every push created a duplicate event carrying a full
  // duplicate copy of the timeline. restSearch honours the tag filter and wraps each hit in `Event`.
  async findEventByTag(tag: string): Promise<string | null> {
    const body = await this.req<{ response?: Array<{ Event?: { id?: string } }> }>(
      "POST", "/events/restSearch", { returnFormat: "json", tags: [tag], limit: 1 },
    ).catch((err: unknown) => {
      if (err instanceof MispApiError && (err.status === 401 || err.status === 403)) throw err;
      return {} as { response?: Array<{ Event?: { id?: string } }> };
    });
    // Tolerate either wrapping — restSearch returns {response:[{Event:{...}}]}, but be lenient in
    // case a MISP version hands back the flat array instead.
    const hits = Array.isArray(body) ? body as Array<{ Event?: { id?: string }; id?: string }> : (body.response ?? []);
    const first = hits[0] as { Event?: { id?: string }; id?: string } | undefined;
    const id = first?.Event?.id ?? first?.id;
    return id ? String(id) : null;
  }

  async createEvent(body: MispEventCreate): Promise<string> {
    const data = await this.req<{ Event?: { id?: string } }>("POST", "/events/add", { Event: body });
    const id = data.Event?.id;
    if (!id) throw new MispApiError("MISP event create returned no id", 0);
    return String(id);
  }

  // Attach a tag, creating it first if the instance doesn't already know it.
  //
  // /events/addTag does NOT auto-create tags: against a live MISP it answers HTTP 200 with
  // `{"saved":false,"errors":"Invalid Tag."}` for an unknown name. That 200 used to read as success,
  // so every tag silently no-opped while still being counted — including the per-case idempotency
  // tag that re-push dedup keys on, which is why each push created a duplicate event. Creating the
  // tag first makes the attach succeed; /tags/add on an existing tag is a harmless no-op, so this
  // stays idempotent.
  async addTagToEvent(eventId: string, tagName: string): Promise<void> {
    try {
      await this.req<unknown>("POST", "/tags/add", { name: tagName });
    } catch {
      // Already exists (or this key can't manage the taxonomy) — let the attach below be the
      // authoritative check, so a genuine failure still surfaces with MISP's own reason.
    }
    await this.req<unknown>("POST", "/events/addTag", { event: eventId, tag: tagName, local: false });
  }

  // List existing attributes from the event (for dedupe on re-push).
  // Auth errors propagate; other failures fall back to empty (dedupe fails gracefully).
  async listAttributes(eventId: string): Promise<MispAttrRef[]> {
    const data = await this.req<{ Event?: { Attribute?: Array<{ type?: string; value?: string }> } }>(
      "GET", `/events/view/${encodeURIComponent(eventId)}`,
    ).catch((err: unknown) => {
      if (err instanceof MispApiError && (err.status === 401 || err.status === 403)) throw err;
      return { Event: { Attribute: [] as Array<{ type?: string; value?: string }> } };
    });
    return (data.Event?.Attribute ?? []).map((a) => ({ type: a.type ?? "", value: a.value ?? "" }));
  }

  async addAttribute(eventId: string, body: MispAttrBody): Promise<void> {
    await this.req<unknown>("POST", `/attributes/add/${encodeURIComponent(eventId)}`, body);
  }
}
