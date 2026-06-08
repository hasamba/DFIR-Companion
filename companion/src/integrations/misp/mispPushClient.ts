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
    if (res.status === 401 || res.status === 403) throw new MispApiError("MISP auth failed (check DFIR_MISP_KEY)", res.status);
    if (!res.ok) throw new MispApiError(`MISP HTTP ${res.status} on ${path}`, res.status);
    return (await res.json()) as T;
  }

  async ping(): Promise<void> {
    await this.req<unknown>("GET", "/servers/getVersion");
  }

  // Search events by tag to find a prior push's event. Returns the event id or null.
  async findEventByTag(tag: string): Promise<string | null> {
    const events = await this.req<Array<{ Event?: { id?: string } }>>(
      "GET", `/events/index?searchTag=${encodeURIComponent(tag)}&limit=1`,
    ).catch(() => [] as Array<{ Event?: { id?: string } }>);
    const id = events[0]?.Event?.id;
    return id ? String(id) : null;
  }

  async createEvent(body: MispEventCreate): Promise<string> {
    const data = await this.req<{ Event?: { id?: string } }>("POST", "/events/add", { Event: body });
    const id = data.Event?.id;
    if (!id) throw new MispApiError("MISP event create returned no id", 0);
    return String(id);
  }

  async addTagToEvent(eventId: string, tagName: string): Promise<void> {
    await this.req<unknown>("POST", "/events/addTag", { event: eventId, tag: tagName, local: false });
  }

  // List existing attributes from the event (for dedupe on re-push).
  async listAttributes(eventId: string): Promise<MispAttrRef[]> {
    const data = await this.req<{ Event?: { Attribute?: Array<{ type?: string; value?: string }> } }>(
      "GET", `/events/view/${encodeURIComponent(eventId)}`,
    ).catch(() => ({ Event: { Attribute: [] as Array<{ type?: string; value?: string }> } }));
    return (data.Event?.Attribute ?? []).map((a) => ({ type: a.type ?? "", value: a.value ?? "" }));
  }

  async addAttribute(eventId: string, body: MispAttrBody): Promise<void> {
    await this.req<unknown>("POST", `/attributes/add/${encodeURIComponent(eventId)}`, body);
  }
}
