import type {
  DetailedLookup,
  EnrichmentProvider,
  EnrichmentResult,
  FetchFn,
  IocKind,
  Verdict,
} from "./provider.js";
import {
  MISP_PING_PATH,
  mispPingStatusMessage,
  mispTransportMessage,
} from "../integrations/misp/mispConnectivity.js";
import { readBoundedJson, RESPONSE_SIZE_LIMITS } from "../providers/boundedResponse.js";
import { boundOrigins } from "../analysis/intelLineage.js";

export interface MispOptions {
  baseUrl: string; // your MISP instance, e.g. https://misp.example.org
  apiKey: string; // MISP Auth Key (Authorization header)
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

interface MispEvent {
  id?: string;
  uuid?: string;
  info?: string;
  threat_level_id?: string;
  orgc_id?: string; // creator org id — always present on an event
  Orgc?: { id?: string; name?: string }; // the resolved creator org, returned with includeContext
  date?: string; // when the event OCCURRED (date-only) — the event's stated date, not an observation
  publish_timestamp?: string | number; // when the event was published (epoch seconds)
}
interface MispTag {
  name?: string;
}
interface MispAttribute {
  id?: string;
  uuid?: string;
  type?: string;
  value?: string;
  category?: string;
  to_ids?: boolean;
  deleted?: boolean; // a soft-deleted attribute: the provider withdrew it — revoked, kept as history
  timestamp?: string | number; // creation or last edit of the record (epoch seconds) — not an observation
  first_seen?: string | null; // ISO 8601 with zone, microseconds possible — an observation
  last_seen?: string | null;
  event_id?: string;
  Event?: MispEvent;
  Tag?: MispTag[];
}

/** Pagination (#1024): read every page up to the bound; a full last page means the read is INCOMPLETE. */
const PAGE_SIZE = 100;
const PAGES_MAX = 64;
/** One assertion per attribute, bounded; the rest are counted on the last one. */
const ASSERTIONS_MAX = 32;
const epochIso = (v: string | number | undefined): string => {
  const n = typeof v === "number" ? v : /^\d+$/.test(String(v ?? "")) ? Number(v) : NaN;
  return Number.isFinite(n) && n > 0 ? new Date(n * 1000).toISOString() : "";
};

// MISP threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined.
function verdictFor(attrs: MispAttribute[]): Verdict {
  if (attrs.length === 0) return "unknown";
  const high = attrs.some((a) => a.to_ids === true || a.Event?.threat_level_id === "1");
  return high ? "malicious" : "suspicious"; // present in MISP = at least suspicious
}

// Who created the event, as the record states it: the resolved org name when includeContext returned
// one, else the bare org id (an identity on this instance, nameless), else nothing. The event's `info`
// and tags are free text about the SUBJECT and are never read as a source.
function creatorOf(ev: MispEvent): string {
  const name = typeof ev.Orgc?.name === "string" ? ev.Orgc.name.trim() : "";
  if (name) return name;
  const id = ev.Orgc?.id ?? ev.orgc_id;
  return id !== undefined && id !== null && String(id).trim() ? `org #${String(id).trim()}` : "";
}

// MISP (Malware Information Sharing Platform). Searches your instance's attributes for
// the indicator value; a hit means the IOC is known threat intel shared on that instance.
export class MispProvider implements EnrichmentProvider {
  readonly name = "MISP";
  readonly scope = "local" as const; // your own instance — OPSEC-safe
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  constructor(private readonly opts: MispOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = opts.baseUrl.replace(/\/+$/, "");
  }

  supports(kind: IocKind): boolean {
    return kind !== "process";
  } // attribute values: hash/ip/domain/url (not bare process names)

  // Cheap reachability + auth check: GET /servers/getVersion (a tiny authenticated endpoint),
  // so we never blast a down instance with one restSearch per IOC. A dead server (connection
  // refused / TLS error) rejects the fetch; a bad key → 401/403. Throws on any of these.
  //
  // This message becomes the `detail` on the /system health card and the reason the provider is
  // skipped, so it has to be diagnosable on its own: name the URL, and the setting at fault when
  // the evidence supports one (#179 — shared with the push-side ping, same endpoint).
  async probe(): Promise<void> {
    const url = `${this.base}${MISP_PING_PATH}`;
    let res: Response;
    try {
      res = await this.fetchFn(url, {
        method: "GET",
        headers: { Authorization: this.opts.apiKey, Accept: "application/json" },
        signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
      });
    } catch (err) {
      throw new Error(mispTransportMessage(err, url));
    }
    if (res.status === 401 || res.status === 403) throw new Error("MISP auth failed (check DFIR_MISP_KEY)");
    if (!res.ok) throw new Error(mispPingStatusMessage(res.status, url));
  }

  /** One page of restSearch; deleted attributes included so a withdrawal is read, not silently absent. */
  private async page(value: string, page: number): Promise<MispAttribute[]> {
    const res = await this.fetchFn(`${this.base}/attributes/restSearch`, {
      method: "POST",
      headers: {
        Authorization: this.opts.apiKey,
        Accept: "application/json",
        "content-type": "application/json",
      },
      // includeContext: the event's creator organisation (Orgc) comes back with each attribute, so
      // the record can say who made the claim (#933 item 18) — MISP RELAYS; it is not the origin.
      // deleted: [0, 1] returns soft-deleted attributes too (#1024): a deletion is a revocation to
      // record, never an absence. Ordered by id so pages are stable across reads.
      body: JSON.stringify({
        returnFormat: "json",
        value,
        limit: PAGE_SIZE,
        page,
        deleted: [0, 1],
        includeEventTags: true,
        includeContext: true,
      }),
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 401 || res.status === 403) throw new Error("MISP auth failed (check DFIR_MISP_KEY)");
    if (!res.ok) throw new Error(`MISP HTTP ${res.status}`);
    const json = await readBoundedJson<{
      response?: { Attribute?: MispAttribute[] };
    }>(res, { maxBytes: RESPONSE_SIZE_LIMITS.json, context: "MISP" });
    return json.response?.Attribute ?? [];
  }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult[] | null> {
    const { results } = await this.lookupDetailed(kind, value);
    return results.length ? results : null;
  }

  /**
   * Every attribute matching the value, across pages (#1024): one assertion per attribute with
   * its own uuid, its observation interval (`first_seen` / `last_seen`, kept apart — never one
   * span across attributes), the record's edit time, the event's stated date and publication,
   * and `deleted` as a revocation. A read cut by the page bound is INCOMPLETE: no absence may be
   * concluded from it.
   */
  async lookupDetailed(_kind: IocKind, value: string): Promise<DetailedLookup> {
    const attrs: MispAttribute[] = [];
    let incomplete = false;
    for (let p = 1; p <= PAGES_MAX; p += 1) {
      const page = await this.page(value, p);
      attrs.push(...page);
      if (page.length < PAGE_SIZE) break;
      if (p === PAGES_MAX) incomplete = true;
    }
    if (attrs.length === 0) return { results: [], backends: [{ name: this.name, outcome: "miss" }] };

    const events = new Map<string, MispEvent>();
    const tags = new Set<string>();
    attrs.forEach((a, i) => {
      const ev = a.Event;
      // Keyed by the event id from either place; an attribute whose Event object lacks an id still
      // carries its creator, so it gets its own slot rather than being dropped.
      if (ev) events.set(ev.id ?? a.event_id ?? `#${i}`, ev);
      for (const t of a.Tag ?? []) if (t.name) tags.add(t.name);
    });
    const lineage = { originKind: "relay" as const, ...boundOrigins([...events.values()].map(creatorOf)) };
    const shown = attrs.slice(0, ASSERTIONS_MAX);
    const beyond = attrs.length - shown.length;
    const results: EnrichmentResult[] = shown.map((a, i) => {
      const ev = a.Event;
      const eventId = ev?.id ?? a.event_id;
      const temporal = {
        ...(a.first_seen ? { observedFrom: a.first_seen } : {}),
        ...(a.last_seen ? { observedTo: a.last_seen } : {}),
        ...(epochIso(a.timestamp) ? { recordEditedAt: epochIso(a.timestamp) } : {}),
        ...(ev?.date ? { eventDate: ev.date } : {}),
        ...(epochIso(ev?.publish_timestamp) ? { publishedAt: epochIso(ev?.publish_timestamp) } : {}),
        ...(incomplete ? { truncated: true } : {}),
      };
      const own = [
        `${a.type ?? "attribute"}${a.category ? ` (${a.category})` : ""}`,
        a.to_ids ? "to_ids" : "",
        ev?.info ? `event: ${ev.info.slice(0, 80)}` : eventId ? `event ${eventId}` : "",
        a.deleted ? "deleted on the MISP instance; kept as history" : "",
        i === shown.length - 1 && beyond ? `+${beyond} more attribute(s) not listed` : "",
      ].filter(Boolean);
      return {
        source: this.name,
        ...lineage,
        verdict: verdictFor([a]),
        score: own.join(", "),
        detections: 1,
        tags: [...(a.Tag ?? []).map((t) => t.name ?? "").filter(Boolean), ...tags].slice(0, 6),
        link: eventId
          ? `${this.base}/events/view/${encodeURIComponent(eventId)}`
          : `${this.base}/attributes/index`,
        ...(a.uuid ? { providerRecordId: a.uuid } : a.id ? { providerRecordId: `attribute:${a.id}` } : {}),
        ...(a.deleted ? { revoked: true } : {}),
        ...(Object.keys(temporal).length ? { temporal } : {}),
      };
    });
    return {
      results,
      backends: [
        {
          name: this.name,
          outcome: "hit",
          ...(incomplete
            ? { incomplete: true, detail: `read cut at ${PAGES_MAX * PAGE_SIZE} attributes` }
            : {}),
        },
      ],
    };
  }
}
