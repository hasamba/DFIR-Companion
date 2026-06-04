import type { EnrichmentProvider, EnrichmentResult, FetchFn, IocKind, Verdict } from "./provider.js";

export interface MispOptions {
  baseUrl: string;   // your MISP instance, e.g. https://misp.example.org
  apiKey: string;    // MISP Auth Key (Authorization header)
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

interface MispEvent { id?: string; info?: string; threat_level_id?: string }
interface MispTag { name?: string }
interface MispAttribute {
  type?: string;
  value?: string;
  category?: string;
  to_ids?: boolean;
  event_id?: string;
  Event?: MispEvent;
  Tag?: MispTag[];
}

// MISP threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined.
function verdictFor(attrs: MispAttribute[]): Verdict {
  if (attrs.length === 0) return "unknown";
  const high = attrs.some((a) => a.to_ids === true || a.Event?.threat_level_id === "1");
  return high ? "malicious" : "suspicious";   // present in MISP = at least suspicious
}

// MISP (Malware Information Sharing Platform). Searches your instance's attributes for
// the indicator value; a hit means the IOC is known threat intel shared on that instance.
export class MispProvider implements EnrichmentProvider {
  readonly name = "MISP";
  readonly scope = "local" as const;     // your own instance — OPSEC-safe
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  constructor(private readonly opts: MispOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = opts.baseUrl.replace(/\/+$/, "");
  }

  supports(kind: IocKind): boolean { return kind !== "process"; } // attribute values: hash/ip/domain/url (not bare process names)

  async lookup(_kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    const res = await this.fetchFn(`${this.base}/attributes/restSearch`, {
      method: "POST",
      headers: {
        Authorization: this.opts.apiKey,
        Accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({ returnFormat: "json", value, limit: 25, includeEventTags: true }),
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 401 || res.status === 403) throw new Error("MISP auth failed (check DFIR_MISP_KEY)");
    if (!res.ok) throw new Error(`MISP HTTP ${res.status}`);

    const json = (await res.json()) as { response?: { Attribute?: MispAttribute[] } };
    const attrs = json.response?.Attribute ?? [];
    if (attrs.length === 0) return null;                       // not present on this instance

    const events = new Map<string, MispEvent>();
    const tags = new Set<string>();
    for (const a of attrs) {
      const ev = a.Event;
      if (ev?.id) events.set(ev.id, ev);
      for (const t of a.Tag ?? []) if (t.name) tags.add(t.name);
    }
    const firstEventId = attrs[0].Event?.id ?? attrs[0].event_id;
    const eventInfo = attrs[0].Event?.info;

    return {
      source: this.name,
      verdict: verdictFor(attrs),
      score: `${attrs.length} attribute(s) in ${events.size || 1} event(s)${eventInfo ? `: ${eventInfo.slice(0, 80)}` : ""}`,
      detections: attrs.length,
      tags: [...tags].slice(0, 6),
      link: firstEventId ? `${this.base}/events/view/${encodeURIComponent(firstEventId)}` : `${this.base}/attributes/index`,
    };
  }
}
