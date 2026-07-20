import { RateLimitError, parseRetryAfterMs, type EnrichmentProvider, type EnrichmentResult, type FetchFn, type IocKind } from "./provider.js";

// WHOIS-equivalent registration lookup for an IP IOC, over RDAP (the modern, JSON-over-HTTPS
// replacement for port-43 WHOIS). Resolves which network block owns the address: net name,
// CIDR range, country, the responsible org, and the abuse contact e-mail — useful for
// attributing attacker infrastructure and knowing who to report it to. Pure registration
// CONTEXT, not a reputation verdict, so the result is always `unknown`.
//
// Default endpoint is rdap.org — the IANA/registry bootstrap redirector that forwards the
// query to the authoritative RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC), so we don't need to know
// which registry owns the IP. No API key. Base overridable via DFIR_RDAP_URL. Injectable
// fetchFn so tests never hit the network.
export interface RdapOptions {
  baseUrl?: string;     // default https://rdap.org
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

// A vCard property row is [name, params, type, value] inside vcardArray[1].
type VcardProp = [string, Record<string, unknown>, string, unknown];
interface RdapEntity {
  roles?: string[];
  handle?: string;
  vcardArray?: [string, VcardProp[]];
  entities?: RdapEntity[];
}
interface RdapIpResponse {
  name?: string;
  handle?: string;
  country?: string;
  startAddress?: string;
  endAddress?: string;
  cidr0_cidrs?: Array<{ v4prefix?: string; v6prefix?: string; length?: number }>;
  // ARIN-specific origin-AS extension (other RIRs rarely include the AS in the IP object).
  arin_originas0_originautnums?: number[];
  entities?: RdapEntity[];
}

// Pull a named field (e.g. "email", "fn", "org") out of a vCard property list.
function vcardValue(vcard: [string, VcardProp[]] | undefined, field: string): string | undefined {
  const props = vcard?.[1];
  if (!Array.isArray(props)) return undefined;
  for (const p of props) {
    if (Array.isArray(p) && p[0] === field && typeof p[3] === "string" && p[3].trim()) return p[3].trim();
  }
  return undefined;
}

// Walk the (possibly nested) entity tree to find the first entity holding a given role and
// return its vCard. Abuse contacts are frequently nested one or two levels deep.
function findEntityByRole(entities: RdapEntity[] | undefined, role: string): RdapEntity | undefined {
  for (const e of entities ?? []) {
    if (e.roles?.includes(role)) return e;
    const nested = findEntityByRole(e.entities, role);
    if (nested) return nested;
  }
  return undefined;
}

function registrantName(entities: RdapEntity[] | undefined): string | undefined {
  const reg = findEntityByRole(entities, "registrant") ?? findEntityByRole(entities, "administrative");
  return vcardValue(reg?.vcardArray, "org") ?? vcardValue(reg?.vcardArray, "fn") ?? reg?.handle;
}

function abuseEmail(entities: RdapEntity[] | undefined): string | undefined {
  const abuse = findEntityByRole(entities, "abuse");
  return vcardValue(abuse?.vcardArray, "email");
}

function cidrRange(j: RdapIpResponse): string | undefined {
  const c = j.cidr0_cidrs?.[0];
  if (c && (c.v4prefix ?? c.v6prefix) && c.length !== undefined) return `${c.v4prefix ?? c.v6prefix}/${c.length}`;
  if (j.startAddress && j.endAddress) return `${j.startAddress} – ${j.endAddress}`;
  return undefined;
}

export class RdapProvider implements EnrichmentProvider {
  readonly name = "WHOIS";
  readonly scope = "external" as const;
  private readonly base: string;
  private readonly fetchFn: FetchFn;
  constructor(private readonly opts: RdapOptions = {}) {
    this.base = (opts.baseUrl ?? "https://rdap.org").replace(/\/+$/, "");
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  supports(kind: IocKind): boolean { return kind === "ip"; }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    if (kind !== "ip") return null;
    const url = `${this.base}/ip/${encodeURIComponent(value)}`;
    const res = await this.fetchFn(url, {
      headers: { Accept: "application/rdap+json, application/json" },
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 404) return null;                          // no allocation found for this IP
    if (res.status === 429) throw new RateLimitError("RDAP/WHOIS rate limit", parseRetryAfterMs(res.headers.get("retry-after")));
    if (!res.ok) throw new Error(`RDAP/WHOIS HTTP ${res.status}`);

    const json = (await res.json()) as RdapIpResponse;
    const netname = json.name ?? json.handle;
    const range = cidrRange(json);
    const country = json.country;
    const asn = json.arin_originas0_originautnums?.[0];
    const org = registrantName(json.entities);
    const abuse = abuseEmail(json.entities);

    const tags: string[] = [];
    if (country) tags.push(country);
    if (asn) tags.push(`AS${asn}`);
    if (netname) tags.push(netname);
    if (org && org !== netname) tags.push(org);
    if (range) tags.push(range);
    if (abuse) tags.push(`abuse: ${abuse}`);

    // A genuinely empty RDAP object (no name, range or country) is a miss.
    if (!netname && !range && !country && !org) return null;

    const scoreParts = [asn ? `AS${asn}` : undefined, org ?? netname, country].filter(Boolean);
    return {
      source: this.name,
      verdict: "unknown",
      score: scoreParts.length ? scoreParts.join(" · ") : undefined,
      tags,
      link: `${this.base}/ip/${encodeURIComponent(value)}`,
    };
  }
}
