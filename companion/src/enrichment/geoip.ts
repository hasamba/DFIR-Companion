import type { EnrichmentProvider, EnrichmentResult, FetchFn, IocKind } from "./provider.js";

// Geo-IP lookup for an IP IOC — "what country (and city / ASN / hosting org) did this address
// come from?". Answers the analyst's first question about any external IP. Pure geo/network
// CONTEXT, not a reputation verdict, so the result is always `unknown`; country leads the
// `score`, with city/ASN/org in `tags`.
//
// Default backend is ipwho.is — keyless, HTTPS, JSON. Base overridable via DFIR_GEOIP_URL and
// an optional DFIR_GEOIP_KEY (appended as ?key=) so an analyst can point it at a paid tier or
// a self-hosted service. The parser is tolerant of the common keyless backends (ipwho.is and
// ip-api.com field names) so swapping the URL usually "just works". Injectable fetchFn.
export interface GeoIpOptions {
  baseUrl?: string;     // default https://ipwho.is
  apiKey?: string;      // optional; appended as ?key=
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

// Union of the fields the supported keyless backends use (ipwho.is + ip-api.com).
interface GeoResponse {
  success?: boolean;        // ipwho.is: false on a reserved/invalid IP (still HTTP 200)
  status?: string;          // ip-api.com: "success" | "fail"
  message?: string;
  country?: string;
  country_name?: string;    // some backends
  country_code?: string;    // ipwho.is
  countryCode?: string;     // ip-api.com
  region?: string;
  regionName?: string;      // ip-api.com
  city?: string;
  connection?: { asn?: number; org?: string; isp?: string; domain?: string };  // ipwho.is
  asn?: number;
  as?: string;              // ip-api.com, e.g. "AS15169 Google LLC"
  org?: string;
  isp?: string;
}

function firstStr(...vals: Array<string | undefined>): string | undefined {
  for (const v of vals) if (typeof v === "string" && v.trim()) return v.trim();
  return undefined;
}

// Normalize an ASN from either a numeric field or an "AS15169 Google LLC" string.
function asnLabel(j: GeoResponse): string | undefined {
  if (typeof j.connection?.asn === "number") return `AS${j.connection.asn}`;
  if (typeof j.asn === "number") return `AS${j.asn}`;
  const m = /^AS\d+/i.exec(j.as ?? "");
  return m ? m[0].toUpperCase() : undefined;
}

export class GeoIpProvider implements EnrichmentProvider {
  readonly name = "GeoIP";
  readonly scope = "external" as const;
  private readonly base: string;
  private readonly fetchFn: FetchFn;
  constructor(private readonly opts: GeoIpOptions = {}) {
    this.base = (opts.baseUrl ?? "https://ipwho.is").replace(/\/+$/, "");
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  supports(kind: IocKind): boolean { return kind === "ip"; }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    if (kind !== "ip") return null;
    const key = this.opts.apiKey ? `?key=${encodeURIComponent(this.opts.apiKey)}` : "";
    const url = `${this.base}/${encodeURIComponent(value)}${key}`;
    const res = await this.fetchFn(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 401 || res.status === 403) throw new Error("GeoIP auth failed (check DFIR_GEOIP_KEY)");
    if (res.status === 429) throw new Error("GeoIP rate limit");
    if (!res.ok) throw new Error(`GeoIP HTTP ${res.status}`);

    const json = (await res.json()) as GeoResponse;
    // Reserved / private / invalid IPs come back as a non-success body (HTTP 200) → miss.
    if (json.success === false || json.status === "fail") return null;

    const country = firstStr(json.country, json.country_name);
    const code = firstStr(json.country_code, json.countryCode);
    const place = firstStr(json.city, json.region, json.regionName);
    const asn = asnLabel(json);
    const org = firstStr(json.connection?.org, json.connection?.isp, json.org, json.isp);
    if (!country && !code && !asn && !org) return null;

    const tags: string[] = [];
    if (code) tags.push(code);
    if (place) tags.push(place);
    if (asn) tags.push(asn);
    if (org) tags.push(org);

    const countryLabel = country ? (code ? `${country} (${code})` : country) : code;
    const scoreParts = [countryLabel, asn && org ? `${asn} ${org}` : asn ?? org].filter(Boolean);
    return {
      source: this.name,
      verdict: "unknown",
      score: scoreParts.length ? scoreParts.join(" · ") : undefined,
      tags,
    };
  }
}
