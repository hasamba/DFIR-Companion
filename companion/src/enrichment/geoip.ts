import type { EnrichmentProvider, EnrichmentResult, FetchFn, IocKind } from "./provider.js";

// Geo-IP lookup for an IP IOC — "what country (and city / ASN / hosting org) did this address
// come from?". Answers the analyst's first question about any external IP. Pure geo/network
// CONTEXT, not a reputation verdict, so the result is always `unknown`; country leads the
// `score`, with city/ASN/org in `tags`.
//
// Default backend is ipinfo.io — keyless, HTTPS, and (unlike ipwho.is / ipapi.co, which bot-
// block Node's fetch) it answers reliably from a server-side client. The endpoint is a URL
// TEMPLATE (DFIR_GEOIP_URL): a `{ip}` placeholder is substituted, otherwise the IP is appended
// as `/{ip}`. An optional DFIR_GEOIP_KEY is substituted for a `{key}` placeholder, else appended
// as `?token=` (ipinfo's param). The parser is tolerant of the common keyless backends
// (ipinfo.io, ip-api.com, ipwho.is field names) so swapping the URL usually "just works".
// Injectable fetchFn so tests never hit the network.
export interface GeoIpOptions {
  baseUrl?: string;     // default https://ipinfo.io/{ip}/json
  apiKey?: string;      // optional; substituted for {key} or appended as ?token=
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

// Union of the fields the supported keyless backends use (ipinfo.io + ip-api.com + ipwho.is).
interface GeoResponse {
  success?: boolean;        // ipwho.is: false on a reserved/invalid IP (still HTTP 200)
  status?: string;          // ip-api.com: "success" | "fail"
  error?: unknown;          // ipinfo: { error: {...} } on a bogon/error
  message?: string;
  country?: string;         // ipwho.is: name; ip-api: name; ipinfo: 2-letter code
  country_name?: string;
  country_code?: string;    // ipwho.is
  countryCode?: string;     // ip-api.com
  region?: string;          // ipwho.is / ipinfo
  regionName?: string;      // ip-api.com
  city?: string;
  connection?: { asn?: number; org?: string; isp?: string; domain?: string };  // ipwho.is
  asn?: number;
  as?: string;              // ip-api.com, e.g. "AS15169 Google LLC"
  org?: string;             // ip-api ("Google Public DNS") | ipinfo ("AS15169 Google LLC")
  isp?: string;
}

function firstStr(...vals: Array<string | undefined>): string | undefined {
  for (const v of vals) if (typeof v === "string" && v.trim()) return v.trim();
  return undefined;
}

const DEFAULT_URL = "https://ipinfo.io/{ip}/json";

export class GeoIpProvider implements EnrichmentProvider {
  readonly name = "GeoIP";
  readonly scope = "external" as const;
  private readonly template: string;
  private readonly fetchFn: FetchFn;
  constructor(private readonly opts: GeoIpOptions = {}) {
    this.template = opts.baseUrl?.trim() || DEFAULT_URL;
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  supports(kind: IocKind): boolean { return kind === "ip"; }

  // Build the request URL from the template + the optional key.
  private buildUrl(value: string): string {
    const ip = encodeURIComponent(value);
    let url = this.template.includes("{ip}") ? this.template.replace("{ip}", ip) : `${this.template.replace(/\/+$/, "")}/${ip}`;
    const key = this.opts.apiKey;
    if (key) {
      if (url.includes("{key}")) url = url.replace("{key}", encodeURIComponent(key));
      else url += `${url.includes("?") ? "&" : "?"}token=${encodeURIComponent(key)}`;
    }
    return url;
  }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    if (kind !== "ip") return null;
    const res = await this.fetchFn(this.buildUrl(value), {
      headers: { Accept: "application/json", "User-Agent": "DFIR-Companion" },
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 401 || res.status === 403) throw new Error("GeoIP auth failed / blocked (set DFIR_GEOIP_URL or DFIR_GEOIP_KEY)");
    if (res.status === 429) throw new Error("GeoIP rate limit");
    if (!res.ok) throw new Error(`GeoIP HTTP ${res.status}`);

    const json = (await res.json()) as GeoResponse;
    // Reserved / private / invalid IPs come back as a non-success body (HTTP 200) → miss.
    if (json.success === false || json.status === "fail" || json.error) return null;

    let country = firstStr(json.country_name, json.country);
    let code = firstStr(json.country_code, json.countryCode);
    // ipinfo returns `country` as a 2-letter code with no separate code field.
    if (!code && country && /^[A-Za-z]{2}$/.test(country)) { code = country.toUpperCase(); country = undefined; }

    // ASN: a numeric field (ipwho.is), or the leading "AS\d+" of an "AS15169 Google LLC"
    // string (ip-api `as`, ipinfo `org`).
    const asString = firstStr(json.as, json.org);
    let asn: string | undefined;
    if (typeof json.connection?.asn === "number") asn = `AS${json.connection.asn}`;
    else if (typeof json.asn === "number") asn = `AS${json.asn}`;
    else { const m = /^(AS\d+)/i.exec(asString ?? ""); if (m) asn = m[1].toUpperCase(); }

    // Org name: prefer an explicit org/isp; strip a leading "AS\d+ " prefix (ipinfo bakes it in).
    let org = firstStr(json.connection?.org, json.connection?.isp, json.org, json.isp);
    if (org) org = org.replace(/^AS\d+\s+/i, "").trim() || undefined;

    const place = firstStr(json.city, json.region, json.regionName);
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
