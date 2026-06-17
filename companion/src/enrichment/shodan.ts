import type { EnrichmentProvider, EnrichmentResult, FetchFn, IocKind } from "./provider.js";

// Shodan host lookup for an IP IOC — "what is hosted on this address?". Surfaces the web
// properties / services Shodan has seen: hostnames + domains, open ports, the running
// products, the owning org/ISP/ASN, and any CVEs Shodan flagged on the host. Great for
// pivoting on attacker infrastructure (find the other domains on the same box). Reuses the
// existing DFIR_SHODAN_KEY (also used by the customer-exposure attack-surface check).
//
// This is INFRASTRUCTURE context, not a reputation call — Shodan seeing an exposed service or
// a CVE on an IP doesn't mean the IP attacked us — so the verdict stays `unknown`; the detail
// rides in `score`/`tags`. Injectable fetchFn so tests never hit the network.
export interface ShodanOptions {
  apiKey: string;
  baseUrl?: string;     // default https://api.shodan.io
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

interface ShodanHost {
  hostnames?: string[];
  domains?: string[];
  ports?: number[];
  org?: string;
  isp?: string;
  asn?: string;
  os?: string | null;
  country_name?: string;
  vulns?: string[];
  data?: Array<{ product?: string }>;
}

function uniq(arr: (string | undefined)[]): string[] {
  return [...new Set(arr.filter((s): s is string => Boolean(s && s.trim())))];
}

export class ShodanProvider implements EnrichmentProvider {
  readonly name = "Shodan";
  readonly scope = "external" as const;
  private readonly base: string;
  private readonly fetchFn: FetchFn;
  constructor(private readonly opts: ShodanOptions) {
    this.base = (opts.baseUrl ?? "https://api.shodan.io").replace(/\/+$/, "");
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  supports(kind: IocKind): boolean { return kind === "ip"; }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    if (kind !== "ip") return null;
    const url = `${this.base}/shodan/host/${encodeURIComponent(value)}?key=${encodeURIComponent(this.opts.apiKey)}`;
    const res = await this.fetchFn(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 404) return null;                          // "No information available for that IP"
    if (res.status === 401 || res.status === 403) throw new Error("Shodan auth failed (check DFIR_SHODAN_KEY)");
    if (res.status === 429) throw new Error("Shodan rate limit");
    if (!res.ok) throw new Error(`Shodan HTTP ${res.status}`);

    const h = (await res.json()) as ShodanHost;
    const hostnames = uniq([...(h.hostnames ?? []), ...(h.domains ?? [])]);
    const ports = (h.ports ?? []).filter((p) => Number.isFinite(p));
    const vulns = uniq(h.vulns ?? []);
    const products = uniq((h.data ?? []).map((d) => d.product));
    const net = h.org ?? h.isp;

    const tags: string[] = [];
    if (h.country_name) tags.push(h.country_name);
    if (h.asn) tags.push(h.asn);
    if (net) tags.push(net);
    for (const host of hostnames.slice(0, 3)) tags.push(host);
    if (ports.length) tags.push(`ports ${ports.slice(0, 8).join(",")}`);
    for (const v of vulns.slice(0, 3)) tags.push(v);

    const summary: string[] = [];
    if (hostnames.length) summary.push(`${hostnames.length} hostname${hostnames.length === 1 ? "" : "s"}`);
    if (ports.length) summary.push(`${ports.length} port${ports.length === 1 ? "" : "s"}`);
    if (products.length) summary.push(products.slice(0, 3).join("/"));
    if (vulns.length) summary.push(`${vulns.length} CVE${vulns.length === 1 ? "" : "s"}`);
    // A host object with nothing useful (no hostnames, ports, services or vulns) is a miss.
    if (summary.length === 0 && tags.length === 0) return null;

    return {
      source: this.name,
      verdict: "unknown",
      score: summary.join(", ") || undefined,
      tags,
      link: `https://www.shodan.io/host/${encodeURIComponent(value)}`,
    };
  }
}
