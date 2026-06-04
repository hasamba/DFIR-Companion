import type { EnrichmentProvider, EnrichmentResult, FetchFn, IocKind, Verdict } from "./provider.js";

export interface AbuseIpdbOptions {
  apiKey: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  maxAgeDays?: number;
}

// AbuseIPDB — IP reputation. GET /api/v2/check?ipAddress=&maxAgeInDays=.
export class AbuseIpdbProvider implements EnrichmentProvider {
  readonly name = "AbuseIPDB";
  private readonly fetchFn: FetchFn;
  constructor(private readonly opts: AbuseIpdbOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  supports(kind: IocKind): boolean { return kind === "ip"; }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    if (kind !== "ip") return null;
    const days = this.opts.maxAgeDays ?? 90;
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=${days}`;
    const res = await this.fetchFn(url, {
      headers: { Key: this.opts.apiKey, Accept: "application/json" },
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 401 || res.status === 403) throw new Error("AbuseIPDB auth failed (check DFIR_ABUSEIPDB_KEY)");
    if (res.status === 429) throw new Error("AbuseIPDB rate limit");
    if (!res.ok) throw new Error(`AbuseIPDB HTTP ${res.status}`);

    const json = (await res.json()) as { data?: { abuseConfidenceScore?: number; totalReports?: number; countryCode?: string; isp?: string; domain?: string } };
    const d = json.data;
    if (!d) return null;
    const score = d.abuseConfidenceScore ?? 0;
    const verdict: Verdict = score >= 50 ? "malicious" : score > 0 ? "suspicious" : "harmless";
    const tags: string[] = [];
    if (d.countryCode) tags.push(d.countryCode);
    if (d.isp) tags.push(d.isp);

    return {
      source: this.name,
      verdict,
      score: `${score}% abuse${d.totalReports ? `, ${d.totalReports} reports` : ""}`,
      detections: d.totalReports,
      tags,
      link: `https://www.abuseipdb.com/check/${encodeURIComponent(value)}`,
    };
  }
}
