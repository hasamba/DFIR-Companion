import {
  RateLimitError,
  parseRetryAfterMs,
  type EnrichmentProvider,
  type EnrichmentResult,
  type FetchFn,
  type IocKind,
  type Verdict,
} from "./provider.js";
import { readBoundedJson, RESPONSE_SIZE_LIMITS } from "../providers/boundedResponse.js";

export interface AbuseIpdbOptions {
  apiKey: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  maxAgeDays?: number;
  now?: () => string; // injectable clock, so the query window is testable
}

// AbuseIPDB — IP reputation. GET /api/v2/check?ipAddress=&maxAgeInDays=.
export class AbuseIpdbProvider implements EnrichmentProvider {
  readonly name = "AbuseIPDB";
  readonly scope = "external" as const;
  private readonly fetchFn: FetchFn;
  constructor(private readonly opts: AbuseIpdbOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  supports(kind: IocKind): boolean {
    return kind === "ip";
  }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    if (kind !== "ip") return null;
    const days = this.opts.maxAgeDays ?? 90;
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=${days}`;
    const res = await this.fetchFn(url, {
      headers: { Key: this.opts.apiKey, Accept: "application/json" },
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 401 || res.status === 403)
      throw new Error("AbuseIPDB auth failed (check DFIR_ABUSEIPDB_KEY)");
    if (res.status === 429)
      throw new RateLimitError("AbuseIPDB rate limit", parseRetryAfterMs(res.headers.get("retry-after")));
    if (!res.ok) throw new Error(`AbuseIPDB HTTP ${res.status}`);

    const json = await readBoundedJson<{
      data?: {
        abuseConfidenceScore?: number;
        totalReports?: number;
        countryCode?: string;
        isp?: string;
        domain?: string;
        lastReportedAt?: string | null;
      };
    }>(res, { maxBytes: RESPONSE_SIZE_LIMITS.json, context: "AbuseIPDB" });
    const d = json.data;
    if (!d) return null;
    const score = d.abuseConfidenceScore ?? 0;
    const verdict: Verdict = score >= 50 ? "malicious" : score > 0 ? "suspicious" : "harmless";
    const tags: string[] = [];
    if (d.countryCode) tags.push(d.countryCode);
    if (d.isp) tags.push(d.isp);

    // The report count and the verdict are bounded by the query window (#933 item 19): a clean
    // answer over the last 90 days says nothing about earlier dates, and the latest report is one
    // point. The window is [now − maxAgeInDays, now] as of this lookup.
    const now = this.opts.now?.() ?? new Date().toISOString();
    const last = typeof d.lastReportedAt === "string" ? Date.parse(d.lastReportedAt) : NaN;
    const temporal = {
      queryWindow: { from: new Date(Date.parse(now) - days * 86_400_000).toISOString(), to: now },
      ...(typeof d.totalReports === "number" ? { reportCount: d.totalReports } : {}),
      ...(Number.isFinite(last) ? { lastReportAt: new Date(last).toISOString() } : {}),
    };
    return {
      source: this.name,
      verdict,
      score: `${score}% abuse${d.totalReports ? `, ${d.totalReports} reports` : ""}`,
      detections: d.totalReports,
      tags,
      link: `https://www.abuseipdb.com/check/${encodeURIComponent(value)}`,
      temporal,
    };
  }
}
