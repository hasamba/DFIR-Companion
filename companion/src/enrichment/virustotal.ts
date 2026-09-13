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

export interface VirusTotalOptions {
  apiKey: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

// VirusTotal v3. One object type per IOC kind (process isn't lookup-able on VT).
const PATH: Partial<Record<IocKind, (v: string) => string>> = {
  hash: (v) => `files/${encodeURIComponent(v)}`,
  ip: (v) => `ip_addresses/${encodeURIComponent(v)}`,
  domain: (v) => `domains/${encodeURIComponent(v)}`,
  url: (v) => `urls/${urlId(v)}`,
};
const GUI: Partial<Record<IocKind, string>> = {
  hash: "file",
  ip: "ip-address",
  domain: "domain",
  url: "url",
};

// VT addresses a URL by the unpadded base64url of the URL string.
function urlId(url: string): string {
  return Buffer.from(url, "utf8").toString("base64url");
}

interface VtStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
}

function verdictFromStats(s: VtStats): { verdict: Verdict; detections: number; total: number } {
  const malicious = s.malicious ?? 0;
  const suspicious = s.suspicious ?? 0;
  const total =
    (s.malicious ?? 0) + (s.suspicious ?? 0) + (s.harmless ?? 0) + (s.undetected ?? 0) + (s.timeout ?? 0);
  const verdict: Verdict =
    malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : total > 0 ? "harmless" : "unknown";
  return { verdict, detections: malicious, total };
}

/** An epoch-seconds field as ISO, under `key` — or nothing when it is not a plausible epoch. */
function epochField(v: unknown, key: string): Record<string, string> {
  const n = typeof v === "number" ? v : typeof v === "string" && /^\d+$/.test(v) ? Number(v) : NaN;
  if (!Number.isFinite(n) || n < 946_684_800 || n > 4_102_444_800) return {}; // 2000-01-01 … 2100-01-01
  return { [key]: new Date(n * 1000).toISOString() };
}

export class VirusTotalProvider implements EnrichmentProvider {
  readonly name = "VirusTotal";
  readonly scope = "external" as const;
  private readonly fetchFn: FetchFn;
  constructor(private readonly opts: VirusTotalOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  supports(kind: IocKind): boolean {
    return kind !== "process";
  } // hash | ip | domain | url

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    const pathFor = PATH[kind];
    if (!pathFor) return null; // unsupported kind (e.g. process)
    const url = `https://www.virustotal.com/api/v3/${pathFor(value)}`;
    const res = await this.fetchFn(url, {
      headers: { "x-apikey": this.opts.apiKey },
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 404) return null; // unknown to VT
    if (res.status === 401 || res.status === 403)
      throw new Error("VirusTotal auth failed (check DFIR_VT_KEY)");
    if (res.status === 429)
      throw new RateLimitError(
        "VirusTotal rate limit (free tier is ~4/min)",
        parseRetryAfterMs(res.headers.get("retry-after")),
      );
    if (!res.ok) throw new Error(`VirusTotal HTTP ${res.status}`);

    const json = await readBoundedJson<{ data?: { id?: string; attributes?: Record<string, unknown> } }>(
      res,
      {
        maxBytes: RESPONSE_SIZE_LIMITS.json,
        context: "VirusTotal",
      },
    );
    const attrs = json.data?.attributes ?? {};
    const stats = (attrs.last_analysis_stats as VtStats) ?? {};
    const { verdict, detections, total } = verdictFromStats(stats);

    const tags = new Set<string>();
    const threat = attrs.popular_threat_classification as { suggested_threat_label?: string } | undefined;
    if (threat?.suggested_threat_label) tags.add(threat.suggested_threat_label);
    for (const t of ((attrs.tags as string[] | undefined) ?? []).slice(0, 5)) tags.add(t);

    const id = json.data?.id ?? (kind === "url" ? urlId(value) : value);
    // The object's own dated facts, each of its kind (#933 item 19): files and URLs carry a
    // first-submission date; every object carries the latest scan the verdict comes from; ip and
    // domain objects carry a record-modification date that is not an observation. Epoch seconds,
    // as VirusTotal documents them; anything else is dropped.
    const temporal = {
      ...(kind === "hash" || kind === "url"
        ? epochField(attrs.first_submission_date, "firstSubmittedAt")
        : {}),
      ...epochField(attrs.last_analysis_date, "verdictMeasuredAt"),
      ...(kind === "ip" || kind === "domain"
        ? epochField(attrs.last_modification_date, "recordUpdatedAt")
        : {}),
    };
    return {
      source: this.name,
      verdict,
      score: total ? `${detections}/${total} detections` : undefined,
      detections,
      total,
      tags: [...tags],
      link: `https://www.virustotal.com/gui/${GUI[kind] ?? "search"}/${encodeURIComponent(id)}`,
      ...(Object.keys(temporal).length ? { temporal } : {}),
    };
  }
}
