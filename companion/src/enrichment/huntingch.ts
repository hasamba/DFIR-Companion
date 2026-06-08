import type { EnrichmentProvider, EnrichmentResult, FetchFn, IocKind, Verdict } from "./provider.js";

export interface HuntingChOptions {
  apiKey: string;    // unified abuse.ch Auth-Key (one key from https://auth.abuse.ch/)
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

// Thrown by a back-end helper on 401/403 so the provider can surface ONE actionable
// "check your key" error instead of silently dropping every platform.
class AbuseAuthError extends Error {}

function num(v: unknown): number {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : 0;
}

function str(v: unknown): string {
  return v === undefined || v === null ? "" : String(v);
}

// Small POST helper shared by every abuse.ch back-end: attaches the Auth-Key, enforces a
// timeout, and maps auth failures to AbuseAuthError. `body` is a urlencoded string (the
// classic MalwareBazaar/URLhaus APIs) or a JSON object (ThreatFox/YARAify).
class AbuseCtx {
  constructor(
    private readonly fetchFn: FetchFn,
    private readonly apiKey: string,
    private readonly timeoutMs: number,
  ) {}

  async post(url: string, body: string | Record<string, unknown>, platform: string): Promise<Record<string, unknown>> {
    const isJson = typeof body !== "string";
    const res = await this.fetchFn(url, {
      method: "POST",
      headers: {
        "content-type": isJson ? "application/json" : "application/x-www-form-urlencoded",
        "Auth-Key": this.apiKey,
      },
      body: isJson ? JSON.stringify(body) : body,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (res.status === 401 || res.status === 403) throw new AbuseAuthError(`${platform} auth ${res.status}`);
    if (!res.ok) throw new Error(`${platform} HTTP ${res.status}`);
    return (await res.json()) as Record<string, unknown>;
  }
}

// ── Per-platform back-ends. Each returns ONE EnrichmentResult on a hit, or null when the
//    indicator is unknown to that platform. They throw only on hard errors (auth / HTTP). ──

// MalwareBazaar — known malware sample (hash only).
async function mbLookup(ctx: AbuseCtx, hash: string): Promise<EnrichmentResult | null> {
  const json = await ctx.post("https://mb-api.abuse.ch/api/v1/", new URLSearchParams({ query: "get_info", hash }).toString(), "MalwareBazaar");
  const status = str(json.query_status);
  const data = json.data as Array<Record<string, unknown>> | undefined;
  if (status === "hash_not_found" || !data?.length) return null;
  const d = data[0];
  const sha256 = str(d.sha256_hash) || hash;
  const signature = str(d.signature);
  const fileType = str(d.file_type);
  const tags = new Set<string>();
  if (signature) tags.add(signature);
  for (const t of ((d.tags as string[] | undefined) ?? []).slice(0, 6)) if (t) tags.add(str(t));
  return {
    source: "MalwareBazaar",
    verdict: "malicious",
    score: signature ? `known: ${signature}` : `known sample${fileType ? ` (${fileType})` : ""}`,
    tags: [...tags],
    link: `https://bazaar.abuse.ch/sample/${encodeURIComponent(sha256)}/`,
  };
}

// ThreatFox — tracked IOC (C2 / payload). Hash uses search_hash; IP/domain/URL use search_ioc.
async function tfLookup(ctx: AbuseCtx, kind: IocKind, value: string): Promise<EnrichmentResult | null> {
  const body = kind === "hash" ? { query: "search_hash", hash: value } : { query: "search_ioc", search_term: value, exact_match: true };
  const json = await ctx.post("https://threatfox-api.abuse.ch/api/v1/", body, "ThreatFox");
  const rows = json.data as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(rows) || rows.length === 0) return null;
  if (json.query_status && json.query_status !== "ok") return null;
  const d = rows.reduce((best, r) => (num(r.confidence_level) > num(best.confidence_level) ? r : best), rows[0]);
  const confidence = num(d.confidence_level);
  const malware = str(d.malware_printable);
  const threatType = str(d.threat_type);
  const tags = new Set<string>();
  if (malware && malware.toLowerCase() !== "unknown") tags.add(malware);
  if (threatType) tags.add(threatType);
  for (const t of ((d.tags as string[] | undefined) ?? []).slice(0, 6)) if (t) tags.add(str(t));
  const desc = [malware, threatType.replace(/_/g, " ")].filter(Boolean).join(", ") || "tracked IOC";
  const id = str(d.id);
  return {
    source: "ThreatFox",
    verdict: confidence >= 50 ? "malicious" : "suspicious",
    score: `${desc}${confidence ? ` (${confidence}% confidence)` : ""}`,
    tags: [...tags],
    link: id ? `https://threatfox.abuse.ch/ioc/${encodeURIComponent(id)}/` : "https://threatfox.abuse.ch/browse/",
  };
}

// URLhaus — malware-distribution URLs. host (IP/domain), url, or payload (hash).
async function urlhausLookup(ctx: AbuseCtx, kind: IocKind, value: string): Promise<EnrichmentResult | null> {
  const endpoint = kind === "hash" ? "payload" : kind === "url" ? "url" : "host";
  const field = kind === "hash" ? (value.length === 32 ? "md5_hash" : "sha256_hash") : kind === "url" ? "url" : "host";
  const json = await ctx.post(`https://urlhaus-api.abuse.ch/v1/${endpoint}/`, new URLSearchParams({ [field]: value }).toString(), "URLhaus");
  if (str(json.query_status) !== "ok") return null;          // no_results / invalid_*
  const urlCount = num(json.url_count);
  const threat = str(json.threat);
  const signature = str(json.signature);
  const tags = new Set<string>();
  if (threat) tags.add(threat);
  if (signature) tags.add(signature);
  const blacklists = json.blacklists as Record<string, unknown> | undefined;
  for (const b of blacklists ? Object.keys(blacklists) : []) tags.add(b);
  const desc = kind === "hash"
    ? `malware payload${signature ? ` (${signature})` : ""}${urlCount ? `, ${urlCount} URL(s)` : ""}`
    : kind === "url"
      ? `malware URL${str(json.url_status) ? ` (${str(json.url_status)})` : ""}`
      : `${urlCount} malware URL(s) hosted`;
  const link = str(json.urlhaus_reference) || `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(value)}`;
  return { source: "URLhaus", verdict: "malicious", score: desc, tags: [...tags], link };
}

// YARAify — which YARA rules / ClamAV signatures matched a sample (hash only).
async function yaraifyLookup(ctx: AbuseCtx, hash: string): Promise<EnrichmentResult | null> {
  const json = await ctx.post("https://yaraify-api.abuse.ch/api/v1/", { query: "lookup_hash", search_term: hash }, "YARAify");
  if (str(json.query_status) !== "ok") return null;
  const data = json.data as Record<string, unknown> | undefined;
  if (!data || typeof data !== "object") return null;
  const meta = (data.metadata as Record<string, unknown> | undefined) ?? {};
  const tasks = (data.tasks as Array<Record<string, unknown>> | undefined) ?? [];
  const rules = new Set<string>();
  const clamav = new Set<string>();
  for (const t of tasks) {
    for (const s of ((t.static_results as Array<Record<string, unknown>> | undefined) ?? [])) {
      const name = str(s.rule_name);
      if (name) rules.add(name);
    }
    for (const c of ((t.clamav_results as string[] | undefined) ?? [])) if (c) clamav.add(str(c));
  }
  if (rules.size === 0 && clamav.size === 0) return null;     // seen, but nothing matched
  const sha256 = str(meta.sha256_hash) || hash;
  const tags = [...rules].slice(0, 4);
  const parts: string[] = [];
  if (rules.size) parts.push(`${rules.size} YARA rule(s)`);
  if (clamav.size) parts.push(`${clamav.size} ClamAV sig(s)`);
  return {
    source: "YARAify",
    verdict: rules.size > 0 ? "malicious" : "suspicious",
    score: parts.join(", "),
    tags,
    link: `https://yaraify.abuse.ch/sample/${encodeURIComponent(sha256)}/`,
  };
}

// Hunting.ch — the abuse.ch hunting platform (https://hunting.abuse.ch/). One indicator is
// looked up across EVERY abuse.ch back-end that knows its kind, and each hit becomes its OWN
// result (separate, clickable badge) — mirroring hunting.abuse.ch/hunt/<ioc>/:
//   hash  → MalwareBazaar (samples) · ThreatFox (IOCs) · URLhaus (payloads) · YARAify (YARA/ClamAV)
//   ip    → ThreatFox · URLhaus (host)
//   domain→ ThreatFox · URLhaus (host)
//   url   → ThreatFox · URLhaus (url)
// All back-ends share the ONE unified abuse.ch Auth-Key (the same key as MalwareBazaar's
// DFIR_MB_KEY — most back-ends 401 without it; YARAify works anonymously). If any platform is
// rate-limited / down / auth-blocked, the ones that DID answer are still returned.
export class HuntingChProvider implements EnrichmentProvider {
  readonly name = "Hunting.ch";
  readonly scope = "external" as const;
  private readonly ctx: AbuseCtx;
  constructor(opts: HuntingChOptions) {
    this.ctx = new AbuseCtx(opts.fetchFn ?? fetch, opts.apiKey, opts.timeoutMs ?? 20_000);
  }

  supports(kind: IocKind): boolean {
    return kind === "hash" || kind === "ip" || kind === "domain" || kind === "url";
  }

  private backends(kind: IocKind, value: string): Array<Promise<EnrichmentResult | null>> {
    if (kind === "hash") {
      return [
        mbLookup(this.ctx, value),
        tfLookup(this.ctx, kind, value),
        urlhausLookup(this.ctx, kind, value),
        yaraifyLookup(this.ctx, value),
      ];
    }
    // ip / domain / url
    return [tfLookup(this.ctx, kind, value), urlhausLookup(this.ctx, kind, value)];
  }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult[] | null> {
    if (!this.supports(kind)) return null;
    const settled = await Promise.allSettled(this.backends(kind, value));
    const results: EnrichmentResult[] = [];
    let authFailed = false;
    let nonAuthError = false;
    for (const s of settled) {
      if (s.status === "fulfilled") {
        if (s.value) results.push(s.value);
      } else if (s.reason instanceof AbuseAuthError) {
        authFailed = true;
      } else {
        nonAuthError = true;
      }
    }
    // Resilient: if ANY platform answered with a hit, return it — one back-end being
    // rate-limited, down, or auth-blocked (e.g. YARAify needs no key while the rest do)
    // must NOT discard the platforms that succeeded.
    if (results.length > 0) return results;
    // Nothing came back. A 401/403 means the shared abuse.ch key is missing/expired —
    // surface it (the standalone MalwareBazaar key is the same one).
    if (authFailed) throw new Error("Hunting.ch (abuse.ch) auth failed — check DFIR_HUNTINGCH_KEY (or DFIR_MB_KEY)");
    // Every back-end errored (transient outage) → throw so the IOC is retried next run
    // rather than cached as "checked, no intel".
    if (nonAuthError) throw new Error("Hunting.ch: all abuse.ch lookups failed");
    return [];   // every platform answered "not found"
  }
}
