import type {
  BackendOutcome,
  DetailedLookup,
  EnrichmentProvider,
  EnrichmentResult,
  FetchFn,
  IocKind,
} from "./provider.js";
import { readBoundedJson, RESPONSE_SIZE_LIMITS } from "../providers/boundedResponse.js";

export interface HuntingChOptions {
  apiKey: string; // unified abuse.ch Auth-Key (one key from https://auth.abuse.ch/)
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

  async post(
    url: string,
    body: string | Record<string, unknown>,
    platform: string,
  ): Promise<Record<string, unknown>> {
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
    return readBoundedJson<Record<string, unknown>>(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: platform,
    });
  }
}

// ── Per-platform back-ends. Each returns ONE EnrichmentResult on a hit, or null when the
//    indicator is unknown to that platform. They throw only on hard errors (auth / HTTP). ──

// Lineage (#933 item 18): the four back-ends are one publisher's own databases — one origin, first-party.
// A MISP/OpenCTI record relaying an abuse.ch feed folds onto this name, so "ThreatFox + MISP" reads as
// one report, not two.
const ABUSE_CH_ORIGIN = (): Pick<EnrichmentResult, "originKind" | "origins"> => ({
  originKind: "first-party",
  origins: ["abuse.ch"],
});

const TF_NO_RESULT = new Set(["no_result", "no_results", "hash_not_found", "ioc_not_found"]);
const TF_EXPIRY_NOTE =
  "ThreatFox removes IOCs older than six months from its API; a miss is not a withdrawal";
const URLHAUS_NO_RESULT = new Set(["no_results"]);
const MB_NO_RESULT = new Set(["hash_not_found", "no_results"]);
const YARAIFY_NO_RESULT = new Set(["no_results", "hash_not_found"]);
/** abuse.ch dates are `YYYY-MM-DD HH:MM:SS` in UTC; kept as ISO with the zone, never guessed. */
const abuseDate = (v: string): string => {
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\s*UTC)?$/.exec(v.trim());
  return m ? `${m[1]}T${m[2]}Z` : "";
};
const dated = (
  fields: Record<string, string | boolean | undefined>,
): EnrichmentResult["temporal"] | undefined => {
  const out: Record<string, string | boolean> = {};
  for (const [k, v] of Object.entries(fields)) {
    if (typeof v === "boolean") {
      if (v) out[k] = v;
    } else if (v) {
      const iso = abuseDate(v);
      if (iso) out[k] = iso;
    }
  }
  return Object.keys(out).length ? out : undefined;
};

// MalwareBazaar — known malware sample (hash only).
async function mbLookup(ctx: AbuseCtx, hash: string): Promise<EnrichmentResult | null> {
  const json = await ctx.post(
    "https://mb-api.abuse.ch/api/v1/",
    new URLSearchParams({ query: "get_info", hash }).toString(),
    "MalwareBazaar",
  );
  const status = str(json.query_status);
  if (MB_NO_RESULT.has(status)) return null;
  if (status !== "ok") throw new Error(`MalwareBazaar query_status ${status || "(absent)"}`);
  const data = json.data;
  if (!Array.isArray(data)) throw new Error("MalwareBazaar: data is not a list");
  if (data.length === 0) return null;
  const d = data[0] as Record<string, unknown>;
  const sha256 = str(d.sha256_hash) || hash;
  const signature = str(d.signature);
  const fileType = str(d.file_type);
  const tags = new Set<string>();
  if (signature) tags.add(signature);
  for (const t of ((d.tags as string[] | undefined) ?? []).slice(0, 6)) if (t) tags.add(str(t));
  const temporal = dated({ observedFrom: str(d.first_seen), observedTo: str(d.last_seen) });
  return {
    source: "MalwareBazaar",
    ...ABUSE_CH_ORIGIN(),
    verdict: "malicious",
    score: signature ? `known: ${signature}` : `known sample${fileType ? ` (${fileType})` : ""}`,
    tags: [...tags],
    link: `https://bazaar.abuse.ch/sample/${encodeURIComponent(sha256)}/`,
    providerRecordId: sha256,
    ...(temporal ? { temporal } : {}),
  };
}

// ThreatFox — tracked IOC (C2 / payload). Hash uses search_hash; IP/domain/URL use search_ioc.
async function tfLookup(ctx: AbuseCtx, kind: IocKind, value: string): Promise<EnrichmentResult | null> {
  const body =
    kind === "hash"
      ? { query: "search_hash", hash: value }
      : { query: "search_ioc", search_term: value, exact_match: true };
  const json = await ctx.post("https://threatfox-api.abuse.ch/api/v1/", body, "ThreatFox");
  // A discriminated reading (#1024): only the documented no-result statuses are a miss; an
  // unknown status or an unexpected shape is an ERROR, never a miss.
  const status = str(json.query_status);
  if (TF_NO_RESULT.has(status)) return null;
  if (status !== "ok") throw new Error(`ThreatFox query_status ${status || "(absent)"}`);
  const rows = json.data;
  if (!Array.isArray(rows)) throw new Error("ThreatFox: data is not a list");
  if (rows.length === 0) return null;
  const d = (rows as Array<Record<string, unknown>>).reduce(
    (best, r) => (num(r.confidence_level) > num(best.confidence_level) ? r : best),
    rows[0],
  );
  const confidence = num(d.confidence_level);
  const malware = str(d.malware_printable);
  const threatType = str(d.threat_type);
  const tags = new Set<string>();
  if (malware && malware.toLowerCase() !== "unknown") tags.add(malware);
  if (threatType) tags.add(threatType);
  for (const t of ((d.tags as string[] | undefined) ?? []).slice(0, 6)) if (t) tags.add(str(t));
  const desc = [malware, threatType.replace(/_/g, " ")].filter(Boolean).join(", ") || "tracked IOC";
  const id = str(d.id);
  const temporal = dated({ observedFrom: str(d.first_seen), observedTo: str(d.last_seen) });
  return {
    source: "ThreatFox",
    ...ABUSE_CH_ORIGIN(),
    verdict: confidence >= 50 ? "malicious" : "suspicious",
    score: `${desc}${confidence ? ` (${confidence}% confidence)` : ""}`,
    tags: [...tags],
    link: id
      ? `https://threatfox.abuse.ch/ioc/${encodeURIComponent(id)}/`
      : "https://threatfox.abuse.ch/browse/",
    ...(id ? { providerRecordId: id } : {}),
    ...(temporal ? { temporal } : {}),
    note: TF_EXPIRY_NOTE,
  };
}

// URLhaus — malware-distribution URLs. host (IP/domain), url, or payload (hash).
async function urlhausLookup(ctx: AbuseCtx, kind: IocKind, value: string): Promise<EnrichmentResult | null> {
  const endpoint = kind === "hash" ? "payload" : kind === "url" ? "url" : "host";
  const field =
    kind === "hash" ? (value.length === 32 ? "md5_hash" : "sha256_hash") : kind === "url" ? "url" : "host";
  const json = await ctx.post(
    `https://urlhaus-api.abuse.ch/v1/${endpoint}/`,
    new URLSearchParams({ [field]: value }).toString(),
    "URLhaus",
  );
  const status = str(json.query_status);
  if (URLHAUS_NO_RESULT.has(status)) return null;
  // `invalid_*` is the provider refusing the value — not a miss, not a hit: an error the service retries.
  if (status !== "ok") throw new Error(`URLhaus query_status ${status || "(absent)"}`);
  const urlCount = num(json.url_count);
  const threat = str(json.threat);
  const signature = str(json.signature);
  const tags = new Set<string>();
  if (threat) tags.add(threat);
  if (signature) tags.add(signature);
  const blacklists = json.blacklists as Record<string, unknown> | undefined;
  for (const b of blacklists ? Object.keys(blacklists) : []) tags.add(b);
  const desc =
    kind === "hash"
      ? `malware payload${signature ? ` (${signature})` : ""}${urlCount ? `, ${urlCount} URL(s)` : ""}`
      : kind === "url"
        ? `malware URL${str(json.url_status) ? ` (${str(json.url_status)})` : ""}`
        : `${urlCount} malware URL(s) hosted`;
  const link =
    str(json.urlhaus_reference) || `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(value)}`;
  // Dated facts per endpoint (#1024): a URL's `date_added` is when it entered the dataset — never
  // when the infrastructure came to exist; `last_online` only when the provider reports one; a
  // host's top-level `firstseen`; a payload's `firstseen` / `lastseen`. The nested URL list is cut
  // by the API at 100 (host) / 1000 (payload): `truncated` says the count covers what was returned.
  const nested = Array.isArray(json.urls) ? json.urls.length : 0;
  const temporal =
    kind === "url"
      ? dated({ addedAt: str(json.date_added), lastOnlineAt: str(json.last_online) })
      : kind === "hash"
        ? dated({
            observedFrom: str(json.firstseen),
            observedTo: str(json.lastseen),
            truncated: nested >= 1000,
          })
        : dated({ observedFrom: str(json.firstseen), truncated: nested >= 100 });
  const recordId = kind === "url" ? str(json.id) : kind === "hash" ? str(json.sha256_hash) || value : value;
  return {
    source: "URLhaus",
    ...ABUSE_CH_ORIGIN(),
    verdict: "malicious",
    score: desc,
    tags: [...tags],
    link,
    ...(recordId ? { providerRecordId: recordId } : {}),
    ...(temporal ? { temporal } : {}),
  };
}

// YARAify — which YARA rules / ClamAV signatures matched a sample (hash only).
async function yaraifyLookup(ctx: AbuseCtx, hash: string): Promise<EnrichmentResult | null> {
  const json = await ctx.post(
    "https://yaraify-api.abuse.ch/api/v1/",
    { query: "lookup_hash", search_term: hash },
    "YARAify",
  );
  const status = str(json.query_status);
  if (YARAIFY_NO_RESULT.has(status)) return null;
  if (status !== "ok") throw new Error(`YARAify query_status ${status || "(absent)"}`);
  const data = json.data as Record<string, unknown> | undefined;
  if (!data || typeof data !== "object") throw new Error("YARAify: data is not an object");
  const meta = (data.metadata as Record<string, unknown> | undefined) ?? {};
  const tasks = (data.tasks as Array<Record<string, unknown>> | undefined) ?? [];
  const rules = new Set<string>();
  const clamav = new Set<string>();
  for (const t of tasks) {
    for (const s of (t.static_results as Array<Record<string, unknown>> | undefined) ?? []) {
      const name = str(s.rule_name);
      if (name) rules.add(name);
    }
    for (const c of (t.clamav_results as string[] | undefined) ?? []) if (c) clamav.add(str(c));
  }
  if (rules.size === 0 && clamav.size === 0) return null; // seen, but nothing matched
  const sha256 = str(meta.sha256_hash) || hash;
  const tags = [...rules].slice(0, 4);
  const parts: string[] = [];
  if (rules.size) parts.push(`${rules.size} YARA rule(s)`);
  if (clamav.size) parts.push(`${clamav.size} ClamAV sig(s)`);
  const temporal = dated({ observedFrom: str(meta.first_seen), observedTo: str(meta.last_seen) });
  return {
    source: "YARAify",
    ...ABUSE_CH_ORIGIN(),
    verdict: rules.size > 0 ? "malicious" : "suspicious",
    score: parts.join(", "),
    tags,
    link: `https://yaraify.abuse.ch/sample/${encodeURIComponent(sha256)}/`,
    providerRecordId: sha256,
    ...(temporal ? { temporal } : {}),
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
const BACKENDS = ["MalwareBazaar", "ThreatFox", "URLhaus", "YARAify"];
const errorText = (e: unknown): string => (e instanceof Error ? e.message : String(e)).slice(0, 200);

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

  /** Every backend, with the ones that do not serve this kind marked `not-queried`. */
  private backends(
    kind: IocKind,
    value: string,
  ): Array<{ name: string; run: Promise<EnrichmentResult | null> | null }> {
    const serves = (names: string[]) => (n: string) => names.includes(n);
    const forKind = serves(kind === "hash" ? BACKENDS : ["ThreatFox", "URLhaus"]);
    return BACKENDS.map((name) => ({
      name,
      run: !forKind(name)
        ? null
        : name === "MalwareBazaar"
          ? mbLookup(this.ctx, value)
          : name === "ThreatFox"
            ? tfLookup(this.ctx, kind, value)
            : name === "URLhaus"
              ? urlhausLookup(this.ctx, kind, value)
              : yaraifyLookup(this.ctx, value),
    }));
  }

  /** Per-backend outcomes (#1024): an errored backend is neither a miss nor checked; it keeps its last-known state. */
  async lookupDetailed(kind: IocKind, value: string): Promise<DetailedLookup> {
    if (!this.supports(kind))
      return { results: [], backends: BACKENDS.map((name) => ({ name, outcome: "not-queried" })) };
    const backends = this.backends(kind, value);
    const settled = await Promise.allSettled(backends.map((b) => b.run ?? Promise.resolve(null)));
    const results: EnrichmentResult[] = [];
    const outcomes: BackendOutcome[] = [];
    settled.forEach((s, i) => {
      const name = backends[i].name;
      if (!backends[i].run) outcomes.push({ name, outcome: "not-queried" });
      else if (s.status === "fulfilled") {
        if (s.value) results.push(s.value);
        outcomes.push({
          name,
          outcome: s.value ? "hit" : "miss",
          ...(s.value?.temporal?.truncated ? { incomplete: true } : {}),
        });
      } else outcomes.push({ name, outcome: "error", detail: errorText(s.reason) });
    });
    return { results, backends: outcomes };
  }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult[] | null> {
    if (!this.supports(kind)) return null;
    const settled = await Promise.allSettled(
      this.backends(kind, value).map((b) => b.run ?? Promise.resolve(null)),
    );
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
    if (authFailed)
      throw new Error("Hunting.ch (abuse.ch) auth failed — check DFIR_HUNTINGCH_KEY (or DFIR_MB_KEY)");
    // Every back-end errored (transient outage) → throw so the IOC is retried next run
    // rather than cached as "checked, no intel".
    if (nonAuthError) throw new Error("Hunting.ch: all abuse.ch lookups failed");
    return []; // every platform answered "not found"
  }
}
