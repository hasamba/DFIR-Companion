import { RateLimitError, parseRetryAfterMs, type EnrichmentProvider, type EnrichmentResult, type FetchFn, type IocKind, type Verdict } from "./provider.js";

export interface CrowdStrikeOptions {
  clientId: string;
  clientSecret: string;
  cloud?: string;        // us-1 (default) | us-2 | eu-1 | gov-us-1 | gov-us-2
  baseUrl?: string;      // explicit API base override (wins over `cloud`)
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

// CrowdStrike Falcon regional API bases. The tenant's cloud determines which one to hit.
const API_BASE: Record<string, string> = {
  "us-1": "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  "gov-us-1": "https://api.laggar.gcw.crowdstrike.com",
  "gov-us-2": "https://api.us-gov-2.crowdstrike.mil",
};
const CLOUD_ALIAS: Record<string, string> = {
  us1: "us-1", us: "us-1", "us-1": "us-1",
  us2: "us-2", "us-2": "us-2",
  eu1: "eu-1", eu: "eu-1", "eu-1": "eu-1",
  gov: "gov-us-1", gov1: "gov-us-1", govus1: "gov-us-1", "gov-us-1": "gov-us-1", usgov1: "gov-us-1",
  gov2: "gov-us-2", govus2: "gov-us-2", "gov-us-2": "gov-us-2", usgov2: "gov-us-2",
};

function resolveBase(opts: CrowdStrikeOptions): string {
  if (opts.baseUrl) return opts.baseUrl.replace(/\/+$/, "");
  const key = CLOUD_ALIAS[(opts.cloud ?? "us-1").trim().toLowerCase()] ?? "us-1";
  return API_BASE[key];
}

// Raised on a credential / missing-scope failure (401/403) so the provider can surface ONE
// actionable message and still return whatever the other back-end produced.
class CsAuthError extends Error {}

function asArray(v: unknown): unknown[] { return Array.isArray(v) ? v : []; }
function str(v: unknown): string { return v === undefined || v === null ? "" : String(v); }
function isSha256(v: string): boolean { return /^[a-f0-9]{64}$/i.test(v); }

// CrowdStrike Falcon — Threat Intelligence enrichment (NO endpoint/SIEM data). One indicator is
// looked up across the abuse-free, intel-only back-ends and each hit is a SEPARATE result:
//   hash         → Falcon Intelligence Indicators + MalQuery sample metadata
//   ip/domain/url → Falcon Intelligence Indicators
// Auth is OAuth2 client-credentials (Client ID + Secret → short-lived bearer, cached + refreshed).
// Needs an API client with "Indicators (Falcon Intelligence): Read" (+ "MalQuery: Read" for hashes).
export class CrowdStrikeProvider implements EnrichmentProvider {
  readonly name = "CrowdStrike";
  readonly scope = "external" as const;
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;
  private token = "";
  private tokenExpiresAt = 0;   // epoch ms; refresh before this

  constructor(private readonly opts: CrowdStrikeOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = resolveBase(opts);
    this.timeoutMs = opts.timeoutMs ?? 20_000;
  }

  supports(kind: IocKind): boolean {
    return kind === "hash" || kind === "ip" || kind === "domain" || kind === "url";
  }

  // OAuth2 client-credentials. CrowdStrike returns 201 with { access_token, expires_in }.
  private async ensureToken(force = false): Promise<string> {
    if (!force && this.token && Date.now() < this.tokenExpiresAt) return this.token;
    const body = new URLSearchParams({ client_id: this.opts.clientId, client_secret: this.opts.clientSecret });
    const res = await this.fetchFn(`${this.base}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: body.toString(),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (res.status === 400 || res.status === 401 || res.status === 403) {
      throw new CsAuthError("CrowdStrike auth failed — check DFIR_CROWDSTRIKE_CLIENT_ID / _SECRET and the cloud region");
    }
    if (!res.ok) throw new Error(`CrowdStrike token HTTP ${res.status}`);
    const json = (await res.json()) as { access_token?: string; expires_in?: number };
    if (!json.access_token) throw new CsAuthError("CrowdStrike token response missing access_token");
    this.token = json.access_token;
    this.tokenExpiresAt = Date.now() + Math.max(0, (json.expires_in ?? 1799) - 60) * 1000;   // 60s safety margin
    return this.token;
  }

  // GET with bearer auth; refreshes the token once on a 401. 403 → missing scope (actionable).
  private async apiGet(path: string, scopeHint: string): Promise<Record<string, unknown>> {
    const call = async (token: string) => this.fetchFn(`${this.base}${path}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    let res = await call(await this.ensureToken());
    if (res.status === 401) res = await call(await this.ensureToken(true));   // token expired → refresh once
    if (res.status === 403) throw new CsAuthError(`CrowdStrike 403 — API client is missing scope: ${scopeHint}`);
    if (res.status === 429) throw new RateLimitError("CrowdStrike rate limit", parseRetryAfterMs(res.headers.get("retry-after")));
    if (res.status === 404) return {};
    if (!res.ok) throw new Error(`CrowdStrike HTTP ${res.status}`);
    return (await res.json()) as Record<string, unknown>;
  }

  // Falcon Intelligence Indicators — adversary-attributed IOC intel.
  private async intelLookup(value: string): Promise<EnrichmentResult | null> {
    const filter = encodeURIComponent(`indicator:'${value}'`);
    const json = await this.apiGet(
      `/intel/combined/indicators/v1?filter=${filter}&limit=1&sort=last_updated.desc`,
      "Indicators (Falcon Intelligence): Read",
    );
    const resources = asArray(json.resources) as Array<Record<string, unknown>>;
    if (!resources.length) return null;
    const d = resources[0];
    const conf = str(d.malicious_confidence).toLowerCase();
    const verdict: Verdict = conf === "high" ? "malicious" : conf === "medium" || conf === "low" ? "suspicious" : "unknown";
    const families = asArray(d.malware_families).map(str).filter(Boolean);
    const actors = asArray(d.actors).map((a) => (typeof a === "string" ? a : str((a as Record<string, unknown>)?.name))).filter(Boolean);
    const threatTypes = asArray(d.threat_types).map(str).filter(Boolean);
    const tags = [...new Set([...families, ...actors.map((a) => `actor: ${a}`), ...threatTypes])].slice(0, 8);
    const parts: string[] = [];
    if (conf) parts.push(`${conf} confidence`);
    if (families[0]) parts.push(families[0]);
    if (actors[0]) parts.push(`actor: ${actors[0]}`);
    return { source: "CrowdStrike Intel", verdict, score: parts.join(" — ") || "tracked indicator", tags };
  }

  // MalQuery — CrowdStrike's malware sample corpus (keyed by sha256).
  private async malqueryLookup(sha256: string): Promise<EnrichmentResult | null> {
    const json = await this.apiGet(`/malquery/entities/metadata/v1?ids=${encodeURIComponent(sha256)}`, "MalQuery: Read");
    const resources = asArray(json.resources) as Array<Record<string, unknown>>;
    if (!resources.length) return null;
    const d = resources[0];
    const family = str(d.family || d.malware_family);
    const label = str(d.label).toLowerCase();
    const fileType = str(d.filetype || d.type);
    const malicious = label === "malicious" || Boolean(family);
    const tags = [family, fileType].filter(Boolean);
    return {
      source: "CrowdStrike MalQuery",
      verdict: malicious ? "malicious" : "unknown",
      score: malicious
        ? `known sample${family ? `: ${family}` : ""}${fileType ? ` (${fileType})` : ""}`
        : `in MalQuery corpus${fileType ? ` (${fileType})` : ""}, unclassified`,
      tags,
    };
  }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult[] | null> {
    if (!this.supports(kind)) return null;
    // Fail fast and loud on a hard credential failure (bad ID/secret/region) — nothing else
    // can succeed, and the error tells the analyst exactly what to fix.
    await this.ensureToken();

    const results: EnrichmentResult[] = [];
    let authFailed = false;   // a 403 = a missing scope on ONE endpoint; the other may still work
    let otherError = false;

    try {
      const r = await this.intelLookup(value);
      if (r) results.push(r);
    } catch (e) {
      if (e instanceof CsAuthError) authFailed = true; else otherError = true;
    }

    if (kind === "hash" && isSha256(value)) {
      try {
        const r = await this.malqueryLookup(value);
        if (r) results.push(r);
      } catch (e) {
        if (e instanceof CsAuthError) authFailed = true; else otherError = true;
      }
    }

    if (results.length > 0) return results;   // resilient: return whatever answered
    if (authFailed) throw new Error("CrowdStrike: API client is missing a required scope — Indicators (Falcon Intelligence): Read and/or MalQuery: Read");
    if (otherError) throw new Error("CrowdStrike lookups failed");
    return [];   // authenticated, but nothing tracked
  }
}
