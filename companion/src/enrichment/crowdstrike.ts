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
import {
  FalconAuthError,
  FalconTokenSource,
  resolveFalconBase,
} from "../integrations/crowdstrike/falconAuth.js";

export interface CrowdStrikeOptions {
  clientId: string;
  clientSecret: string;
  cloud?: string; // us-1 (default) | us-2 | eu-1 | gov-us-1 | gov-us-2
  baseUrl?: string; // explicit API base override (wins over `cloud`)
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

// Raised on a credential / missing-scope failure (401/403) so the provider can surface ONE
// actionable message and still return whatever the other back-end produced. The sign-in itself
// (cloud -> base, OAuth2 token) is shared with the NG-SIEM search client: integrations/crowdstrike.
class CsAuthError extends FalconAuthError {}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function str(v: unknown): string {
  return v === undefined || v === null ? "" : String(v);
}
function isSha256(v: string): boolean {
  return /^[a-f0-9]{64}$/i.test(v);
}

/**
 * Escape a value for a single-quoted FQL string literal. encodeURIComponent protects the URL, not
 * the query language underneath it: a quote inside the value still terminates the literal. IOC
 * values arrive from parsed evidence and a quote is legal in a URL, so without this a single
 * apostrophe malforms the filter — CrowdStrike 400s and that IOC fails on every enrichment run
 * from then on — or closes the literal and changes what the query asks. Backslash first, or it
 * would escape the escapes added after it.
 */
function escapeFqlLiteral(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

// Lineage (#933 item 18): Falcon Intelligence and MalQuery are CrowdStrike's own data — first-party.
const CROWDSTRIKE_ORIGIN = (): Pick<EnrichmentResult, "originKind" | "origins"> => ({
  originKind: "first-party",
  origins: ["CrowdStrike"],
});

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
  private readonly tokens: FalconTokenSource;

  constructor(private readonly opts: CrowdStrikeOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = resolveFalconBase(opts);
    this.timeoutMs = opts.timeoutMs ?? 20_000;
    this.tokens = new FalconTokenSource({
      clientId: opts.clientId,
      clientSecret: opts.clientSecret,
      base: this.base,
      fetchFn: this.fetchFn,
      timeoutMs: this.timeoutMs,
      authFailedMessage:
        "CrowdStrike auth failed — check DFIR_CROWDSTRIKE_CLIENT_ID / _SECRET and the cloud region",
      label: "CrowdStrike",
    });
  }

  supports(kind: IocKind): boolean {
    return kind === "hash" || kind === "ip" || kind === "domain" || kind === "url";
  }

  private ensureToken(force = false): Promise<string> {
    return this.tokens.get(force);
  }

  // GET with bearer auth; refreshes the token once on a 401. 403 → missing scope (actionable).
  private async apiGet(path: string, scopeHint: string): Promise<Record<string, unknown>> {
    const call = async (token: string) =>
      this.fetchFn(`${this.base}${path}`, {
        headers: { authorization: `Bearer ${token}`, accept: "application/json" },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    let res = await call(await this.ensureToken());
    if (res.status === 401) res = await call(await this.ensureToken(true)); // token expired → refresh once
    if (res.status === 403)
      throw new CsAuthError(`CrowdStrike 403 — API client is missing scope: ${scopeHint}`);
    if (res.status === 429)
      throw new RateLimitError("CrowdStrike rate limit", parseRetryAfterMs(res.headers.get("retry-after")));
    if (res.status === 404) return {};
    if (!res.ok) throw new Error(`CrowdStrike HTTP ${res.status}`);
    return readBoundedJson<Record<string, unknown>>(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: "CrowdStrike",
    });
  }

  // Falcon Intelligence Indicators — adversary-attributed IOC intel.
  private async intelLookup(value: string): Promise<EnrichmentResult | null> {
    const filter = encodeURIComponent(`indicator:'${escapeFqlLiteral(value)}'`);
    const json = await this.apiGet(
      `/intel/combined/indicators/v1?filter=${filter}&limit=1&sort=last_updated.desc`,
      "Indicators (Falcon Intelligence): Read",
    );
    const resources = asArray(json.resources) as Array<Record<string, unknown>>;
    if (!resources.length) return null;
    const d = resources[0];
    const conf = str(d.malicious_confidence).toLowerCase();
    const verdict: Verdict =
      conf === "high" ? "malicious" : conf === "medium" || conf === "low" ? "suspicious" : "unknown";
    const families = asArray(d.malware_families).map(str).filter(Boolean);
    const actors = asArray(d.actors)
      .map((a) => (typeof a === "string" ? a : str((a as Record<string, unknown>)?.name)))
      .filter(Boolean);
    const threatTypes = asArray(d.threat_types).map(str).filter(Boolean);
    const tags = [...new Set([...families, ...actors.map((a) => `actor: ${a}`), ...threatTypes])].slice(0, 8);
    const parts: string[] = [];
    if (conf) parts.push(`${conf} confidence`);
    if (families[0]) parts.push(families[0]);
    if (actors[0]) parts.push(`actor: ${actors[0]}`);
    return {
      source: "CrowdStrike Intel",
      ...CROWDSTRIKE_ORIGIN(),
      verdict,
      score: parts.join(" — ") || "tracked indicator",
      tags,
    };
  }

  // MalQuery — CrowdStrike's malware sample corpus (keyed by sha256).
  private async malqueryLookup(sha256: string): Promise<EnrichmentResult | null> {
    const json = await this.apiGet(
      `/malquery/entities/metadata/v1?ids=${encodeURIComponent(sha256)}`,
      "MalQuery: Read",
    );
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
      ...CROWDSTRIKE_ORIGIN(),
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
    let authFailed = false; // a 403 = a missing scope on ONE endpoint; the other may still work
    let otherError = false;

    try {
      const r = await this.intelLookup(value);
      if (r) results.push(r);
    } catch (e) {
      if (e instanceof FalconAuthError) authFailed = true;
      else otherError = true;
    }

    if (kind === "hash" && isSha256(value)) {
      try {
        const r = await this.malqueryLookup(value);
        if (r) results.push(r);
      } catch (e) {
        if (e instanceof FalconAuthError) authFailed = true;
        else otherError = true;
      }
    }

    if (results.length > 0) return results; // resilient: return whatever answered
    if (authFailed)
      throw new Error(
        "CrowdStrike: API client is missing a required scope — Indicators (Falcon Intelligence): Read and/or MalQuery: Read",
      );
    if (otherError) throw new Error("CrowdStrike lookups failed");
    return []; // authenticated, but nothing tracked
  }
}
