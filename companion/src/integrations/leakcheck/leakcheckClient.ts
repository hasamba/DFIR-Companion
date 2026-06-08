// Minimal typed client for the LeakCheck Pro API v2 (https://wiki.leakcheck.io/en/api).
// GET https://leakcheck.io/api/v2/query/{query}?type={email|domain|...}; auth is the
// X-API-Key header. Used to check the CUSTOMER's own exposure (domains/emails) against
// breach data — this is deliberately NOT part of the IOC enrichment path, so an adversary
// indicator is never sent here.
//
// Like the other integrations, the HTTP transport is an injectable fetchFn so the
// orchestration and transforms can be unit-tested with no network.

import type { FetchFn } from "../../enrichment/provider.js";

export type LeakCheckType = "auto" | "email" | "domain" | "username" | "phone" | "hash" | "keyword";

export interface LeakCheckSource {
  name?: string;
  breach_date?: string;
  unverified?: number;
  passwordless?: number;
  compilation?: number;
}

// One leaked record. LeakCheck returns a variable set of fields per breach; everything past
// the common shape is optional (and we never persist the raw password — see leakReport).
export interface LeakCheckRecord {
  email?: string;
  username?: string;
  password?: string;
  source?: LeakCheckSource;
  fields?: string[];
  first_name?: string;
  last_name?: string;
  [k: string]: unknown;
}

export interface LeakCheckResult {
  success: boolean;
  found: number;
  quota?: number;          // remaining lookups on the plan
  result: LeakCheckRecord[];
  error?: string;
}

export class LeakCheckError extends Error {
  constructor(message: string, readonly status: number, readonly kind: "auth" | "permission" | "ratelimit" | "badrequest" | "http" | "api") {
    super(message);
    this.name = "LeakCheckError";
  }
}

export interface LeakCheckClientOptions {
  apiKey: string;          // LeakCheck Pro API key (>= 40 chars)
  fetchFn?: FetchFn;
  timeoutMs?: number;
  baseUrl?: string;        // default https://leakcheck.io/api/v2
}

export class LeakCheckClient {
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;

  constructor(private readonly opts: LeakCheckClientOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = (opts.baseUrl ?? "https://leakcheck.io/api/v2").replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 20_000;
  }

  async query(query: string, type: LeakCheckType, opts: { limit?: number; offset?: number } = {}): Promise<LeakCheckResult> {
    const params = new URLSearchParams({ type });
    if (opts.limit != null) params.set("limit", String(opts.limit));
    if (opts.offset != null) params.set("offset", String(opts.offset));
    const url = `${this.base}/query/${encodeURIComponent(query)}?${params.toString()}`;
    const res = await this.fetchFn(url, {
      headers: { "X-API-Key": this.opts.apiKey, accept: "application/json" },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    // Surface LeakCheck's OWN error text from the body for every failure — its 4xx codes are
    // ambiguous on their own (e.g. a 403 is "Active plan required" OR "Limit reached", never a
    // per-query-type thing), so the reason must come from `error`, not a guessed message.
    if (!res.ok) {
      const body = (await res.json().catch(() => ({}))) as { error?: string };
      const reason = body.error ? ` — ${body.error}` : "";
      if (res.status === 401) throw new LeakCheckError(`LeakCheck 401 (auth)${reason} — check DFIR_LEAKCHECK_KEY`, 401, "auth");
      if (res.status === 403) {
        throw new LeakCheckError(
          `LeakCheck 403 (forbidden)${reason} — LeakCheck returns 403 only for "Active plan required" or `
          + `"Limit reached": confirm DFIR_LEAKCHECK_KEY is the API key of your active (Enterprise) plan and the quota isn't exhausted`,
          403, "permission");
      }
      if (res.status === 429) throw new LeakCheckError(`LeakCheck rate limit${reason} (slow down DFIR_LEAKCHECK_DELAY_MS)`, 429, "ratelimit");
      if (res.status === 400 || res.status === 422) throw new LeakCheckError(`LeakCheck ${res.status}${reason || `: ${res.status}`}`, res.status, "badrequest");
      throw new LeakCheckError(`LeakCheck HTTP ${res.status}${reason}`, res.status, "http");
    }

    const json = (await res.json()) as Partial<LeakCheckResult>;
    // A genuine "no breaches" answer is success:true / found:0; success:false is an API-level error.
    if (json.success === false) throw new LeakCheckError(`LeakCheck: ${json.error ?? "query failed"}`, 200, "api");
    const result = Array.isArray(json.result) ? json.result : [];
    return { success: true, found: json.found ?? result.length, quota: json.quota, result, error: json.error };
  }

  queryEmail(email: string): Promise<LeakCheckResult> {
    return this.query(email, "email");
  }

  queryDomain(domain: string, limit = 1000): Promise<LeakCheckResult> {
    return this.query(domain, "domain", { limit });
  }
}
