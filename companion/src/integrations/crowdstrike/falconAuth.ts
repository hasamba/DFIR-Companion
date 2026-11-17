// CrowdStrike Falcon API sign-in, shared by every Falcon client (#2666): the threat-intel enrichment
// provider (enrichment/crowdstrike.ts) and the Next-Gen SIEM search client (ngsiemSearch.ts).
//
// Two things live here: which regional API base a tenant's cloud maps to, and the OAuth2
// client-credentials token (Client ID + Secret -> a short-lived bearer, cached and refreshed). Each
// client has its own API client and so its own token source; the secret never leaves this file in
// an error message.

import { readBoundedJson, RESPONSE_SIZE_LIMITS } from "../../providers/boundedResponse.js";

export type FalconFetch = typeof fetch;

// CrowdStrike Falcon regional API bases. The tenant's cloud determines which one to hit.
export const FALCON_API_BASE: Readonly<Record<string, string>> = {
  "us-1": "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  "gov-us-1": "https://api.laggar.gcw.crowdstrike.com",
  "gov-us-2": "https://api.us-gov-2.crowdstrike.mil",
};

const FALCON_CLOUD_ALIAS: Readonly<Record<string, string>> = {
  us1: "us-1",
  us: "us-1",
  "us-1": "us-1",
  us2: "us-2",
  "us-2": "us-2",
  eu1: "eu-1",
  eu: "eu-1",
  "eu-1": "eu-1",
  gov: "gov-us-1",
  gov1: "gov-us-1",
  govus1: "gov-us-1",
  "gov-us-1": "gov-us-1",
  usgov1: "gov-us-1",
  gov2: "gov-us-2",
  govus2: "gov-us-2",
  "gov-us-2": "gov-us-2",
  usgov2: "gov-us-2",
};

/** The API base for a tenant: an explicit base URL wins, else the cloud's region (default us-1). */
export function resolveFalconBase(opts: { cloud?: string; baseUrl?: string }): string {
  if (opts.baseUrl) return opts.baseUrl.replace(/\/+$/, "");
  const key = FALCON_CLOUD_ALIAS[(opts.cloud ?? "us-1").trim().toLowerCase()] ?? "us-1";
  return FALCON_API_BASE[key];
}

/** A credential or scope failure the analyst must fix in Settings (bad ID/secret/region, 401/403). */
export class FalconAuthError extends Error {}

export interface FalconTokenOptions {
  clientId: string;
  clientSecret: string;
  base: string;
  fetchFn: FalconFetch;
  timeoutMs: number;
  /** The sentence a rejected sign-in throws: names the settings to check, never the secret. */
  authFailedMessage: string;
  /** Short name for errors and the bounded-read context, e.g. "CrowdStrike". */
  label: string;
}

/** OAuth2 client-credentials. CrowdStrike returns 201 with { access_token, expires_in }. */
export class FalconTokenSource {
  private token = "";
  private expiresAt = 0; // epoch ms; refresh before this

  constructor(private readonly opts: FalconTokenOptions) {}

  /** `signal` aborts the sign-in together with the caller's work; the token timeout still applies. */
  async get(force = false, signal?: AbortSignal): Promise<string> {
    if (!force && this.token && Date.now() < this.expiresAt) return this.token;
    const { clientId, clientSecret, base, fetchFn, timeoutMs, label } = this.opts;
    const body = new URLSearchParams({ client_id: clientId, client_secret: clientSecret });
    const timeout = AbortSignal.timeout(timeoutMs);
    const res = await fetchFn(`${base}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: body.toString(),
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    });
    if (res.status === 400 || res.status === 401 || res.status === 403) {
      throw new FalconAuthError(this.opts.authFailedMessage);
    }
    if (!res.ok) throw new Error(`${label} token HTTP ${res.status}`);
    const json = await readBoundedJson<{ access_token?: string; expires_in?: number }>(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: label,
    });
    if (!json.access_token) throw new FalconAuthError(`${label} token response missing access_token`);
    this.token = json.access_token;
    this.expiresAt = Date.now() + Math.max(0, (json.expires_in ?? 1799) - 60) * 1000; // 60s margin
    return this.token;
  }
}
