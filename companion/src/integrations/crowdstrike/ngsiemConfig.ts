// The NG-SIEM search client's settings (#2666), read from process.env at the moment a search starts —
// DFIR_CROWDSTRIKE_ is a writable, reloadable prefix, so a Settings save applies without a restart.
//
// The SIEM client is a SEPARATE Falcon API client from the threat-intel one (least privilege; each
// feature switches on and off on its own). Only the cloud falls back to the threat-intel setting,
// because both clients live in the same tenant.
//
// #2685: the base URL is validated here, when it is read, so a console address or a value without
// https:// is a Settings sentence instead of "could not reach". DFIR_CROWDSTRIKE_SIEM_CA is a PEM
// bundle path that ADDS to the trusted roots (a TLS-inspecting proxy); verification is never off.

import { readSiemLimits, siemConfigured } from "../../analysis/siemSearch.js";
import { resolveFalconBase } from "./falconAuth.js";
import { NgsiemCaError, ngsiemFetchFor } from "./ngsiemTransport.js";

type Env = Readonly<Record<string, string | undefined>>;

export interface NgsiemCredentials {
  clientId: string;
  clientSecret: string;
  cloud?: string;
  baseUrl?: string;
  /** Path to a PEM CA bundle trusted in addition to the default roots. */
  ca?: string;
}

/** The SIEM API client's credentials and region, or null when the feature is off. */
export function ngsiemCredentialsFromEnv(env: Env): NgsiemCredentials | null {
  if (!siemConfigured(env)) return null;
  const cloud = (env.DFIR_CROWDSTRIKE_SIEM_CLOUD ?? "").trim() || (env.DFIR_CROWDSTRIKE_CLOUD ?? "").trim();
  const baseUrl = (env.DFIR_CROWDSTRIKE_SIEM_BASE_URL ?? "").trim();
  const ca = (env.DFIR_CROWDSTRIKE_SIEM_CA ?? "").trim();
  return {
    clientId: (env.DFIR_CROWDSTRIKE_SIEM_CLIENT_ID ?? "").trim(),
    clientSecret: (env.DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET ?? "").trim(),
    ...(cloud ? { cloud } : {}),
    ...(baseUrl ? { baseUrl } : {}),
    ...(ca ? { ca } : {}),
  };
}

const BASE_URL_HELP =
  "DFIR_CROWDSTRIKE_SIEM_BASE_URL must be https:// plus the Falcon API host (for example https://api.us-2.crowdstrike.com), or blank to use the cloud setting.";

/** Falcon's web console, which is not the API: falcon.crowdstrike.com, falcon.us-2.crowdstrike.com … */
const CONSOLE_HOST = /^falcon\.([a-z0-9-]+\.)*crowdstrike\.(com|mil)$/i;

/** An explicit API base: https, a host, no credentials, no query or fragment, not the console. */
export function checkFalconBaseUrl(raw: string): { ok: true; base: string } | { ok: false; error: string } {
  const value = raw.trim();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, error: `The base URL is not a valid URL. ${BASE_URL_HELP}` };
  }
  if (url.protocol !== "https:")
    return { ok: false, error: `The base URL must start with https://. ${BASE_URL_HELP}` };
  if (!url.hostname) return { ok: false, error: `The base URL has no host. ${BASE_URL_HELP}` };
  if (url.username || url.password)
    return { ok: false, error: `The base URL must not contain a user name or password. ${BASE_URL_HELP}` };
  if (url.search || url.hash || value.includes("?") || value.includes("#"))
    return { ok: false, error: `The base URL must not contain a query or fragment. ${BASE_URL_HELP}` };
  if (CONSOLE_HOST.test(url.hostname))
    return {
      ok: false,
      error: `The base URL is the Falcon console address, not the API — the API host starts with "api.". ${BASE_URL_HELP}`,
    };
  return { ok: true, base: `${url.origin}${url.pathname}`.replace(/\/+$/, "") };
}

/** The API base the client will call, after validation. */
export function ngsiemBase(
  creds: NgsiemCredentials,
): { ok: true; base: string } | { ok: false; error: string } {
  if (creds.baseUrl) return checkFalconBaseUrl(creds.baseUrl);
  return { ok: true, base: resolveFalconBase({ ...(creds.cloud ? { cloud: creds.cloud } : {}) }) };
}

/** A Settings problem that refuses a search before any call, or null (also null when off). */
export function ngsiemSettingsError(env: Env): string | null {
  const creds = ngsiemCredentialsFromEnv(env);
  if (!creds) return null;
  const base = ngsiemBase(creds);
  if (!base.ok) return base.error;
  try {
    ngsiemFetchFor(creds.ca); // an unreadable or empty CA bundle refuses before any call
    return null;
  } catch (err) {
    if (err instanceof NgsiemCaError) return err.message;
    throw err;
  }
}

/** "api.us-2.crowdstrike.com" (with ":port" when not 443) for messages — never a full URL. */
export function hostLabel(base: string): string {
  try {
    return new URL(base).host;
  } catch {
    return "the CrowdStrike API host";
  }
}

export { readSiemLimits, siemConfigured };
