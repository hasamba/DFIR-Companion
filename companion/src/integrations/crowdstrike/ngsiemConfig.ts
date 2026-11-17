// The NG-SIEM search client's settings (#2666), read from process.env at the moment a search starts —
// DFIR_CROWDSTRIKE_ is a writable, reloadable prefix, so a Settings save applies without a restart.
//
// The SIEM client is a SEPARATE Falcon API client from the threat-intel one (least privilege; each
// feature switches on and off on its own). Only the cloud falls back to the threat-intel setting,
// because both clients live in the same tenant.

import { readSiemLimits, siemConfigured } from "../../analysis/siemSearch.js";

type Env = Readonly<Record<string, string | undefined>>;

export interface NgsiemCredentials {
  clientId: string;
  clientSecret: string;
  cloud?: string;
  baseUrl?: string;
}

/** The SIEM API client's credentials and region, or null when the feature is off. */
export function ngsiemCredentialsFromEnv(env: Env): NgsiemCredentials | null {
  if (!siemConfigured(env)) return null;
  const cloud = (env.DFIR_CROWDSTRIKE_SIEM_CLOUD ?? "").trim() || (env.DFIR_CROWDSTRIKE_CLOUD ?? "").trim();
  const baseUrl = (env.DFIR_CROWDSTRIKE_SIEM_BASE_URL ?? "").trim();
  return {
    clientId: (env.DFIR_CROWDSTRIKE_SIEM_CLIENT_ID ?? "").trim(),
    clientSecret: (env.DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET ?? "").trim(),
    ...(cloud ? { cloud } : {}),
    ...(baseUrl ? { baseUrl } : {}),
  };
}

export { readSiemLimits, siemConfigured };
