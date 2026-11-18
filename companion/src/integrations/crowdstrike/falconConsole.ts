// The Falcon web console host for the SIEM client's tenant (#2685, "Open in Falcon").
//
// A CQL card links to Next-Gen SIEM Advanced event search on the console — a plain link, no API call
// and no credentials. The console host follows the same cloud setting the API client uses. An
// explicit base URL override counts only when its host is a known regional API host; any other host
// (a proxy, a test server) leaves the console on the cloud's default. gov-us-2 has no confirmed
// console address here, so it gets no link rather than a guessed one.

import { resolveFalconBase } from "./falconAuth.js";
import type { NgsiemCredentials } from "./ngsiemConfig.js";

/** Regional API host -> its console origin. */
const CONSOLE_BY_API_HOST: Readonly<Record<string, string>> = {
  "api.crowdstrike.com": "https://falcon.crowdstrike.com",
  "api.us-2.crowdstrike.com": "https://falcon.us-2.crowdstrike.com",
  "api.eu-1.crowdstrike.com": "https://falcon.eu-1.crowdstrike.com",
  "api.laggar.gcw.crowdstrike.com": "https://falcon.laggar.gcw.crowdstrike.com",
};

const hostOf = (url: string): string => {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
};

/** The console origin for these settings, or undefined when it is not known. */
export function falconConsoleOrigin(creds: Pick<NgsiemCredentials, "cloud" | "baseUrl">): string | undefined {
  const override = creds.baseUrl ? CONSOLE_BY_API_HOST[hostOf(creds.baseUrl)] : undefined;
  if (override) return override;
  const cloudBase = resolveFalconBase({ ...(creds.cloud ? { cloud: creds.cloud } : {}) });
  return CONSOLE_BY_API_HOST[hostOf(cloudBase)];
}
