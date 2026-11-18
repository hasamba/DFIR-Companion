// The fetch the NG-SIEM client uses (#2685): the default one, or — when DFIR_CROWDSTRIKE_SIEM_CA is
// set — one whose TLS trust is the default roots PLUS that PEM bundle. Supplementing rather than
// replacing keeps one server working both on a network that inspects TLS (the proxy's root CA) and
// off it (CrowdStrike's real chain). "default" is Node's own trust list, so NODE_EXTRA_CA_CERTS and
// --use-system-ca keep working beside the bundle. Verification is never off; there is no insecure option.
//
// One undici Agent per bundle (path + size + mtime), cached, so searches share one connection pool.
// A replaced Agent is NOT closed: a search already running holds a fetch bound to it and still has
// polls, pages, a token refresh and its cancel to send — closing it would cut that search off and
// leave its Falcon job running. Once those requests end, its idle keep-alive sockets time out
// (seconds) and the unreferenced Agent is collected. Bundle changes are rare, so this costs nothing.

import { readFileSync, statSync } from "node:fs";
import * as tls from "node:tls";
import { Agent, fetch as undiciFetch } from "undici";
import type { FalconFetch } from "./falconAuth.js";

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

/** A CA bundle the analyst must fix in Settings. The message names the path, never its contents. */
export class NgsiemCaError extends Error {}

/** Node's default trust (bundled + NODE_EXTRA_CA_CERTS + system when enabled); the bundled roots on older Node. */
function defaultTrust(): readonly string[] {
  const get = (tls as { getCACertificates?: (type: string) => string[] }).getCACertificates;
  return typeof get === "function" ? get("default") : tls.rootCertificates;
}

let cached: { key: string; agent: Agent; fetchFn: FalconFetch } | undefined;

function caKey(path: string): string {
  try {
    const st = statSync(path);
    return `${path}\u0000${st.size}\u0000${st.mtimeMs}`;
  } catch (err) {
    throw new NgsiemCaError(
      `DFIR_CROWDSTRIKE_SIEM_CA could not be read (${path}): ${(err as NodeJS.ErrnoException).code ?? "unreadable"}. Point it at a PEM file this server can read.`,
    );
  }
}

/** The SIEM fetch for a CA bundle path (undefined -> the default fetch). Throws NgsiemCaError. */
export function ngsiemFetchFor(caPath: string | undefined): FalconFetch {
  if (!caPath) return fetch;
  const key = caKey(caPath);
  if (cached?.key === key) return cached.fetchFn;
  let pem: string;
  try {
    pem = readFileSync(caPath, "utf8");
  } catch (err) {
    throw new NgsiemCaError(
      `DFIR_CROWDSTRIKE_SIEM_CA could not be read (${caPath}): ${(err as NodeJS.ErrnoException).code ?? "unreadable"}.`,
    );
  }
  if (!PEM_CERT.test(pem)) {
    throw new NgsiemCaError(
      `DFIR_CROWDSTRIKE_SIEM_CA (${caPath}) holds no PEM certificate. It must contain at least one "-----BEGIN CERTIFICATE-----" block.`,
    );
  }
  const agent = new Agent({ connect: { ca: [...defaultTrust(), pem] } });
  const fetchFn = ((input: string | URL | Request, init?: RequestInit) =>
    undiciFetch(input as string, { ...(init ?? {}), dispatcher: agent } as never)) as unknown as FalconFetch;
  cached = { key, agent, fetchFn };
  return fetchFn;
}

/** Test seam: the Agent behind the current bundle, if any. */
export function currentNgsiemAgentForTest(): Agent | undefined {
  return cached?.agent;
}
