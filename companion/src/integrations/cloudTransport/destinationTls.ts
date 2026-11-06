import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { rootCertificates } from "node:tls";
import { buildTlsConnect } from "../../enrichment/tlsFetch.js";

// Cloud collection (#2310): the outbound TLS policy, decided for each REAL destination host.
//
// One cloud run talks to many hosts — a token endpoint (sts.amazonaws.com, login.microsoftonline.com,
// oauth2.googleapis.com) and then the data endpoints — and every one of them gets the same rules the
// other outbound features use (enrichment/tlsFetch.ts):
//   - a CA bundle keeps verification ON and is trusted for every cloud host;
//   - "skip verification" is refused for a non-loopback host unless DFIR_TLS_ALLOW_INSECURE_EXTERNAL
//     is true. Cloud hosts are never loopback, so the override applies exactly as it does to the
//     other env-configured integrations.
// The decision is made per host, not once per client: the loopback guard can only be honest when it
// sees the host the socket really connects to.

/** The cloud transport settings, already resolved from the environment by composition. */
export interface CloudTransportSettings {
  /** Path to a PEM CA bundle (an inspecting proxy's CA, a private CA). Added to the built-in trust. */
  caCertPath?: string;
  /** Skip certificate verification. Refused for a non-loopback host without the global override. */
  insecure?: boolean;
  /** An http:// or https:// proxy that every cloud request tunnels through with CONNECT. */
  proxyUrl?: string;
}

/** The TLS options one destination's socket is opened with. Empty means the default trust. */
export interface DestinationTls {
  ca?: string[];
  rejectUnauthorized?: false;
}

export interface DestinationTlsDeps {
  readFile?: (path: string) => string;
  onWarn?: (message: string) => void;
}

export type DestinationTlsPolicy = (host: string) => DestinationTls;

export class CloudTransportError extends Error {}

function readCa(path: string, read: (p: string) => string): string {
  try {
    return read(path);
  } catch (err) {
    // The path is configuration, not a secret; the file's contents never reach the message.
    const code = (err as NodeJS.ErrnoException).code;
    throw new CloudTransportError(`Cloud CA bundle '${path}' could not be read${code ? ` (${code})` : ""}`);
  }
}

const urlHost = (host: string): string => (isIP(host) === 6 ? `[${host}]` : host);

/**
 * The per-destination TLS decision. The CA bundle is read once, here, so a missing file fails the
 * whole run up front instead of every request later. A refused host is remembered with its error,
 * so the warning and the refusal are each said once per host, not once per socket.
 */
export function destinationTlsPolicy(
  settings: CloudTransportSettings,
  deps: DestinationTlsDeps = {},
): DestinationTlsPolicy {
  const read = deps.readFile ?? ((p: string) => readFileSync(p, "utf8"));
  const caText = settings.caCertPath ? readCa(settings.caCertPath, read) : undefined;
  const cache = new Map<string, DestinationTls | Error>();

  const decide = (host: string): DestinationTls | Error => {
    try {
      const connect = buildTlsConnect(
        {
          caCertPath: caText === undefined ? undefined : "cloud-ca",
          insecureSkipVerify: Boolean(settings.insecure),
          hostUrl: `https://${urlHost(host)}`,
          onWarn: (m) => deps.onWarn?.(`cloud collection → ${host}: ${m}`),
        },
        { readFile: () => caText ?? "" },
      );
      if (!connect) return {};
      return {
        // Added to the built-in roots, not instead of them: a host the proxy does not inspect still
        // presents its public certificate, and it must keep verifying.
        ...(connect.ca !== undefined ? { ca: [...rootCertificates, connect.ca] } : {}),
        ...(connect.rejectUnauthorized === false ? { rejectUnauthorized: false as const } : {}),
      };
    } catch (err) {
      return new CloudTransportError(`cloud collection → ${host}: ${(err as Error).message}`);
    }
  };

  return (host: string) => {
    const key = host.toLowerCase();
    let result = cache.get(key);
    if (result === undefined) {
      result = decide(key);
      cache.set(key, result);
    }
    if (result instanceof Error) throw result;
    return result;
  };
}
