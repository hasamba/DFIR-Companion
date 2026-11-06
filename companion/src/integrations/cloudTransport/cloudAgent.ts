import type { ClientRequest } from "node:http";
import { connect as netConnect, isIP } from "node:net";
import type { Duplex } from "node:stream";
import { connect as tlsConnect } from "node:tls";
import { Agent as AgentBase, type AgentConnectOpts } from "agent-base";
import { HttpsProxyAgent } from "https-proxy-agent";
import {
  CloudTransportError,
  destinationTlsPolicy,
  type CloudTransportSettings,
  type DestinationTlsDeps,
  type DestinationTlsPolicy,
} from "./destinationTls.js";

// The ONE Node agent every cloud SDK is handed (#2310). It is a Node http(s) Agent, so the AWS
// NodeHttpHandler, the Azure pipeline and gaxios (Google) all accept it as-is, and each socket it
// opens is decided for the host that socket really goes to: the token endpoint and the data
// endpoint each get the CA, insecure and proxy policy on their own.

/** An http:// or https:// proxy URL, checked here so a typo fails the run with a clear message. */
export function parseProxyUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new CloudTransportError("Cloud proxy URL is not a valid URL — expected http://host:port");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new CloudTransportError(
      `Cloud proxy URL must start with http:// or https://, not ${url.protocol}//`,
    );
  }
  return url;
}

/**
 * The proxy URL without its user:password. https-proxy-agent writes the URL it is given to its debug
 * log (DEBUG=https-proxy-agent), so the login travels only in the CONNECT header it never logs.
 */
function withoutCredentials(url: URL): URL {
  const bare = new URL(url.href);
  bare.username = "";
  bare.password = "";
  return bare;
}

/** Basic Proxy-Authorization for a proxy URL that carries a login, decoded the way browsers do. */
function proxyAuthHeaders(url: URL): Record<string, string> {
  if (!url.username && !url.password) return {};
  const login = `${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`;
  return { "Proxy-Authorization": `Basic ${Buffer.from(login).toString("base64")}` };
}

/** Socket options for one destination: its own TLS policy, and SNI only for a host name. */
function destinationOptions(policy: DestinationTlsPolicy, host: string) {
  return { ...policy(host), servername: isIP(host) ? undefined : host };
}

export class CloudAgent extends AgentBase {
  readonly #policy: DestinationTlsPolicy;
  readonly #proxy: HttpsProxyAgent<string> | undefined;

  constructor(policy: DestinationTlsPolicy, proxyUrl?: URL) {
    super({ keepAlive: true });
    this.#policy = policy;
    // The proxy's own certificate (an https:// proxy) is checked with the same policy as any host.
    this.#proxy = proxyUrl
      ? new HttpsProxyAgent(withoutCredentials(proxyUrl).href, {
          ...(proxyUrl.protocol === "https:" ? destinationOptions(policy, proxyUrl.hostname) : {}),
          headers: proxyAuthHeaders(proxyUrl),
        })
      : undefined;
  }

  /** Whether requests tunnel through a proxy, for a status line. Never the URL: it can hold a password. */
  get proxied(): boolean {
    return this.#proxy !== undefined;
  }

  connect(req: ClientRequest, opts: AgentConnectOpts): Promise<Duplex> | Duplex {
    const host = opts.host ?? "localhost";
    const port = opts.port ?? (opts.secureEndpoint ? 443 : 80);
    // Throws for a refused destination (insecure toward a non-loopback host): the request fails.
    const tls = opts.secureEndpoint ? destinationOptions(this.#policy, host) : {};
    if (this.#proxy) {
      // https-proxy-agent opens the CONNECT tunnel, then spreads these options into the tls.connect
      // to the REAL destination — so the CA and verification apply past the proxy, per host.
      const tunnelOpts = opts.secureEndpoint
        ? { host, port, secureEndpoint: true as const, ...tls }
        : { host, port, secureEndpoint: false as const };
      return this.#proxy.connect(req, tunnelOpts);
    }
    if (!opts.secureEndpoint) return netConnect({ host, port });
    return tlsConnect({ host, port, ...tls });
  }

  destroy(): void {
    this.#proxy?.destroy();
    super.destroy();
  }
}

export interface CloudTransport {
  /** Hand this to an SDK as its Node http(s) agent. */
  readonly agent: CloudAgent;
  /** Close pooled sockets when the run ends. */
  close(): void;
}

/**
 * The transport one collection run uses. Throws CloudTransportError up front for an unreadable CA
 * bundle or a malformed proxy URL; a refused destination fails only the requests to that host.
 */
export function createCloudTransport(
  settings: CloudTransportSettings,
  deps: DestinationTlsDeps = {},
): CloudTransport {
  const policy = destinationTlsPolicy(settings, deps);
  const proxyUrl = settings.proxyUrl ? parseProxyUrl(settings.proxyUrl) : undefined;
  const agent = new CloudAgent(policy, proxyUrl);
  return { agent, close: () => agent.destroy() };
}
