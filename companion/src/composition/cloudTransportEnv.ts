import { createCloudTransport, type CloudTransport } from "../integrations/cloudTransport/cloudAgent.js";
import type { CloudTransportSettings } from "../integrations/cloudTransport/destinationTls.js";
import { warnLine } from "../logging/serverLogger.js";
import { isEnvFlag } from "./env.js";

/**
 * Cloud collection's TLS and proxy settings, from env (#2310). One family for every cloud SDK and
 * every cloud host — token endpoints included — named like the other integrations' (DFIR_<NAME>_CA,
 * DFIR_<NAME>_INSECURE) so the TLS trust hint can quote them as DFIR_CLOUD_*. The standard
 * HTTPS_PROXY variables are NOT read: the proxy is the one the operator set here, or none.
 */
export function cloudTransportSettingsFromEnv(env: NodeJS.ProcessEnv = process.env): CloudTransportSettings {
  const ca = env.DFIR_CLOUD_CA?.trim();
  const proxy = env.DFIR_CLOUD_PROXY_URL?.trim();
  return {
    ...(ca ? { caCertPath: ca } : {}),
    ...(isEnvFlag(env.DFIR_CLOUD_INSECURE) ? { insecure: true } : {}),
    ...(proxy ? { proxyUrl: proxy } : {}),
  };
}

/** The transport for one collection run. Throws CloudTransportError for a bad CA path or proxy URL. */
export function cloudTransportFromEnv(env: NodeJS.ProcessEnv = process.env): CloudTransport {
  return createCloudTransport(cloudTransportSettingsFromEnv(env), {
    onWarn: (m) => warnLine(`[DFIR] ${m}`),
  });
}
