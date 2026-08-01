import { buildTlsFetch } from "../enrichment/tlsFetch.js";
import { warnLine } from "../logging/serverLogger.js";
import { isEnvFlag } from "./env.js";

/**
 * Per-integration TLS trust, resolved from env at composition time (#384, moved from server.ts).
 *
 * Optional per-provider TLS trust for a self-hosted intel host with an internal-CA or self-signed
 * cert. Returns undefined (→ the default, fully-verified global fetch) unless a DFIR_<NAME>_CA
 * bundle or DFIR_<NAME>_INSECURE flag is set. Scoped to that provider only.
 */

/**
 * Resolves each integration's actual target host, so tlsFetchFor can pass hostUrl to buildTlsFetch's
 * loopback guard (#246) — WITHOUT it, insecureSkipVerify's guard defaults to "treat as loopback" and
 * never rejects anything, silently defeating the guard entirely (the bug this map exists to close).
 * MISP/YETI/OPENCTI/IRIS/TIMESKETCH/JIRA/SERVICENOW read their configurable DFIR_<NAME>_URL. NOTION
 * and CLICKUP have no such env var — they're fixed SaaS hosts — so their entries are the literal
 * constants those clients themselves use, which correctly makes the guard treat them as
 * non-loopback (there's no legitimate reason to skip TLS verification against the real
 * api.notion.com/api.clickup.com).
 */
const TLS_HOST_URL: Partial<Record<string, string | (() => string | undefined)>> = {
  MISP: () => process.env.DFIR_MISP_URL,
  YETI: () => process.env.DFIR_YETI_URL,
  OPENCTI: () => process.env.DFIR_OPENCTI_URL,
  IRIS: () => process.env.DFIR_IRIS_URL,
  TIMESKETCH: () => process.env.DFIR_TIMESKETCH_URL,
  JIRA: () => process.env.DFIR_JIRA_URL,
  SERVICENOW: () => process.env.DFIR_SERVICENOW_URL,
  NOTION: "https://api.notion.com",
  CLICKUP: "https://api.clickup.com/api/v2",
  // NOTIFY webhooks are arbitrary external URLs (hooks.slack.com, outlook.office.com, a self-
  // hosted Mattermost) only known at send time from NotificationConfigStore — there's no single
  // env var to read at boot. That is precisely why DFIR_NOTIFY_INSECURE=1 silently bypassed the
  // non-loopback TLS-MITM guard for ALL of them: hostUrl was undefined and the guard defaults to
  // "treat as loopback", i.e. allow. Since we can't know the host, assume the answer that fails
  // closed — a sentinel that is definitively not loopback, so the guard fires and tlsFetchFor
  // falls back to the verified global fetch unless the operator ALSO sets
  // DFIR_TLS_ALLOW_INSECURE_EXTERNAL=true. hostUrl feeds nothing but isLoopbackUrl, so a reserved
  // .invalid name (RFC 2606) is the honest spelling: it names no real host and can't be mistaken
  // for one being verified. Only consulted when insecure is set — otherwise no custom fetch is
  // built at all. Threading the real per-send URL through would let a loopback webhook keep
  // using insecure on its own, which this deliberately no longer does.
  NOTIFY: () => (isEnvFlag(process.env.DFIR_NOTIFY_INSECURE) ? "https://notify-webhook.invalid" : undefined),
};

export type TlsIntegration =
  | "MISP"
  | "YETI"
  | "OPENCTI"
  | "IRIS"
  | "TIMESKETCH"
  | "NOTION"
  | "CLICKUP"
  | "NOTIFY"
  | "JIRA"
  | "SERVICENOW";

export function tlsFetchFor(name: TlsIntegration) {
  const hostSource = TLS_HOST_URL[name];
  const hostUrl = typeof hostSource === "function" ? hostSource() : hostSource;
  try {
    return buildTlsFetch({
      caCertPath: process.env[`DFIR_${name}_CA`],
      insecureSkipVerify: isEnvFlag(process.env[`DFIR_${name}_INSECURE`]),
      hostUrl,
      onWarn: (m) => warnLine(`[DFIR] ${name}: ${m}`),
    });
  } catch (err) {
    // buildTlsFetch throws when insecureSkipVerify targets a non-loopback host without the
    // explicit DFIR_TLS_ALLOW_INSECURE_EXTERNAL override (#246). Every call site of tlsFetchFor
    // sits inline in an options object built at server startup (and in the live /settings/reload
    // path) with no surrounding try/catch — letting this propagate would crash the ENTIRE server
    // over one optional integration's TLS misconfiguration. Disable custom TLS trust for just this
    // provider instead (falls back to the default, fully-verified global fetch — a real self-signed
    // cert then fails that provider's own connection attempts with a normal, contained TLS error,
    // not a server-wide outage) and say why loudly so the operator can see it in the logs.
    warnLine(`[DFIR] ${name}: ${(err as Error).message}`);
    return undefined;
  }
}
