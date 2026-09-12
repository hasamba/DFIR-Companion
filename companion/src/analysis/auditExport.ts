import { z } from "zod";
import type { ActivityCategory, ActivityLogEntry } from "./activityLog.js";

// Audit-log export to a SIEM (issue #929). This module is the PURE core: the destination model,
// input validation, secret redaction, and the mapping from a stored activity entry to the record
// that leaves the box. No I/O — the store (auditExportStore.ts), the per-destination position
// (auditExportCursor.ts), and the wire formats + transports (integrations/audit/) build on it.
//
// OPSEC, and the reason the destination is NOT two .env fields: forwarding the activity log sends
// case identifiers, analyst names, and what each analyst did to a third-party system, and the
// credential that reaches it is a secret. That is the same shape as a notification channel, so it
// gets the same treatment — a global gitignored config file, an empty list until an analyst adds a
// destination, and redaction on every response (notifications.ts / notificationStore.ts).
//
// WHAT THE EXPORTED RECORD CARRIES, and why it is wider than #929 asked for:
//   - `id`     — the activity entry's own id. A batching exporter retries, and without a stable id
//                per record a retry duplicates rows in the SIEM. It is the dedup key.
//   - `outcome`— success or error. An audit trail that shows only the actions that worked is not
//                an audit trail; a failed privileged action is the interesting one.
//   - `actorVerified` — whether the name came from an authenticated session or from the client.
//                ActivityLogStore.add prefers the session identity when there is one and falls back
//                to a client-supplied name otherwise, so the two are NOT the same claim. Collapsing
//                them into one `investigator` string (as #929 proposed) hands an auditor a name
//                without telling them whether anyone verified it.

export const AUDIT_DESTINATION_TYPES = ["splunk", "elastic", "syslog"] as const;
export type AuditDestinationType = (typeof AUDIT_DESTINATION_TYPES)[number];

export const SYSLOG_PROTOCOLS = ["udp", "tcp"] as const;
export type SyslogProtocol = (typeof SYSLOG_PROTOCOLS)[number];

export const DEFAULT_SYSLOG_PORT = 514;

export interface SplunkConfig {
  url: string; // HEC collector base, e.g. https://splunk:8088
  token: string; // HEC token — secret
  index?: string;
  sourcetype?: string;
}

export interface ElasticConfig {
  url: string; // cluster base, e.g. https://es:9200
  index: string;
  username?: string;
  password?: string; // secret
  apiKey?: string; // secret
}

export interface SyslogConfig {
  host: string;
  port: number;
  protocol: SyslogProtocol;
  appName?: string;
}

export interface AuditDestination {
  id: string;
  type: AuditDestinationType;
  name: string;
  enabled: boolean;
  splunk?: SplunkConfig;
  elastic?: ElasticConfig;
  syslog?: SyslogConfig;
  createdAt: string;
  updatedAt: string;
}

export interface DestinationDraft {
  type: AuditDestinationType;
  name: string;
  enabled: boolean;
  splunk?: SplunkConfig;
  elastic?: ElasticConfig;
  syslog?: SyslogConfig;
}

// ── The record that leaves the box ───────────────────────────────────────────────────────────

export interface AuditEvent {
  id: string;
  timestamp: string;
  caseId: string;
  category: ActivityCategory;
  action: string;
  detail: string;
  actor: string;
  actorId?: string;
  actorKind?: "local" | "oidc" | "service";
  actorVerified: boolean;
  targetType?: string;
  targetId?: string;
  outcome: "success" | "error";
}

/**
 * Map one stored activity entry to its exported record. `caseId` is a parameter because the store
 * encodes it in the file's location rather than in each entry, so it has to be supplied by the
 * reader — it is not recoverable from the entry alone.
 */
export function toAuditEvent(entry: ActivityLogEntry, caseId: string): AuditEvent {
  return {
    id: entry.id,
    timestamp: entry.timestamp,
    caseId,
    category: entry.category,
    action: entry.action,
    detail: entry.detail,
    actor: entry.actor,
    ...(entry.actorId ? { actorId: entry.actorId } : {}),
    ...(entry.actorKind ? { actorKind: entry.actorKind } : {}),
    // An actorId is only ever written from an authenticated session (identityContext.ts), so its
    // presence is the honest answer to "did the server verify this name?".
    actorVerified: Boolean(entry.actorId),
    ...(entry.targetType ? { targetType: entry.targetType } : {}),
    ...(entry.targetId ? { targetId: entry.targetId } : {}),
    outcome: entry.outcome,
  };
}

/**
 * The record the Test button sends. Marked as a test in `action` and `detail` so it can never be
 * mistaken for a real analyst action in the SIEM, and deliberately unverified — nobody
 * authenticated it.
 */
export function testAuditEvent(at: string): AuditEvent {
  return {
    id: `test-${at}`,
    timestamp: at,
    caseId: "_test",
    category: "settings",
    action: "audit_export_test",
    detail: "DFIR Companion audit-export connection test — not a real investigation action",
    actor: "dfir-companion",
    actorVerified: false,
    outcome: "success",
  };
}

// ── Input validation ─────────────────────────────────────────────────────────────────────────

const splunkInput = z.object({
  url: z.string().optional(),
  token: z.string().optional(),
  index: z.string().optional(),
  sourcetype: z.string().optional(),
});
const elasticInput = z.object({
  url: z.string().optional(),
  index: z.string().optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  apiKey: z.string().optional(),
});
const syslogInput = z.object({
  host: z.string().optional(),
  port: z.number().optional(),
  protocol: z.string().optional(),
  appName: z.string().optional(),
});

const destinationInputSchema = z.object({
  type: z.enum(AUDIT_DESTINATION_TYPES),
  name: z.string().optional(),
  enabled: z.boolean().optional(),
  splunk: splunkInput.optional(),
  elastic: elasticInput.optional(),
  syslog: syslogInput.optional(),
});

export interface ParsedDestinationInput {
  ok: boolean;
  draft?: DestinationDraft;
  error?: string;
}

const DEFAULT_NAMES: Record<AuditDestinationType, string> = {
  splunk: "Splunk HEC",
  elastic: "Elasticsearch",
  syslog: "Syslog",
};

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

/**
 * Two URLs name the same collector. Only a trailing slash is normalised away — a differing host
 * case or port is treated as a DIFFERENT endpoint, which fails safe: the edit is asked for a fresh
 * credential rather than silently reusing one.
 */
function sameEndpointUrl(a: string | undefined, b: string | undefined): boolean {
  const strip = (u: string | undefined) => (u ?? "").trim().replace(/\/+$/, "");
  const left = strip(a);
  return left.length > 0 && left === strip(b);
}

/**
 * Validate a destination submitted by the Settings form.
 *
 * A blank secret on an edit keeps the saved one — but ONLY when the credential still points at the
 * same place. Slack and Discord shared one `webhookUrl` field, and an edit that switched provider
 * and left the redacted box blank posted one service's payload to the other service's endpoint
 * (#683). Two versions of that trap live here, and the type check alone catches only the first:
 *
 *   - a TYPE change (Splunk -> Elasticsearch) would reuse an HEC token as a cluster password;
 *   - a URL change at the SAME type would send the old collector's token to a new host, which is
 *     the more likely mistake and the one a redacted field invites — the box looks filled in.
 *
 * So inheritance of a CREDENTIAL requires the same type and the same endpoint. Non-secret config
 * (index, sourcetype, username, app name) still travels across a URL change: it describes what to
 * write, not who may write it.
 */
export function parseDestinationInput(raw: unknown, existing?: AuditDestination): ParsedDestinationInput {
  const parsed = destinationInputSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      error: parsed.error.issues.map((i) => `${i.path.join(".") || "input"}: ${i.message}`).join("; "),
    };
  }
  const v = parsed.data;
  const sameType = existing?.type === v.type;
  const draft: DestinationDraft = {
    type: v.type,
    name: (v.name ?? "").trim() || DEFAULT_NAMES[v.type],
    enabled: v.enabled ?? true,
  };

  if (v.type === "splunk") {
    const prev = sameType ? existing?.splunk : undefined;
    const url = (v.splunk?.url ?? "").trim() || (prev?.url ?? "");
    if (!isHttpUrl(url)) return { ok: false, error: "splunk requires an http(s) collector URL" };
    // The token may be inherited only when it would go back to the collector it was issued for.
    const sameCollector = sameEndpointUrl(prev?.url, url);
    const token = (v.splunk?.token ?? "").trim() || (sameCollector ? (prev?.token ?? "") : "");
    if (!token) {
      return {
        ok: false,
        error: !sameType
          ? "changing this destination to splunk requires a new HEC token"
          : prev?.url && !sameCollector
            ? "changing the collector URL requires a new HEC token — the saved one belongs to the old collector"
            : "splunk requires an HEC token",
      };
    }
    draft.splunk = {
      url: url.replace(/\/+$/, ""),
      token,
      ...((v.splunk?.index ?? "").trim() || prev?.index
        ? { index: (v.splunk?.index ?? "").trim() || prev!.index! }
        : {}),
      ...((v.splunk?.sourcetype ?? "").trim() || prev?.sourcetype
        ? { sourcetype: (v.splunk?.sourcetype ?? "").trim() || prev!.sourcetype! }
        : {}),
    };
  } else if (v.type === "elastic") {
    const prev = sameType ? existing?.elastic : undefined;
    const url = (v.elastic?.url ?? "").trim() || (prev?.url ?? "");
    if (!isHttpUrl(url)) return { ok: false, error: "elastic requires an http(s) cluster URL" };
    const index = (v.elastic?.index ?? "").trim() || (prev?.index ?? "");
    if (!index) return { ok: false, error: "elastic requires an index name" };
    // No credential is legitimate — a security-only cluster on a closed network may not need one,
    // which is why a cluster URL change cannot be REFUSED here the way Splunk's is. It still must
    // not carry the old cluster's secret across.
    const sameCluster = sameEndpointUrl(prev?.url, url);
    const password = (v.elastic?.password ?? "").trim() || (sameCluster ? (prev?.password ?? "") : "");
    const apiKey = (v.elastic?.apiKey ?? "").trim() || (sameCluster ? (prev?.apiKey ?? "") : "");
    // Not a secret, and visible in the redacted view, so it travels with the rest of the config.
    const username = (v.elastic?.username ?? "").trim() || (prev?.username ?? "");
    draft.elastic = {
      url: url.replace(/\/+$/, ""),
      index,
      ...(username ? { username } : {}),
      ...(password ? { password } : {}),
      ...(apiKey ? { apiKey } : {}),
    };
  } else {
    const prev = sameType ? existing?.syslog : undefined;
    const host = (v.syslog?.host ?? "").trim() || (prev?.host ?? "");
    if (!host) return { ok: false, error: "syslog requires a host" };
    const port = v.syslog?.port ?? prev?.port ?? DEFAULT_SYSLOG_PORT;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return { ok: false, error: "syslog port must be an integer between 1 and 65535" };
    }
    const rawProtocol = (v.syslog?.protocol ?? "").trim() || prev?.protocol || "udp";
    if (!(SYSLOG_PROTOCOLS as readonly string[]).includes(rawProtocol)) {
      return { ok: false, error: `syslog protocol must be one of ${SYSLOG_PROTOCOLS.join(", ")}` };
    }
    const appName = (v.syslog?.appName ?? "").trim() || prev?.appName || "";
    draft.syslog = {
      host,
      port,
      protocol: rawProtocol as SyslogProtocol,
      ...(appName ? { appName } : {}),
    };
  }

  return { ok: true, draft };
}

/**
 * Merge a validated draft onto a saved destination. Drops the config blocks of every other type so
 * a retyped destination cannot keep a stale endpoint or credential behind it.
 */
export function applyDestinationPatch(
  existing: AuditDestination,
  draft: DestinationDraft,
  at: string,
): AuditDestination {
  const next: AuditDestination = {
    ...existing,
    type: draft.type,
    name: draft.name,
    enabled: draft.enabled,
    updatedAt: at,
  };
  delete next.splunk;
  delete next.elastic;
  delete next.syslog;
  if (draft.splunk) next.splunk = draft.splunk;
  if (draft.elastic) next.elastic = draft.elastic;
  if (draft.syslog) next.syslog = draft.syslog;
  return next;
}

// ── Redaction ────────────────────────────────────────────────────────────────────────────────

export interface RedactedDestination extends Omit<AuditDestination, "splunk" | "elastic" | "syslog"> {
  splunk?: Omit<SplunkConfig, "token"> & { hasToken: boolean };
  elastic?: Omit<ElasticConfig, "password" | "apiKey"> & { hasPassword: boolean; hasApiKey: boolean };
  syslog?: SyslogConfig; // carries no secret
}

/** Strip every credential for a client-facing view. The browser learns only whether one is set. */
export function redactDestination(destination: AuditDestination): RedactedDestination {
  const { splunk, elastic, syslog, ...rest } = destination;
  const out: RedactedDestination = { ...rest };
  if (splunk) {
    const { token, ...splunkRest } = splunk;
    out.splunk = { ...splunkRest, hasToken: Boolean(token) };
  }
  if (elastic) {
    const { password, apiKey, ...elasticRest } = elastic;
    out.elastic = { ...elasticRest, hasPassword: Boolean(password), hasApiKey: Boolean(apiKey) };
  }
  if (syslog) out.syslog = syslog;
  return out;
}
