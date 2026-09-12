import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent, stampSourceArtifactHash } from "./canonicalEvent.js";
import { renderAwsDescription } from "./awsDescription.js";
import { decodeGwsToken, readGwsParams, type GwsTokenReading } from "./gwsOAuth.js";
import {
  extractRecords,
  aggregateEvents,
  addIoc,
  oneLine,
  isObject,
  getCI,
  getPath,
  normalizeTime,
  cleanIp,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";

// Deterministic importer for Google Workspace Admin SDK Reports API activities — the third identity
// ingest path, beside m365Import.ts (Entra) and oktaImport.ts. No AI call.
//
// FAN-OUT MATTERS HERE. One activity record carries an `events[]` array, and each entry is a
// separate thing that happened — a record is not an event. Mapping one record to one timeline row
// would silently drop the second and later events, so each entry becomes its own row.
//
// Google records carry no severity at all (unlike Suricata or an EDR verdict), so severity is
// DERIVED from the event name, the same approach as the M365 and Okta importers. This is not a
// detection engine: each mapping says "worth an analyst's attention", not "malicious".
//
// The tradecraft encoded is Workspace account takeover and mail theft: 2SV turned off, admin roles
// granted, recovery addresses re-pointed, OAuth grants authorized, and — the one most often missed —
// CREATE_EMAIL_MONITOR, which silently copies a user's mail to an attacker's mailbox.
//
// The `token` application's rows (#931 item 10) are decoded by gwsOAuth.ts: the client id is the
// identity, the scopes grade the grant, the API method and bytes are named on an activity, and
// each row says what its record does NOT establish. Those rows carry a canonical envelope; every
// Workspace key carries the tenant (`id.customerId`) so two customers' identical rows stay two.

type Row = Record<string, unknown>;

export interface GoogleWorkspaceImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface GoogleWorkspaceParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number; // activity RECORDS read (not mapped events — one record can carry several)
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "google-workspace" | "empty"
}

interface EventDef {
  severity: Severity;
  mitre?: string[];
}

// Curated high-signal event names → derived severity + MITRE. Keyed by the event `name`, lowercased;
// Google mixes SCREAMING_CASE (admin) and snake_case (login/token/drive) so the table normalizes.
const GWS_EVENTS: Record<string, EventDef> = {
  // ── login ──
  login_success: { severity: "Info", mitre: ["T1078.004"] },
  logout: { severity: "Info" },
  login_failure: { severity: "Medium", mitre: ["T1110"] },
  login_challenge: { severity: "Low" },
  login_verification: { severity: "Info" },
  suspicious_login: { severity: "High", mitre: ["T1078.004"] },
  suspicious_login_less_secure_app: { severity: "High", mitre: ["T1078.004"] },
  suspicious_programmatic_login: { severity: "High", mitre: ["T1078.004"] },
  account_disabled_password_leak: { severity: "High", mitre: ["T1078.004"] },
  gov_attack_warning: { severity: "High", mitre: ["T1078.004"] },

  // ── 2-step verification: the Workspace equivalent of Okta MFA tampering ──
  unenroll_user_from_strong_auth: { severity: "High", mitre: ["T1556.006"] },
  turn_off_2_step_verification: { severity: "High", mitre: ["T1556.006"] },
  "2sv_disable": { severity: "High", mitre: ["T1556.006"] },
  unenroll_user_from_titan_security_key: { severity: "High", mitre: ["T1556.006"] },
  "2sv_enroll": { severity: "Info" },

  // ── credentials and recovery ──
  change_password: { severity: "Medium", mitre: ["T1098"] },
  reset_password: { severity: "Medium", mitre: ["T1098"] },
  password_edit: { severity: "Medium", mitre: ["T1098"] },
  recovery_email_edit: { severity: "Medium", mitre: ["T1098.005"] },
  recovery_phone_edit: { severity: "Medium", mitre: ["T1098.005"] },
  add_recovery_email: { severity: "Medium", mitre: ["T1098.005"] },
  add_recovery_phone: { severity: "Medium", mitre: ["T1098.005"] },

  // ── privilege ──
  grant_admin_privilege: { severity: "High", mitre: ["T1098.003"] },
  assign_role: { severity: "High", mitre: ["T1098.003"] },
  create_role: { severity: "High", mitre: ["T1098.003"] },
  add_privilege: { severity: "High", mitre: ["T1098.003"] },
  revoke_admin_privilege: { severity: "Medium" },
  create_user: { severity: "Medium", mitre: ["T1136.003"] },
  delete_user: { severity: "Medium" },
  suspend_user: { severity: "Medium" },

  // ── mail interception and exfiltration ──
  create_email_monitor: { severity: "High", mitre: ["T1114"] },
  email_forwarding_out_of_domain: { severity: "High", mitre: ["T1114.003"] },
  change_email_setting: { severity: "Medium", mitre: ["T1114"] },
  create_data_transfer_request: { severity: "Medium", mitre: ["T1530"] },
  download_userlist_csv: { severity: "Medium", mitre: ["T1087.004"] },

  // ── OAuth / programmatic access ──
  authorize: { severity: "High", mitre: ["T1528"] },
  request: { severity: "Info" },
  revoke: { severity: "Info" },
  enable_api_access: { severity: "Medium", mitre: ["T1098.001"] },
  add_to_trusted_oauth2_apps: { severity: "High", mitre: ["T1528"] },

  // ── Drive: sharing outward is the exfil signal, not the edit ──
  change_document_visibility: { severity: "Medium", mitre: ["T1537"] },
  change_document_access_scope: { severity: "Medium", mitre: ["T1537"] },
  change_user_access: { severity: "Medium", mitre: ["T1537"] },
  download: { severity: "Low", mitre: ["T1530"] },
  copy: { severity: "Low", mitre: ["T1530"] },

  // ── groups ──
  add_member: { severity: "Medium", mitre: ["T1098"] },
  change_acl_permission: { severity: "Medium", mitre: ["T1098"] },
};

function defFor(name: string): EventDef {
  return GWS_EVENTS[name.trim().toLowerCase()] ?? { severity: "Info" };
}

// A Reports API activity always carries id.time + id.applicationName. Anything missing those is
// another product's JSON and is skipped rather than guessed at.
function isWorkspaceActivity(rec: Row): boolean {
  const id = getCI(rec, "id");
  if (!isObject(id)) return false;
  return Boolean(getCI(id, "time")) && Boolean(getCI(id, "applicationName"));
}

function text(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

// The parameter worth putting in the description — who or what the operation acted on. Google's
// parameter names vary per event, so the preference order names the ones an analyst reads first.
const TARGET_PARAMS = [
  "USER_EMAIL",
  "user_email",
  "doc_title",
  "GROUP_EMAIL",
  "group_email",
  "APPLICATION_NAME",
  "app_name",
  "client_id",
  "target_domain",
  "DOMAIN_NAME",
  "OLD_VALUE",
  "NEW_VALUE",
];

// Parameters that IDENTIFY the thing an event acted on — stable ids, never a title and never a
// value. `doc_title` is not identity (two documents share a title); OLD_VALUE/NEW_VALUE are the
// change itself, and keying on them turns every configuration edit into its own group until the
// event cap starts dropping groups. Order is preference: the first present wins for the key.
const IDENTITY_PARAMS = [
  "doc_id",
  "target_user", // Drive emits one access-change event PER SHAREE, same doc_id, different target_user
  "USER_EMAIL",
  "user_email",
  "GROUP_EMAIL",
  "group_email",
  "client_id",
  "SETTING_NAME",
  "DEVICE_ID",
  "target_domain",
  "DOMAIN_NAME",
] as const;

function paramsByName(event: Row): Map<string, string> {
  const params = getCI(event, "parameters");
  const byName = new Map<string, string>();
  if (!Array.isArray(params)) return byName;
  for (const p of params) {
    if (!isObject(p)) continue;
    const name = text(getCI(p, "name"));
    const raw = getCI(p, "value") ?? getCI(p, "multiValue") ?? getCI(p, "boolValue");
    if (!name || raw == null) continue;
    byName.set(name, Array.isArray(raw) ? raw.map(text).join(", ") : text(raw));
  }
  return byName;
}

// The stable identity of the event's target for the aggregation key: EVERY identity parameter the
// event carries, in a fixed order — not the first one. A Drive access change names both the
// document and the sharee, and one document shared with three people is three events. "" when the
// event names none (a login) — then the key is exactly what it was before.
function targetIdentity(event: Row): string {
  const byName = paramsByName(event);
  return IDENTITY_PARAMS.filter((k) => byName.get(k))
    .map((k) => `${k}=${byName.get(k)}`)
    .join(";");
}

function targetLabel(event: Row): string {
  const params = getCI(event, "parameters");
  if (!Array.isArray(params)) return "";
  const byName = new Map<string, string>();
  for (const p of params) {
    if (!isObject(p)) continue;
    const row = p;
    const name = text(getCI(row, "name"));
    const raw = getCI(row, "value") ?? getCI(row, "multiValue") ?? getCI(row, "boolValue");
    if (!name || raw == null) continue;
    byName.set(name, Array.isArray(raw) ? raw.map(text).join(", ") : text(raw));
  }
  for (const key of TARGET_PARAMS) {
    const hit = byName.get(key);
    if (hit) return hit;
  }
  return "";
}

const TOKEN_APP = "token";
// The head slot is 120 (awsDescription.ts): `Google Workspace token: authorize by <who> from <ip>`
// with the longest event name (9) and a full IPv6 (39) leaves 36 for the actor, so the source
// address is never the part a long actor name pushes out.
const WHO_MAX = 36;

// The canonical envelope of a token row — agency per event: on an `activity` the APPLICATION is
// the actor (it called the API) and the user the subject; on the other four the USER is the actor
// and the application the object. The cloud principal follows the actor (the client id on an
// activity, the user's profile id otherwise) so its type never contradicts its id. A `request`
// that names a `requester_email` carries that account as the subject — the account the request
// is for. No placeholder resource: `cloud.resource` is the API method or nothing.
function tokenEnvelope(
  rec: Row,
  t: GwsTokenReading,
  name: string,
  ip: string,
  locator: string,
): MappedEvent["canonical"] {
  const email = text(getPath(rec, "actor.email"));
  const profileId = text(getPath(rec, "actor.profileId"));
  const tenant = text(getPath(rec, "id.customerId"));
  const observed = text(getPath(rec, "id.time"));
  const recordId = text(getPath(rec, "id.uniqueQualifier"));
  const user =
    email || profileId
      ? {
          kind: "account" as const,
          ...(email ? { name: email } : {}),
          ...(profileId ? { id: profileId } : {}),
        }
      : undefined;
  const app =
    t.client.id || t.client.name
      ? {
          kind: "cloud_principal" as const,
          ...(t.client.id ? { id: t.client.id } : {}),
          ...(t.client.name ? { name: t.client.name } : {}),
        }
      : undefined;
  const method = [t.api.name, t.api.method].filter(Boolean).join(".");
  const activity = t.kind === "activity";
  const requester =
    t.kind === "request" && t.requester ? { kind: "account" as const, name: t.requester } : undefined;
  const principalId = activity ? t.client.id : profileId;
  return createCanonicalEvent({
    event: { category: "cloud", type: "oauth", action: name, outcome: "success" },
    ...(activity
      ? { ...(app ? { actor: app } : {}), ...(user ? { subject: user } : {}) }
      : {
          ...(user ? { actor: user } : {}),
          ...(app ? { object: app } : {}),
          ...(requester ? { subject: requester } : {}),
        }),
    ...(ip ? { network: { source: { address: ip } } } : {}),
    cloud: {
      provider: "google-workspace",
      ...(tenant ? { tenant } : {}),
      ...(principalId ? { principalId } : {}),
      principalType: activity ? "application" : "user",
      ...(activity && method ? { resource: method } : {}),
    },
    time: { observed, normalized: normalizeTime(observed) },
    evidence: { rawRecords: [{ source: "google-workspace", locator, ...(recordId ? { recordId } : {}) }] },
    producer: {
      importer: "google-workspace",
      parserVersion: "1",
      mappingVersion: "gws-token-v1",
      ruleVersions: ["gws-oauth-v1"],
    },
    rawFieldMap: {
      "event.action": ["events[].name"],
      "time.observed": ["id.time"],
      ...(activity
        ? {
            "actor.id": ["client_id"],
            "actor.name": ["app_name"],
            "subject.name": ["actor.email"],
            "subject.id": ["actor.profileId"],
            "cloud.resource": ["api_name", "method_name"],
          }
        : {
            "actor.name": ["actor.email"],
            "actor.id": ["actor.profileId"],
            "object.id": ["client_id"],
            "object.name": ["app_name"],
            ...(requester ? { "subject.name": ["requester_email"] } : {}),
          }),
      "cloud.tenant": ["id.customerId"],
      "cloud.principalId": [activity ? "client_id" : "actor.profileId"],
      ...(ip ? { "network.source.address": ["ipAddress"] } : {}),
    },
  });
}

function mapEvent(rec: Row, event: Row, sink: Map<string, SiemIoc>, locator: string): MappedEvent {
  const app = text(getPath(rec, "id.applicationName"));
  const name = text(getCI(event, "name"));
  const actor = text(getPath(rec, "actor.email") || getPath(rec, "actor.profileId"));
  const ip = cleanIp(text(getCI(rec, "ipAddress")));
  const tenant = text(getPath(rec, "id.customerId"));
  if (ip) addIoc(sink, "ip", ip);
  // The tenant and the target IDENTITY, bounded with a digest (#931 prerequisite). A document
  // shared with three people is three rows; two documents with one title are two; two customers'
  // identical rows are two.
  const baseKey = `gws|${app}|${name}|${actor}|${ip}|${tenant}|${targetIdentity(event)}`;
  const timestamp = normalizeTime(text(getPath(rec, "id.time")));

  const token = app.toLowerCase() === TOKEN_APP ? decodeGwsToken(name, readGwsParams(event)) : null;
  if (token) {
    const who = oneLine(actor).slice(0, WHO_MAX);
    const head = `Google Workspace ${app}: ${name}${who ? ` by ${who}` : ""}${ip ? ` from ${ip}` : ""}`;
    return {
      timestamp,
      description: renderAwsDescription({
        head,
        posture: token.posture,
        outcome: "",
        object: token.object,
        optional: token.optional,
        tail: "",
        qualifiers: token.qualifiers,
      }),
      severity: token.severity,
      mitre: [...token.mitre],
      // The client id is the row's identity; when the record has none, the record's own id joins
      // so two applications never fold into one row behind a shared display name.
      aggKey: boundedAggKey(
        `${baseKey}${token.keySegment}${token.client.id ? "" : `|record:${text(getPath(rec, "id.uniqueQualifier")) || locator}`}`.toLowerCase(),
      ),
      sources: ["Google Workspace"],
      canonical: tokenEnvelope(rec, token, name, ip, locator),
    };
  }

  const target = targetLabel(event);
  const def = defFor(name);
  let description = `Google Workspace ${app}: ${name}`;
  if (actor) description += ` by ${actor}`;
  if (target) description += ` → ${oneLine(target).slice(0, 120)}`;
  if (ip) description += ` from ${ip}`;
  description = description.slice(0, 600);

  return {
    timestamp,
    description,
    severity: def.severity,
    mitre: [...(def.mitre ?? [])],
    aggKey: boundedAggKey(baseKey.toLowerCase()),
    sources: ["Google Workspace"],
  };
}

export function parseGoogleWorkspaceReport(
  input: string,
  opts: GoogleWorkspaceImportOptions = {},
): GoogleWorkspaceParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const empty: GoogleWorkspaceParseResult = {
    events: [],
    iocs: [],
    total: 0,
    kept: 0,
    dropped: 0,
    groups: 0,
    format: "empty",
  };

  const trimmed = input.trim();
  if (!trimmed) return empty;

  // extractRecords already unwraps the common containers, `items` among them.
  const records = extractRecords(trimmed).records;
  const total = records.length;
  if (total === 0) return empty;

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  records.forEach((raw, recordIndex) => {
    if (!isObject(raw)) return;
    const rec = raw;
    if (!isWorkspaceActivity(rec)) return;
    const events = getCI(rec, "events");
    // One record, N events — each is its own thing that happened, with its own locator.
    const list = Array.isArray(events) ? events : [];
    list.forEach((e, eventIndex) => {
      if (!isObject(e)) return;
      mapped.push(mapEvent(rec, e, iocSink, `record:${recordIndex}/event:${eventIndex}`));
    });
  });

  const aggregated = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const events = stampSourceArtifactHash(aggregated.events, input);
  const groups = aggregated.groups;

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, mapped.length - represented),
    groups,
    format: mapped.length ? "google-workspace" : "empty",
  };
}
