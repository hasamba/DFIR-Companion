import type { Severity } from "./stateTypes.js";
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
  return Boolean(getCI(id as Row, "time")) && Boolean(getCI(id as Row, "applicationName"));
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

function targetLabel(event: Row): string {
  const params = getCI(event, "parameters");
  if (!Array.isArray(params)) return "";
  const byName = new Map<string, string>();
  for (const p of params) {
    if (!isObject(p)) continue;
    const row = p as Row;
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

function mapEvent(rec: Row, event: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const app = text(getPath(rec, "id.applicationName"));
  const name = text(getCI(event, "name"));
  const actor = text(getPath(rec, "actor.email") || getPath(rec, "actor.profileId"));
  const ip = cleanIp(text(getCI(rec, "ipAddress")));
  const target = targetLabel(event);

  const def = defFor(name);
  const severity = def.severity;
  const mitre = [...(def.mitre ?? [])];
  if (ip) addIoc(sink, "ip", ip);

  let description = `Google Workspace ${app}: ${name}`;
  if (actor) description += ` by ${actor}`;
  if (target) description += ` → ${oneLine(target).slice(0, 120)}`;
  if (ip) description += ` from ${ip}`;
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(text(getPath(rec, "id.time"))),
    description,
    severity,
    mitre,
    aggKey: `gws|${app}|${name}|${actor}|${ip}`.toLowerCase().slice(0, 400),
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
  for (const raw of records) {
    if (!isObject(raw)) continue;
    const rec = raw as Row;
    if (!isWorkspaceActivity(rec)) continue;
    const events = getCI(rec, "events");
    // One record, N events — each is its own thing that happened.
    const list = Array.isArray(events) ? events : [];
    for (const e of list) {
      if (!isObject(e)) continue;
      mapped.push(mapEvent(rec, e as Row, iocSink));
    }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

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
