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

// Deterministic importer for the Okta System Log (API v1 `/api/v1/logs`) — the identity ingest path
// for orgs that federate through Okta rather than Entra. Sibling of m365Import.ts; no AI call.
//
// Okta grades its own records with a `severity` field, but that field describes OPERATIONAL
// importance to the Okta admin (INFO/WARN/ERROR), not maliciousness to an investigator — a
// successful attacker login is INFO. Severity is therefore DERIVED from the eventType, the same way
// the SIEM importer derives it per event id, and Okta's own value is ignored. This is not a
// detection engine: every mapping below is "this operation is worth an analyst's attention", not
// "this is an attack".
//
// The tradecraft the table encodes is account-takeover and persistence in the IdP: MFA factors
// removed or reset, policies weakened, API tokens minted, admin roles granted, sessions
// impersonated, OAuth grants consented. Those are the actions that turn one phished password into
// durable access, and they are the reason an Okta log is worth importing at all.

type Row = Record<string, unknown>;

export interface OktaImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface OktaParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "okta-system-log" | "empty"
}

interface EventDef {
  severity: Severity;
  mitre?: string[];
}

// Curated high-signal Okta event types → derived severity + MITRE. Keys are exact eventType values,
// lowercased. Anything absent falls to the prefix heuristics below, then Info.
const OKTA_EVENTS: Record<string, EventDef> = {
  // ── Authentication ──
  "user.session.start": { severity: "Info", mitre: ["T1078.004"] },
  "user.authentication.sso": { severity: "Info", mitre: ["T1078.004"] },
  "user.session.impersonation.initiate": { severity: "High", mitre: ["T1078.004"] },
  "user.session.impersonation.grant": { severity: "High", mitre: ["T1078.004"] },
  "user.account.lock": { severity: "Medium", mitre: ["T1110"] },
  "user.account.unlock": { severity: "Medium" },

  // ── MFA tampering: the single most load-bearing group here. Removing or resetting a factor is
  //    how an attacker who has the password keeps access past the next login.
  "user.mfa.factor.deactivate": { severity: "High", mitre: ["T1556.006"] },
  "user.mfa.factor.suspend": { severity: "High", mitre: ["T1556.006"] },
  "user.mfa.factor.reset_all": { severity: "High", mitre: ["T1556.006"] },
  "system.mfa.factor.deactivate": { severity: "High", mitre: ["T1556.006"] },
  "user.mfa.factor.activate": { severity: "Medium", mitre: ["T1556.006"] },
  "user.mfa.factor.update": { severity: "Medium", mitre: ["T1556.006"] },
  "user.authentication.auth_via_mfa": { severity: "Info" },

  // ── Credential and recovery changes ──
  "user.account.reset_password": { severity: "Medium", mitre: ["T1098"] },
  "user.account.update_password": { severity: "Medium", mitre: ["T1098"] },
  "user.account.unlock_by_admin": { severity: "Medium" },
  "user.account.report_suspicious_activity_by_enduser": { severity: "Medium" },

  // ── Privilege and tenancy ──
  "user.account.privilege.grant": { severity: "High", mitre: ["T1098.003"] },
  "group.user_membership.add": { severity: "Medium", mitre: ["T1098"] },
  "user.lifecycle.create": { severity: "Medium", mitre: ["T1136.003"] },
  "user.lifecycle.activate": { severity: "Medium", mitre: ["T1136.003"] },
  "user.lifecycle.delete.initiated": { severity: "Medium" },

  // ── Durable programmatic access ──
  "system.api_token.create": { severity: "High", mitre: ["T1098.001"] },
  "app.oauth2.client.credential.create": { severity: "High", mitre: ["T1098.001"] },
  "app.oauth2.as.consent.grant": { severity: "High", mitre: ["T1528"] },
  "application.user_membership.add": { severity: "Medium", mitre: ["T1098"] },
  "application.lifecycle.create": { severity: "Medium" },

  // ── Policy weakening: a rule change that drops MFA for a group is silent and total. ──
  "policy.lifecycle.update": { severity: "High", mitre: ["T1556"] },
  "policy.rule.update": { severity: "High", mitre: ["T1556"] },
  "policy.rule.delete": { severity: "High", mitre: ["T1556"] },
  "policy.lifecycle.delete": { severity: "High", mitre: ["T1556"] },
  "zone.update": { severity: "Medium", mitre: ["T1556"] },

  // ── Federation tampering (Golden SAML territory) ──
  "system.idp.lifecycle.create": { severity: "High", mitre: ["T1484.002"] },
  "system.idp.lifecycle.update": { severity: "High", mitre: ["T1484.002"] },
};

// Prefix fallbacks for the long tail, so a type Okta adds later still lands somewhere sensible
// rather than silently at Info. Checked in order; first match wins.
const PREFIX_RULES: ReadonlyArray<readonly [string, EventDef]> = [
  ["user.mfa.", { severity: "Medium", mitre: ["T1556.006"] }],
  ["policy.", { severity: "Medium", mitre: ["T1556"] }],
  ["system.idp.", { severity: "Medium", mitre: ["T1484.002"] }],
  ["system.api_token.", { severity: "Medium", mitre: ["T1098.001"] }],
  ["app.oauth2.", { severity: "Medium", mitre: ["T1528"] }],
];

// Which event types a FAILURE on is credential-access signal. Okta namespaces its types, so the
// prefixes are the contract: session start/end, the authentication family, and the MFA challenge
// path. Everything else (policy, app, token, group, user lifecycle) can fail for a hundred
// operational reasons that have nothing to do with guessing a password.
const AUTH_EVENT_PREFIXES = [
  "user.session.",
  "user.authentication.",
  "user.mfa.attempt",
  "user.mfa.factor.verify",
  "system.push.send_factor_verify",
] as const;

function isAuthEvent(eventType: string): boolean {
  const key = eventType.trim().toLowerCase();
  return AUTH_EVENT_PREFIXES.some((p) => key.startsWith(p));
}

function defFor(eventType: string): EventDef {
  const key = eventType.trim().toLowerCase();
  const exact = OKTA_EVENTS[key];
  if (exact) return exact;
  for (const [prefix, def] of PREFIX_RULES) if (key.startsWith(prefix)) return def;
  return { severity: "Info" };
}

// An Okta System Log record always carries eventType + published. Anything without both is another
// product's JSON and is skipped rather than guessed at.
function isOktaEvent(rec: Row): boolean {
  return Boolean(getCI(rec, "eventType")) && Boolean(getCI(rec, "published"));
}

function text(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

// The first target worth naming — the app or user the operation acted on. Okta sends an array with
// mixed types; an AppInstance is the most useful to an analyst, else the first entry with a name.
function targetLabel(rec: Row): string {
  const targets = getCI(rec, "target");
  if (!Array.isArray(targets)) return "";
  const named = targets.filter(isObject) as Row[];
  const app = named.find((t) => /appinstance|app/i.test(text(getCI(t, "type"))));
  const pick = app ?? named[0];
  if (!pick) return "";
  return text(getCI(pick, "displayName") || getCI(pick, "alternateId"));
}

function mapEvent(rec: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const eventType = text(getCI(rec, "eventType"));
  const actor = text(getPath(rec, "actor.alternateId") || getPath(rec, "actor.displayName"));
  const ip = cleanIp(text(getPath(rec, "client.ipAddress")));
  const city = text(getPath(rec, "client.geographicalContext.city"));
  const country = text(getPath(rec, "client.geographicalContext.country"));
  const result = text(getPath(rec, "outcome.result"));
  const reason = text(getPath(rec, "outcome.reason"));
  const target = targetLabel(rec);
  const failed = /failure|deny|skipped/i.test(result);

  const def = defFor(eventType);
  let severity = def.severity;
  const mitre = [...(def.mitre ?? [])];
  // A failure is a different event from a success, but only an AUTHENTICATION failure is
  // brute-force signal. Tagging every failed operation T1110 reported a rejected policy edit or a
  // failed provisioning call as password guessing, which is a different claim about the attacker
  // entirely. Non-auth failures keep the [FAILED] annotation and their own derived severity — they
  // are still worth reading, just not as credential access.
  if (failed && isAuthEvent(eventType)) {
    if (severity === "Info") severity = "Medium";
    if (!mitre.includes("T1110")) mitre.push("T1110");
  }
  if (ip) addIoc(sink, "ip", ip);

  let description = `Okta ${eventType}`;
  if (actor) description += ` by ${actor}`;
  if (target) description += ` → ${oneLine(target).slice(0, 120)}`;
  if (ip) description += ` from ${ip}`;
  if (city || country) description += ` (${[city, country].filter(Boolean).join(", ")})`;
  if (failed) description += ` [FAILED${reason ? `: ${oneLine(reason).slice(0, 80)}` : ""}]`;
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(text(getCI(rec, "published"))),
    description,
    severity,
    mitre,
    aggKey: `okta|${eventType}|${actor}|${ip}|${result}`.toLowerCase().slice(0, 400),
    sources: ["Okta"],
  };
}

export function parseOktaSystemLog(input: string, opts: OktaImportOptions = {}): OktaParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const empty: OktaParseResult = {
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

  const records = extractRecords(trimmed).records;
  const total = records.length;
  if (total === 0) return empty;

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  for (const raw of records) {
    if (!isObject(raw)) continue;
    const rec = raw;
    if (!isOktaEvent(rec)) continue;
    mapped.push(mapEvent(rec, iocSink));
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
    dropped: Math.max(0, total - represented),
    groups,
    format: mapped.length ? "okta-system-log" : "empty",
  };
}
