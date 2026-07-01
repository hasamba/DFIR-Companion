// Deterministic importer for Microsoft 365 / Entra ID audit data — the cloud/identity ingest
// path (business-email-compromise & cloud IR). The eighth deterministic path; no AI call.
//
// Three related sources are handled, auto-detected per record:
//   1. M365 Unified Audit Log (UAL) — `Search-UnifiedAuditLog` CSV/JSON or the Office 365
//      Management Activity API. The rich detail is in an `AuditData` JSON string (when present)
//      that is parsed and merged over the outer row. Keyed by `Operation` + `Workload`.
//   2. Entra ID (Azure AD) SIGN-IN logs — Graph schema (`userPrincipalName`, `appDisplayName`,
//      `ipAddress`, `status.errorCode`, `riskLevelDuringSignIn`, `location`).
//   3. Entra ID directory AUDIT logs — Graph schema (`activityDisplayName`, `initiatedBy`,
//      `targetResources`).
//
// Like Windows event logs, M365 records carry no maliciousness score, so severity is DERIVED
// from the operation type (BEC tradecraft: inbox rules, mailbox delegation, OAuth/service-
// principal abuse, role grants, failed sign-ins) — the same approach as the SIEM importer's
// per-EID table, NOT a detection engine. Entra's own `riskLevel` (Identity Protection) IS a
// verdict and drives severity directly. The source IP becomes an IOC; the UPN is surfaced in
// the description so the asset↔IoC graph picks up the account.

import type { Severity } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";
import {
  extractRecords,
  aggregateEvents,
  cleanIp,
  addIoc,
  firstStr,
  oneLine,
  str,
  isObject,
  getCI,
  getPath,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface M365ImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface M365ParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;  // "m365-ual" | "entra-signin" | "entra-audit" | "mixed" | "empty"
}

interface OpDef { severity: Severity; mitre?: string[]; }

// Curated high-signal M365/Entra operations → derived severity + MITRE (keys lowercased, no
// trailing period). Anything not here falls to the keyword heuristics, then Info.
const M365_OPS: Record<string, OpDef> = {
  "new-inboxrule": { severity: "High", mitre: ["T1564.008"] },
  "set-inboxrule": { severity: "High", mitre: ["T1564.008"] },
  "updateinboxrules": { severity: "High", mitre: ["T1564.008"] },
  "new-transportrule": { severity: "High", mitre: ["T1114"] },
  "set-transportrule": { severity: "High", mitre: ["T1114"] },
  "add-mailboxpermission": { severity: "High", mitre: ["T1098.002"] },
  "add-mailboxfolderpermission": { severity: "Medium", mitre: ["T1098.002"] },
  "set-mailbox": { severity: "Medium", mitre: ["T1114"] },
  "add member to role": { severity: "High", mitre: ["T1098.003"] },
  "add eligible member to role": { severity: "High", mitre: ["T1098.003"] },
  "add service principal": { severity: "High", mitre: ["T1098.001"] },
  "add service principal credentials": { severity: "High", mitre: ["T1098.001"] },
  "consent to application": { severity: "High", mitre: ["T1528"] },
  "add delegated permission grant": { severity: "High", mitre: ["T1528"] },
  "add app role assignment grant to user": { severity: "High", mitre: ["T1528"] },
  "add application": { severity: "Medium", mitre: ["T1098.001"] },
  "update application": { severity: "Medium", mitre: ["T1098.001"] },
  "add user": { severity: "Medium", mitre: ["T1136.003"] },
  "delete user": { severity: "Medium" },
  "disable account": { severity: "Medium" },
  "reset user password": { severity: "Medium", mitre: ["T1098"] },
  "change user password": { severity: "Medium", mitre: ["T1098"] },
  "userloggedin": { severity: "Info", mitre: ["T1078.004"] },
  "userloginfailed": { severity: "Medium", mitre: ["T1110"] },
  "mailitemsaccessed": { severity: "Low", mitre: ["T1114"] },
  "sendas": { severity: "Medium", mitre: ["T1114"] },
  "sendonbehalf": { severity: "Medium", mitre: ["T1114"] },
  "filemalwaredetected": { severity: "High", mitre: ["T1204"] },
  "filedownloaded": { severity: "Low", mitre: ["T1530"] },
  "filesyncdownloadedfull": { severity: "Low", mitre: ["T1530"] },
  "harddelete": { severity: "Low", mitre: ["T1070.008"] },
  "softdelete": { severity: "Low", mitre: ["T1070.008"] },
  "disable-antiphishrule": { severity: "High", mitre: ["T1562"] },
  "remove mfa": { severity: "High", mitre: ["T1556.006"] },
};

function opSeverity(op: string): OpDef {
  const k = op.toLowerCase().trim().replace(/\.$/, "");
  if (M365_OPS[k]) return M365_OPS[k];
  if (/inbox\s*rule/.test(k)) return { severity: "High", mitre: ["T1564.008"] };
  if (/service principal|application.*(secret|credential|certificat)/.test(k)) return { severity: "High", mitre: ["T1098.001"] };
  if (/consent to application|oauth2permission|delegated permission/.test(k)) return { severity: "High", mitre: ["T1528"] };
  if (/add (member|eligible member) to role/.test(k)) return { severity: "High", mitre: ["T1098.003"] };
  if (/transportrule/.test(k)) return { severity: "High", mitre: ["T1114"] };
  if (/mailboxpermission/.test(k)) return { severity: "High", mitre: ["T1098.002"] };
  if (/password/.test(k)) return { severity: "Medium", mitre: ["T1098"] };
  if (/loginfailed|failed/.test(k)) return { severity: "Medium", mitre: ["T1110"] };
  if (/malware/.test(k)) return { severity: "High", mitre: ["T1204"] };
  return { severity: "Info" };
}

// ───────────────────────────── value helpers ─────────────────────────────

function arrFirst(v: unknown): unknown {
  return Array.isArray(v) ? v.find((x) => x != null && x !== "") : v;
}
function pickStr(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const s = str(arrFirst(v)).trim();
    if (s) return s;
  }
  return "";
}

// Pull a usable IP from M365 ClientIP forms: "1.2.3.4", "[1.2.3.4]:port", "[ipv6]:port".
function extractIp(s: string): string {
  const v = s.trim();
  if (!v) return "";
  const m4 = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(v);
  if (m4) return cleanIp(m4[1]);
  const m6 = /\[([0-9a-f:]+)\]/i.exec(v);
  if (m6) return cleanIp(m6[1]);
  return cleanIp(v);
}

// Merge a record's parsed `AuditData` JSON (UAL) over the outer row; pass others through.
function normalizeRecord(rec: Row): Row {
  const ad = getCI(rec, "AuditData");
  if (typeof ad === "string" && ad.trim().startsWith("{")) {
    try { return { ...rec, ...(JSON.parse(ad) as Row) }; } catch { /* keep outer */ }
  } else if (isObject(ad)) {
    return { ...rec, ...ad };
  }
  return rec;
}

// ───────────────────────────── classification ─────────────────────────────

type Kind = "ual" | "signin" | "audit" | "other";

function classify(rec: Row): Kind {
  if (getCI(rec, "Operation") || getCI(rec, "Operations")) return "ual";
  if (getCI(rec, "userPrincipalName") && (getCI(rec, "appDisplayName") || getCI(rec, "ipAddress")) &&
      (getCI(rec, "status") || getCI(rec, "riskState") || getCI(rec, "riskLevelDuringSignIn"))) return "signin";
  if (getCI(rec, "activityDisplayName") && (getCI(rec, "initiatedBy") || getCI(rec, "targetResources"))) return "audit";
  // A bare AuditData object (Management API) still has Workload + RecordType.
  if (getCI(rec, "Workload") && getCI(rec, "RecordType")) return "ual";
  return "other";
}

// ───────────────────────────── mappers ─────────────────────────────

function mapUal(rec: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const op = pickStr(rec, ["Operation", "Operations"]) || "operation";
  const workload = pickStr(rec, ["Workload"]);
  const user = pickStr(rec, ["UserId", "UserKey", "UserIds"]);
  const ip = extractIp(pickStr(rec, ["ClientIP", "ClientIPAddress", "ActorIpAddress", "ClientInfoString"]));
  const target = pickStr(rec, ["ObjectId", "MailboxOwnerUPN", "SiteUrl", "TargetUserOrGroupName"]);
  const result = pickStr(rec, ["ResultStatus", "ResultStatusDetail"]);
  const failed = /fail/i.test(result);

  const def = opSeverity(op);
  let severity = def.severity;
  if (failed && severity === "Info") severity = "Low";
  if (ip) addIoc(sink, "ip", ip);

  let description = `M365 ${workload || "audit"}: ${op}`;
  if (user) description += ` by ${user}`;
  if (ip) description += ` from ${ip}`;
  if (target && target !== user) description += ` → ${oneLine(target).slice(0, 120)}`;
  if (failed) description += " [FAILED]";
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(pickStr(rec, ["CreationTime", "CreationDate"])),
    description, severity, mitre: [...(def.mitre ?? [])],
    aggKey: `m365|${workload}|${op}|${user}|${ip}`.toLowerCase().slice(0, 400),
    sources: ["Microsoft 365"],
  };
}

function mapSignIn(rec: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const upn = pickStr(rec, ["userPrincipalName", "userDisplayName"]);
  const app = pickStr(rec, ["appDisplayName", "resourceDisplayName"]);
  const ip = extractIp(pickStr(rec, ["ipAddress"]));
  const errorCode = Number(getPath(rec, "status.errorCode") ?? getCI(rec, "errorCode")) || 0;
  const failureReason = pickStr(rec, ["status.failureReason", "status.additionalDetails"]);
  const risk = pickStr(rec, ["riskLevelDuringSignIn", "riskLevelAggregated", "riskState"]).toLowerCase();
  const city = pickStr(rec, ["location.city"]);
  const country = pickStr(rec, ["location.countryOrRegion"]);
  // ROPC (Resource Owner Password Credentials) legacy-auth grant — sends the password directly to
  // the token endpoint with no interactive MFA prompt, a known Conditional-Access/MFA bypass. Entra
  // sign-in logs surface this as the literal "BAV2ROPC" marker in the client UserAgent.
  const isRopc = /bav2ropc/i.test(pickStr(rec, ["userAgent", "UserAgent"]));

  let severity: Severity; const mitre = ["T1078.004"];
  if (/high|confirmedcompromised|atrisk/.test(risk)) severity = "High";
  else if (risk === "medium") severity = "Medium";
  else if (isRopc) { severity = "Medium"; mitre.push("T1556.007", "T1621"); }
  else if (errorCode !== 0) { severity = "Medium"; mitre.push("T1110"); }
  else severity = "Info";
  if (ip) addIoc(sink, "ip", ip);

  let description = `Entra sign-in: ${upn || "?"}`;
  if (ip) description += ` from ${ip}`;
  if (city || country) description += ` (${[city, country].filter(Boolean).join(", ")})`;
  if (app) description += ` via ${app}`;
  if (errorCode !== 0) description += ` [FAILED${failureReason ? `: ${oneLine(failureReason).slice(0, 80)}` : ""}]`;
  if (risk && risk !== "none") description += ` [risk: ${risk}]`;
  if (isRopc) description += " [legacy-auth ROPC — MFA bypass]";
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(pickStr(rec, ["createdDateTime"])),
    description, severity, mitre,
    aggKey: `entra-signin|${upn}|${ip}|${app}|${errorCode}|${risk}`.toLowerCase().slice(0, 400),
    sources: ["Entra ID"],
  };
}

function mapAudit(rec: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const activity = pickStr(rec, ["activityDisplayName"]) || "directory change";
  const initiator = pickStr(rec, ["initiatedBy.user.userPrincipalName", "initiatedBy.app.displayName"]);
  const initiatorIp = extractIp(pickStr(rec, ["initiatedBy.user.ipAddress"]));
  const result = pickStr(rec, ["result"]);
  const targets = getCI(rec, "targetResources");
  const target = Array.isArray(targets) && isObject(targets[0])
    ? str(getCI(targets[0] as Row, "userPrincipalName") || getCI(targets[0] as Row, "displayName")) : "";

  const def = opSeverity(activity);
  if (initiatorIp) addIoc(sink, "ip", initiatorIp);

  let description = `Entra audit: ${activity}`;
  if (initiator) description += ` by ${initiator}`;
  if (initiatorIp) description += ` from ${initiatorIp}`;
  if (target) description += ` → ${oneLine(target).slice(0, 120)}`;
  if (result && !/success/i.test(result)) description += ` [${result}]`;
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(pickStr(rec, ["activityDateTime"])),
    description, severity: def.severity, mitre: [...(def.mitre ?? [])],
    aggKey: `entra-audit|${activity}|${initiator}|${target}`.toLowerCase().slice(0, 400),
    sources: ["Entra ID"],
  };
}

// ───────────────────────────── record extraction ─────────────────────────────

function extractM365(text: string): Row[] {
  const trimmed = text.trim();
  if (!trimmed) return [];
  if (trimmed[0] === "[" || trimmed[0] === "{") {
    return extractRecords(trimmed).records;
  }
  // CSV (Search-UnifiedAuditLog | Export-Csv): build row objects from the header.
  const { headers, rows } = parseCsv(trimmed);
  if (!headers.length) return [];
  return rows.map((cols) => { const r: Row = {}; headers.forEach((h, i) => { r[h.trim()] = cols[i] ?? ""; }); return r; });
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseM365Audit(text: string, opts: M365ImportOptions = {}): M365ParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const records = extractM365(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let sawUal = false, sawSignin = false, sawAudit = false;

  for (const raw of records) {
    const rec = normalizeRecord(raw);
    const kind = classify(rec);
    if (kind === "ual") { mapped.push(mapUal(rec, iocSink)); sawUal = true; }
    else if (kind === "signin") { mapped.push(mapSignIn(rec, iocSink)); sawSignin = true; }
    else if (kind === "audit") { mapped.push(mapAudit(rec, iocSink)); sawAudit = true; }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const kinds = [sawUal && "m365-ual", sawSignin && "entra-signin", sawAudit && "entra-audit"].filter(Boolean) as string[];
  const format = kinds.length > 1 ? "mixed" : kinds[0] ?? "empty";

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format,
  };
}
