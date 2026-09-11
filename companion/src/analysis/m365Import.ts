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
import { boundedAggKey } from "./aggKey.js";
import {
  extractRecords,
  aggregateEvents,
  cleanIp,
  addIoc,
  oneLine,
  str,
  isObject,
  getCI,
  getPath,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
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
  format: string; // "m365-ual" | "entra-signin" | "entra-audit" | "mixed" | "empty"
}

interface OpDef {
  severity: Severity;
  mitre?: string[];
}

// Curated high-signal M365/Entra operations → derived severity + MITRE (keys lowercased, no
// trailing period). Anything not here falls to the keyword heuristics, then Info.
const M365_OPS: Record<string, OpDef> = {
  "new-inboxrule": { severity: "High", mitre: ["T1564.008"] },
  "set-inboxrule": { severity: "High", mitre: ["T1564.008"] },
  updateinboxrules: { severity: "High", mitre: ["T1564.008"] },
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
  userloggedin: { severity: "Info", mitre: ["T1078.004"] },
  userloginfailed: { severity: "Medium", mitre: ["T1110"] },
  mailitemsaccessed: { severity: "Low", mitre: ["T1114"] },
  sendas: { severity: "Medium", mitre: ["T1114"] },
  sendonbehalf: { severity: "Medium", mitre: ["T1114"] },
  filemalwaredetected: { severity: "High", mitre: ["T1204"] },
  filedownloaded: { severity: "Low", mitre: ["T1530"] },
  filesyncdownloadedfull: { severity: "Low", mitre: ["T1530"] },
  harddelete: { severity: "Low", mitre: ["T1070.008"] },
  softdelete: { severity: "Low", mitre: ["T1070.008"] },
  "disable-antiphishrule": { severity: "High", mitre: ["T1562"] },
  "remove mfa": { severity: "High", mitre: ["T1556.006"] },
};

/** Does this operation read a FILE, as opposed to changing a setting? See the aggKey note. */
function isFileRead(op: string): boolean {
  return /^(?:filedownloaded|filesyncdownloadedfull|fileaccessed|filepreviewed)$/i.test((op ?? "").trim());
}

function opSeverity(op: string): OpDef {
  const k = op.toLowerCase().trim().replace(/\.$/, "");
  if (M365_OPS[k]) return M365_OPS[k];
  if (/inbox\s*rule/.test(k)) return { severity: "High", mitre: ["T1564.008"] };
  if (/service principal|application.*(secret|credential|certificat)/.test(k))
    return { severity: "High", mitre: ["T1098.001"] };
  if (/consent to application|oauth2permission|delegated permission/.test(k))
    return { severity: "High", mitre: ["T1528"] };
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
    try {
      return { ...rec, ...(JSON.parse(ad) as Row) };
    } catch {
      /* keep outer */
    }
  } else if (isObject(ad)) {
    return { ...rec, ...ad };
  }
  return rec;
}

// ───────────────────────────── classification ─────────────────────────────

type Kind = "ual" | "signin" | "audit" | "other";

function classify(rec: Row): Kind {
  if (getCI(rec, "Operation") || getCI(rec, "Operations")) return "ual";
  if (
    getCI(rec, "userPrincipalName") &&
    (getCI(rec, "appDisplayName") || getCI(rec, "ipAddress")) &&
    (getCI(rec, "status") || getCI(rec, "riskState") || getCI(rec, "riskLevelDuringSignIn"))
  )
    return "signin";
  if (getCI(rec, "activityDisplayName") && (getCI(rec, "initiatedBy") || getCI(rec, "targetResources")))
    return "audit";
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
    description,
    severity,
    mitre: [...(def.mitre ?? [])],
    // The RESOURCE is part of the key for an object read. Without it, aggregation folded every
    // read by one principal into a single counted event before any correlation could see it — so
    // bulk-read detection (#908 item 8) was structurally blind to this provider. Only data-plane
    // reads carry it: a hundred management calls by one principal genuinely are one thing, and
    // adding the resource everywhere would undo the aggregation this importer exists to do.
    aggKey: `m365|${workload}|${op}|${user}|${ip}${isFileRead(op) && target ? `|${target}` : ""}`
      .toLowerCase()
      .slice(0, 400),
    sources: ["Microsoft 365"],
  };
}

// The Entra sign-in error codes that mean CREDENTIAL VALIDATION ITSELF FAILED, and nothing else.
// A code in this set is the only kind of failure that supports a T1110 (brute force / spray) claim.
//
// This set is an ALLOW-LIST for a reason. Every nonzero errorCode used to become Medium + T1110,
// which made a brute-force finding out of an MFA challenge (50074, 50076), a Conditional Access
// block (53003), an expired password (50055), a "keep me signed in" prompt (50140) and the single
// most common code in any tenant export, 50058 — which Microsoft documents as "expected when a
// user is unauthenticated and hasn't yet signed in". The failed side of a real tenant's sign-in log
// is mostly interrupts, so the old rule graded routine noise as an attack. Enumerating the
// credential failures is bounded; enumerating everything that is NOT one is not.
//
// Codes and meanings from Microsoft's AADSTS reference (learn.microsoft.com/entra/identity-platform
// /reference-error-codes). A code outside this set is still reported as a failure — it just does
// not carry an attack technique.
const CREDENTIAL_FAILURE_CODES = new Set([
  50034, // UserAccountNotFound — the account does not exist (enumeration / spray fan-out)
  50056, // Invalid or null password
  50064, // CredentialAuthenticationError — username/password validation failed
  50126, // InvalidUserNameOrPassword — the wrong-password code
]);

// 50053 is NOT in that set, because Microsoft documents it as two different conditions: IdsLocked
// ("the account is locked because the user tried to sign in too many times with an incorrect user
// ID or password") OR a sign-in blocked because it came from an IP address with malicious activity.
// The first is the strongest single spray signal there is; the second is a risk/policy block that
// says nothing about passwords. Asserting T1110 for both would re-introduce, in the allow-list
// meant to end it, exactly the overstatement this classifier exists to remove. Microsoft's own
// remediation advice is to read the Failure Reason to tell them apart, so that is what decides —
// and an absent or unrecognised reason stays the conservative side of the split.
const LOCKOUT_REASON = /\block(?:ed|out)?\b/i;

// The outcome of one sign-in record, kept separate from severity so a missing, empty or malformed
// status can never take the success path. `Number(x) || 0` used to fold a non-numeric errorCode
// into 0 — the same value a genuine success carries — and an ABSENT status took that path too,
// even though a record reaches this mapper on a risk field alone, with no status at all. Only a
// finite numeric zero is a success now; everything unreadable is `unknown` and says so.
type SignInOutcome = "success" | "credential-failure" | "other-failure" | "unknown";

function signInOutcome(raw: unknown, failureReason: string): { outcome: SignInOutcome; code: number | null } {
  if (raw === undefined || raw === null || raw === "") return { outcome: "unknown", code: null };
  const code = Number(raw);
  if (!Number.isFinite(code)) return { outcome: "unknown", code: null };
  if (code === 0) return { outcome: "success", code: 0 };
  const credential =
    CREDENTIAL_FAILURE_CODES.has(code) || (code === 50053 && LOCKOUT_REASON.test(failureReason));
  return { outcome: credential ? "credential-failure" : "other-failure", code };
}

function mapSignIn(rec: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const upn = pickStr(rec, ["userPrincipalName", "userDisplayName"]);
  const app = pickStr(rec, ["appDisplayName", "resourceDisplayName"]);
  const ip = extractIp(pickStr(rec, ["ipAddress"]));
  const failureReason = pickStr(rec, ["status.failureReason", "status.additionalDetails"]);
  const { outcome, code } = signInOutcome(
    getPath(rec, "status.errorCode") ?? getCI(rec, "errorCode"),
    failureReason,
  );
  const risk = pickStr(rec, ["riskLevelDuringSignIn", "riskLevelAggregated", "riskState"]).toLowerCase();
  const city = pickStr(rec, ["location.city"]);
  const country = pickStr(rec, ["location.countryOrRegion"]);
  // ROPC (Resource Owner Password Credentials) legacy-auth grant — sends the password straight to
  // the token endpoint, so no interactive MFA prompt is shown. Entra surfaces it as the literal
  // "BAV2ROPC" marker in the client UserAgent.
  //
  // WHAT THIS IS NOT: proof that MFA was bypassed. The UserAgent is a client-supplied string, and
  // Conditional Access can block the grant outright — in which case the record is a FAILED sign-in
  // that the old code still described as "MFA bypass". It also carried T1556.007 (Hybrid Identity)
  // and T1621 (MFA Request Generation — push bombing); ROPC is neither, and it generates no MFA
  // request at all. There is no ATT&CK technique for "authenticated over a legacy protocol", so the
  // honest mapping is the T1078.004 already present. See #931 item 3.
  const isRopc = /bav2ropc/i.test(pickStr(rec, ["userAgent", "UserAgent"]));

  let severity: Severity;
  const mitre = ["T1078.004"];
  if (/high|confirmedcompromised|atrisk/.test(risk)) severity = "High";
  else if (risk === "medium") severity = "Medium";
  else if (outcome === "credential-failure") {
    severity = "Medium";
    mitre.push("T1110");
  } else if (outcome === "success" && isRopc) severity = "Medium";
  // A failure that is not a credential failure, and a record whose status could not be read, are
  // both worth seeing and neither is evidence of an attack.
  else if (outcome !== "success") severity = "Low";
  else severity = "Info";
  if (ip) addIoc(sink, "ip", ip);

  let description = `Entra sign-in: ${upn || "?"}`;
  if (ip) description += ` from ${ip}`;
  if (city || country) description += ` (${[city, country].filter(Boolean).join(", ")})`;
  if (app) description += ` via ${app}`;
  if (outcome === "unknown") description += " [outcome unknown: unreadable status]";
  else if (outcome !== "success")
    description += ` [FAILED${code === null ? "" : ` ${code}`}${failureReason ? `: ${oneLine(failureReason).slice(0, 80)}` : ""}]`;
  if (risk && risk !== "none") description += ` [risk: ${risk}]`;
  if (isRopc) description += " [legacy-auth ROPC — no interactive MFA prompt]";
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(pickStr(rec, ["createdDateTime"])),
    description,
    severity,
    mitre,
    // `outcome` and `isRopc` are both discriminators: keying on the raw code alone folded an
    // unreadable status into the `0` bucket that genuine successes use, and left a ROPC grant to
    // merge with an ordinary sign-in by the same user (aggregation keeps ONE description).
    aggKey: `entra-signin|${upn}|${ip}|${app}|${outcome}|${code ?? "?"}|${risk}|${isRopc ? "ropc" : ""}`
      .toLowerCase()
      .slice(0, 400),
    sources: ["Entra ID"],
  };
}

// Graph's directoryAudit.result is one of success | failure | timeout | unknownFutureValue, and a
// non-Graph export may spell success as succeeded/OK. Each Graph value is its own outcome — a
// timeout is not a failure — and only an absent or unrecognised value is "unknown".
function auditOutcome(result: string): "success" | "failure" | "timeout" | "unknownFutureValue" | "unknown" {
  const r = result.trim().toLowerCase();
  if (/^(success|succeeded|successful|ok)$/.test(r)) return "success";
  if (r === "failure" || r === "failed") return "failure";
  if (r === "timeout") return "timeout";
  if (r === "unknownfuturevalue") return "unknownFutureValue";
  return "unknown";
}

function mapAudit(rec: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const activity = pickStr(rec, ["activityDisplayName"]) || "directory change";
  const initiator = pickStr(rec, ["initiatedBy.user.userPrincipalName", "initiatedBy.app.displayName"]);
  // Identity for the KEY, never the display name: two apps can share "Sync" and differ by id.
  const initiatorId =
    pickStr(rec, ["initiatedBy.user.id", "initiatedBy.app.appId", "initiatedBy.app.servicePrincipalId"]) ||
    initiator;
  const initiatorIp = extractIp(pickStr(rec, ["initiatedBy.user.ipAddress"]));
  const result = pickStr(rec, ["result"]);
  // EVERY target, as a typed stable identity, deduplicated and sorted so order does not matter. The
  // old key took targetResources[0]'s display name: a change naming two users was "the first
  // user", and two applications sharing a display name were one.
  const targets = getCI(rec, "targetResources");
  const targetIds = [
    ...new Set(
      (Array.isArray(targets) ? targets : [])
        .filter(isObject)
        .map(
          (t) =>
            `${str(getCI(t, "type")) || "resource"}:${str(getCI(t, "id")) || str(getCI(t, "userPrincipalName")) || str(getCI(t, "displayName"))}`,
        )
        .filter((x) => !x.endsWith(":")),
    ),
  ].sort();
  const targetLabels = (Array.isArray(targets) ? targets : [])
    .filter(isObject)
    .map((t) => str(getCI(t, "userPrincipalName") || getCI(t, "displayName")))
    .filter(Boolean);
  const target = targetLabels.length
    ? `${targetLabels[0]}${targetLabels.length > 1 ? ` +${targetLabels.length - 1} more` : ""}`
    : "";

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
    description,
    severity: def.severity,
    mitre: [...(def.mitre ?? [])],
    // Bounded identities first, the target list last, bounded with a digest (#931 prerequisite).
    aggKey: boundedAggKey(
      `entra-audit|${activity}|${auditOutcome(result)}|${initiatorId}|${targetIds.join(",")}`.toLowerCase(),
    ),
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
  return rows.map((cols) => {
    const r: Row = {};
    headers.forEach((h, i) => {
      r[h.trim()] = cols[i] ?? "";
    });
    return r;
  });
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
  let sawUal = false,
    sawSignin = false,
    sawAudit = false;

  for (const raw of records) {
    const rec = normalizeRecord(raw);
    const kind = classify(rec);
    if (kind === "ual") {
      mapped.push(mapUal(rec, iocSink));
      sawUal = true;
    } else if (kind === "signin") {
      mapped.push(mapSignIn(rec, iocSink));
      sawSignin = true;
    } else if (kind === "audit") {
      mapped.push(mapAudit(rec, iocSink));
      sawAudit = true;
    }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const kinds = [sawUal && "m365-ual", sawSignin && "entra-signin", sawAudit && "entra-audit"].filter(
    Boolean,
  ) as string[];
  const format = kinds.length > 1 ? "mixed" : (kinds[0] ?? "empty");

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
