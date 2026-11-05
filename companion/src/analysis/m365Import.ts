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
import { readCloudRecords } from "./cloudRecords.js";
import { adaptM365ExportRows, type UndatedRows } from "./m365ExportAdapters.js";
import type { JsonRepairs } from "./tolerantJson.js";
import { isEntraUalRecord } from "./entraAuditRecord.js";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { isExchangeRecord, mapExchangeRow } from "./exchangeAuditImport.js";
import { entraPrivilegePaths, PRIVILEGE_PATHS_MAX } from "./entraPrivilegePath.js";
import { mailboxChains, MAILBOX_CHAINS_MAX } from "./mailboxChain.js";
import { isEntraSignIn, readEntraSignIn } from "./ualLogon.js";
import { sprayPatternRows, SPRAY_PATTERNS_MAX, type SprayCandidate } from "./passwordSprayFanout.js";
import { createCanonicalEvent, sourceArtifactHash } from "./canonicalEvent.js";
import { m365Coverage } from "./cloudCoverageBuilders.js";
import {
  applySigmaMatches,
  applySigmaToRecordRows,
  sigmaMatchesFor,
  type SigmaGradingSnapshot,
} from "./sigmaImportGrade.js";
import type { CloudCoverageDraft } from "./cloudCoverage.js";
import {
  isServicePrincipalSignIn,
  learnApiResolver,
  mapEntraAuditRows,
  mapSpSignIn,
  type Resolver,
} from "./entraAuditImport.js";
import {
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
import type { ImportDebugRecorder } from "./importDebug.js";
import { cloudRecordIdentity, m365RecordProvider, type CloudRecordIdentity } from "./cloudRecordIdentity.js";
import { gateRecords, gateRows, isDuplicateRecord, type RecordGate } from "./cloudRecordGate.js";
import type { AggregateProvenance } from "./eventAggregate.js";
import { signInObservation } from "./signInObservation.js";
import type { StoredAuthObservation } from "./authObservationStore.js";

type Row = Record<string, unknown>;

export interface M365ImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  /** This attempt's import debug recorder (#1736): decisions and counts only, never row content. */
  debug?: ImportDebugRecorder;
  /**
   * Import-time Sigma rules (#2202), applied to Entra user sign-ins and Graph / Log Analytics
   * directory-audit records. UAL-shaped Entra records and service-principal sign-ins are not graded:
   * their fields differ from what the azure/signinlogs and azure/auditlogs rules are written for.
   */
  sigma?: SigmaGradingSnapshot;
  /** The upload already read by `extractM365Records` (#2301), so the ingest layer reads it once. */
  prepared?: M365Records;
  /** The case ledger's verdict per record (#2301): duplicates are skipped before aggregation. */
  recordGate?: RecordGate;
  /** Aggregate → source-record membership sink (#2301). */
  provenance?: AggregateProvenance;
  /**
   * Streaming import (#2303): the records are one batch of a larger file. `recordIndexBase` is the
   * batch's offset in the file, so every `record:<index>` locator still points into the upload;
   * `resolver` is the object-id → app-id lookup learned over the WHOLE file by the preliminary pass;
   * `rowsOnly` returns the mapped rows unaggregated (the streaming importer budgets them itself) and
   * skips the whole-export summaries; `spraySummary: false` leaves the within-upload spray row out.
   */
  recordIndexBase?: number;
  resolver?: Resolver;
  rowsOnly?: boolean;
  spraySummary?: boolean;
}

export interface M365ParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "m365-ual" | "entra-signin" | "entra-audit" | "mixed" | "empty"
  /** Per-upload coverage drafts (#1063) — Workload/Operation per tenant. */
  coverage: CloudCoverageDraft[];
  // Every within-upload spray candidate this parse built (#1104) — importBatch left unset here,
  // since parseM365Audit is pure and has no idPrefix; the ingest layer (importM365) stamps it.
  sprayCandidates: SprayCandidate[];
  // Every Entra sign-in for the sign-in observation store (#2301), MFA interruptions included.
  signInObservations: Array<Omit<StoredAuthObservation, "importBatch">>;
  /** Rows a Sigma rule matched (#2204), for the import note; 0 without a snapshot. */
  sigmaRowsMatched?: number;
  /** What the tolerant reader repaired to read the file (#2302), disclosed in the import note. */
  repairs?: JsonRepairs;
  /** Mailbox audit rows left without a time: the file's date order is unknown (#2302). */
  undatedRows?: UndatedRows;
  /** The mapped rows, unaggregated — only with `rowsOnly` (#2303). */
  mapped?: MappedEvent[];
  /** For each `mapped` row, the index (in this batch) of the record it came from. */
  rowRecords?: number[];
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
// `onKey` hears which candidate key supplied the value (#1736) — the key name, never the value.
function pickStr(row: Row, keys: string[], onKey?: (key: string) => void): string {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const s = str(arrFirst(v)).trim();
    if (s) {
      onKey?.(k);
      return s;
    }
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
export function normalizeRecord(rec: Row): Row {
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

type Kind = "ual" | "signin" | "spsignin" | "audit" | "other";

function classify(rec: Row): Kind {
  if (getCI(rec, "Operation") || getCI(rec, "Operations")) return "ual";
  if (isServicePrincipalSignIn(rec)) return "spsignin";
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

function mapUal(rec: Row, sink: Map<string, SiemIoc>, debug?: ImportDebugRecorder): MappedEvent {
  const op = pickStr(rec, ["Operation", "Operations"], (k) => debug?.field("action", k)) || "operation";
  const workload = pickStr(rec, ["Workload"]);
  const user = pickStr(rec, ["UserId", "UserKey", "UserIds"], (k) => debug?.field("user", k));
  // All four are Microsoft 365's own Unified Audit Log fields, recorded by Microsoft's own
  // service infrastructure from the authenticated session's real connection — edge-observed, not
  // client-asserted (#1184 audit).
  const ip = extractIp(
    pickStr(rec, ["ClientIP", "ClientIPAddress", "ActorIpAddress", "ClientInfoString"], (k) =>
      debug?.field("source_ip", k),
    ),
  );
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
  // The target and the description are both identities downstream (correlation keys on the
  // description once aggKey is gone), so each clip keeps a digest of what it removed (#940).
  if (target && target !== user) description += ` → ${boundedTextTo(oneLine(target), 120)}`;
  if (failed) description += " [FAILED]";
  description = boundedTextTo(description, 600);

  return {
    timestamp: normalizeTime(
      pickStr(rec, ["CreationTime", "CreationDate", "TimeGenerated"], (k) => debug?.field("timestamp", k)),
    ),
    description,
    severity,
    mitre: [...(def.mitre ?? [])],
    // The RESOURCE is part of the key for an object read. Without it, aggregation folded every
    // read by one principal into a single counted event before any correlation could see it — so
    // bulk-read detection (#908 item 8) was structurally blind to this provider. Only data-plane
    // reads carry it: a hundred management calls by one principal genuinely are one thing, and
    // adding the resource everywhere would undo the aggregation this importer exists to do.
    aggKey: boundedAggKey(
      `m365|${workload}|${op}|${user}|${ip}${isFileRead(op) && target ? `|${target}` : ""}`.toLowerCase(),
    ),
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

function mapSignIn(
  rec: Row,
  sink: Map<string, SiemIoc>,
  index: number,
  debug?: ImportDebugRecorder,
): MappedEvent {
  const upn = pickStr(rec, ["userPrincipalName", "userDisplayName"], (k) => debug?.field("user", k));
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
  description = boundedTextTo(description, 600); // an identity downstream — see mapUal

  return {
    timestamp: normalizeTime(pickStr(rec, ["createdDateTime"])),
    description,
    severity,
    mitre,
    // `outcome` and `isRopc` are both discriminators: keying on the raw code alone folded an
    // unreadable status into the `0` bucket that genuine successes use, and left a ROPC grant to
    // merge with an ordinary sign-in by the same user (aggregation keeps ONE description).
    aggKey: boundedAggKey(
      `entra-signin|${upn}|${ip}|${app}|${outcome}|${code ?? "?"}|${risk}|${isRopc ? "ropc" : ""}`.toLowerCase(),
    ),
    sources: ["Entra ID"],
    // Minimal canonical envelope (931.3, #1086, #1100 item 1): just enough structure for a
    // correlator to group on `account.name` / `event.outcome` without parsing `description`.
    // `event.outcome` carries the raw outcome string verbatim (no enum in the schema, so nothing
    // is collapsed the way a binary failed/success mapping would). No isRopc/riskLevel fields —
    // neither exists in canonicalEventEnvelopeSchema's `authentication` block, and correlation
    // above needs neither; ROPC and risk stay exactly where they already were, in `description`.
    ...(upn
      ? {
          canonical: createCanonicalEvent({
            event: { category: "authentication", type: "signin", outcome },
            actor: { kind: "account", name: upn },
            account: { name: upn },
            ...(ip ? { network: { source: { address: ip, provenance: "edge-observed" } } } : {}),
            time: {
              observed: pickStr(rec, ["createdDateTime"]),
              normalized: normalizeTime(pickStr(rec, ["createdDateTime"])),
            },
            evidence: { rawRecords: [{ source: "m365-signin", locator: `record:${index}` }] },
            producer: { importer: "m365", parserVersion: "1", mappingVersion: "m365-signin-v1" },
          }),
        }
      : {}),
  };
}

// Graph's directoryAudit.result is one of success | failure | timeout | unknownFutureValue, and a
// non-Graph export may spell success as succeeded/OK. Each Graph value is its own outcome — a
// timeout is not a failure — and only an absent or unrecognised value is "unknown".

// ───────────────────────────── top-level parse ─────────────────────────────

/** The upload read once (#2301): the normalized records parseM365Audit maps, in its order. */
export interface M365Records {
  normalized: Row[];
  repairs?: JsonRepairs;
  undated: UndatedRows;
}

export function extractM365Records(text: string): M365Records {
  // JSON (tolerant: BOM, `][`, trailing garbage) or CSV (Search-UnifiedAuditLog | Export-Csv) — #2302.
  const { records, repairs } = readCloudRecords(text);
  // Log Analytics and MES mailbox-audit columns are renamed into the shapes the mappers read (#2302).
  const adapted = adaptM365ExportRows(records);
  return { normalized: adapted.rows.map(normalizeRecord), repairs, undated: adapted.undated };
}

/** Each record's cloud identity (#2301), by the kind classify() reads it as. */
export function m365RecordIdentities(records: readonly Row[]): CloudRecordIdentity[] {
  return records.map((rec) => cloudRecordIdentity(m365RecordProvider(classify(rec), rec), rec));
}

export function parseM365Audit(text: string, opts: M365ImportOptions = {}): M365ParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { normalized, repairs, undated } = opts.prepared ?? extractM365Records(text);
  const total = normalized.length;
  if (total === 0) {
    return {
      events: [],
      iocs: [],
      total: 0,
      kept: 0,
      dropped: 0,
      groups: 0,
      format: "empty",
      coverage: [],
      sprayCandidates: [],
      signInObservations: [],
      repairs,
    };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let sawUal = false;
  let sawSignin = false;
  let sawAudit = false;

  // Object-id → app-id facts other records of this export state (entraAuditImport.ts): the only
  // way a consent record, which names its API by object id alone, can identify Microsoft Graph.
  const resolve = opts.resolver ?? learnApiResolver(normalized);
  // Coverage (#1063): normalized, since Workload/Operation/RecordType/OrganizationId can sit
  // inside the raw record's `AuditData` envelope until normalizeRecord unwraps it.
  const uploadId = sourceArtifactHash(text);
  const coverage: CloudCoverageDraft[] = m365Coverage(normalized).map((d) => ({ ...d, uploadId }));
  // Password-spray fan-out candidates (931.3 password-spray half, #1086, #1100 item 1): built
  // from `readEntraSignIn` — the same reader mailboxChain.ts's own sign-in join already trusts —
  // over every normalized sign-in record, BEFORE aggregateEvents folds one source's distinct
  // accounts into a single counted row. A candidate needs a real IP and a real tenant; a record
  // missing either is excluded from counting entirely, never merged into a shared bucket.
  const sprayCandidates: SprayCandidate[] = [];
  const signInObservations: M365ParseResult["signInObservations"] = [];
  const gate = opts.recordGate;
  const snapshot = opts.sigma;
  let sigmaRows = 0;
  const sigmaFor = (sourceId: string, rec: Row) => {
    const refs = sigmaMatchesFor(opts.sigma, sourceId, rec, (n) =>
      opts.debug?.observed("sigma_incomplete", n),
    );
    if (refs.length) sigmaRows++;
    return refs;
  };
  const indexBase = opts.recordIndexBase ?? 0;
  const rowRecords: number[] = [];
  normalized.forEach((rec, index) => {
    // A record the case already holds maps to nothing (#2301); its locator index is kept.
    if (isDuplicateRecord(gate, index)) return;
    const before = mapped.length;
    mapRecordInto(rec, index, indexBase + index);
    mapped.splice(before, mapped.length - before, ...gateRows(gate, index, mapped.slice(before)));
    while (rowRecords.length < mapped.length) rowRecords.push(index);
  });
  // `index` reads the batch's record gate; `at` is the record's place in the whole upload.
  function mapRecordInto(rec: Row, index: number, at: number): void {
    const kind = classify(rec);
    if (kind === "ual" && isEntraUalRecord(rec)) {
      // An Entra directory change exported through the UAL: the same decoder as the Graph shape.
      mapped.push(...mapEntraAuditRows(rec, iocSink, at, resolve, opSeverity));
      opts.debug?.fallback("entra_ual_decoder");
      sawUal = true;
    } else if (kind === "ual") {
      // An Exchange record the decoder narrates (rules, forwarding, permissions, access, items)
      // replaces the plain row; any other Exchange operation keeps it.
      const exchange = isExchangeRecord(rec) ? mapExchangeRow(rec, iocSink, at) : null;
      if (exchange) opts.debug?.fallback("exchange_decoder");
      mapped.push(exchange ?? mapUal(rec, iocSink, opts.debug));
      sawUal = true;
    } else if (kind === "signin") {
      const row = mapSignIn(rec, iocSink, at, opts.debug);
      mapped.push(snapshot ? applySigmaMatches(row, sigmaFor("azure-signinlogs", rec), snapshot) : row);
      sawSignin = true;
      if (isEntraSignIn(rec)) {
        const s = readEntraSignIn(rec);
        const hostOrTenant = s.resourceTenant || s.homeTenant;
        // Only a genuine credential failure counts as a spray attempt — an MFA interruption,
        // a Conditional Access block, an expired password, or an unreadable status is a
        // failure for OTHER reasons and must never inflate a spray count (Codex review, P1).
        // Reuses the same `signInOutcome` classification `mapSignIn` uses, so the two never
        // disagree about what "failed" means for the same record.
        const failureReason = pickStr(rec, ["status.failureReason", "status.additionalDetails"]);
        const { outcome } = signInOutcome(
          getPath(rec, "status.errorCode") ?? getCI(rec, "errorCode"),
          failureReason,
        );
        const sprayOutcome =
          outcome === "credential-failure" ? "failed" : outcome === "success" ? "success" : null;
        // The observation store keeps every sign-in, MFA interruptions included (#2301) — the
        // exclusion above guards the spray count only, and the store's spray reader filters too.
        if (s.user && hostOrTenant && s.observed) {
          const recordId = gate?.identities[index]?.key;
          signInObservations.push(
            signInObservation({
              rec,
              account: s.user,
              sourceIp: s.ip,
              tenant: hostOrTenant,
              observed: s.observed,
              locator: `record:${at}`,
              recordId,
              sprayOutcome,
            }),
          );
        }
        if (s.user && s.ip && hostOrTenant && s.observed && sprayOutcome) {
          sprayCandidates.push({
            timestamp: normalizeTime(s.observed),
            account: s.user,
            sourceIp: s.ip,
            hostOrTenant,
            outcome: sprayOutcome,
            locator: `record:${at}`,
          });
        }
      }
    } else if (kind === "spsignin") {
      mapped.push(mapSpSignIn(rec, iocSink, at));
      sawSignin = true;
    } else if (kind === "audit") {
      const rows = mapEntraAuditRows(rec, iocSink, at, resolve, opSeverity);
      mapped.push(
        ...(snapshot ? applySigmaToRecordRows(rows, sigmaFor("azure-auditlogs", rec), snapshot) : rows),
      );
      sawAudit = true;
    } else {
      // Not a UAL, sign-in or directory-audit record by its own fields: never mapped (#1736).
      opts.debug?.skipped("unrecognized_record");
    }
  }

  if (sigmaRows) opts.debug?.observed("sigma_match", sigmaRows);
  if (opts.rowsOnly)
    return {
      events: [],
      iocs: [...iocSink.values()].slice(0, maxIocs),
      total,
      kept: 0,
      dropped: 0,
      groups: 0,
      format: m365Format(sawUal, sawSignin, sawAudit),
      coverage,
      sprayCandidates,
      signInObservations,
      sigmaRowsMatched: sigmaRows,
      repairs,
      mapped,
      rowRecords,
      ...(undated.rows ? { undatedRows: undated } : {}),
    };
  const capped = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
    provenance: opts.provenance,
  });
  // Summaries read every NEW record (#2301): a duplicate is blanked in place, so a re-upload adds
  // no second summary and every `record:<index>` locator still points into the original upload.
  const fresh = gateRecords(gate, normalized);
  // The summaries built over every record of this export — the privilege path per application
  // (#973) and the mailbox chain per mailbox and session (#975) — are appended AFTER the cap,
  // each under its own bound: `maxEvents` bounds SOURCE rows, a summary never evicts one, and
  // `kept` / `dropped` / `groups` count source rows alone.
  const derived = (rows: MappedEvent[], bound: number): SiemEvent[] =>
    aggregateEvents(rows, { aggregate: opts.aggregate, minSeverity: opts.minSeverity, maxEvents: bound })
      .events;
  const summaries = [
    ...(sawAudit || sawUal
      ? [
          ...derived(entraPrivilegePaths(fresh, resolve), PRIVILEGE_PATHS_MAX + 1),
          ...(sawUal ? derived(mailboxChains(fresh), MAILBOX_CHAINS_MAX + 1) : []),
        ]
      : []),
    ...(sprayCandidates.length && opts.spraySummary !== false
      ? derived(
          sprayPatternRows(sprayCandidates, {
            source: "Microsoft 365",
            importer: "m365",
            mappingVersion: "m365-spray-v1",
          }),
          SPRAY_PATTERNS_MAX + 1,
        )
      : []),
  ];
  const events = [...capped.events, ...summaries];
  const groups = capped.groups;

  const represented = capped.events.reduce((n, e) => n + (e.count ?? 1), 0);
  const format = m365Format(sawUal, sawSignin, sawAudit);

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: capped.events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format,
    coverage,
    sprayCandidates,
    signInObservations,
    sigmaRowsMatched: sigmaRows,
    repairs,
    ...(undated.rows ? { undatedRows: undated } : {}),
  };
}

/** "m365-ual" | "entra-signin" | "entra-audit" | "mixed" | "empty", from the kinds a parse saw. */
export function m365Format(ual: boolean, signin: boolean, audit: boolean): string {
  const kinds = [ual ? "m365-ual" : "", signin ? "entra-signin" : "", audit ? "entra-audit" : ""].filter(
    Boolean,
  );
  return kinds.length > 1 ? "mixed" : (kinds[0] ?? "empty");
}
