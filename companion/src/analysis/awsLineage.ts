// AWS credential lineage (#931 item 5, chain half — #979): which later calls used the credential
// an issuance minted, from which sources, beside which shapes — built over the records of ONE
// CloudTrail upload inside the importer (the data-plane rows a credential is used for are Info
// and leave the forensic timeline at import; the importer aggregates them before any merge).
//
// What one row rests on, and what it never says:
//   - identity: the access key id (or the Identity Center credential id), never a session name or
//     a role's display name; the owning account is the target role's for AssumeRole*, the target
//     principal's for AssumeRoot, the caller's for a session or federation token;
//   - "issued at <t>" only on the exact key match with an issuance record whose response exposes
//     the key; otherwise "no issuance record in this upload exposes this credential id", and for a
//     workload key "delivered by the service; no STS record is expected";
//   - every source is named with its first use; "from a new source" is never said — the workload's
//     addresses are not in this evidence, and the row says so;
//   - the shapes are exact (eventSource, eventName) calls that succeeded; a denied call is an
//     attempt and raises nothing;
//   - every record is scanned (bounded accumulators); only the narrated evidence is capped, and
//     the row says how many records are not individually cited;
//   - absence rests on the upload's own record count and range, never on continuity.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { AwsLineageBlock, AwsLineageShape } from "./canonicalAwsLineage.js";
import {
  readAwsIdentity,
  readCredentialIssuance,
  type AwsIdentity,
  type CredentialIssuance,
} from "./awsIdentity.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { cleanIp, getCI, normalizeTime, str, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

export const AWS_LINEAGE_MAX = 256;
/** Sources tracked per key (the rest counted); locators cited per row; sources named in the words. */
export const SOURCES_PER_KEY_MAX = 64;
const RAW_RECORDS_MAX = 256;
const SOURCES_NAMED_MAX = 8;
const SHAPES_NAMED_MAX = 6;
/** Distinct sources past the tracked 64 that are still counted as distinct; further records count as untracked. */
const OVERFLOW_SOURCES_MAX = 1024;
/** Enumeration calls kept per key for the window scan — the earliest by time. */
const ENUMERATION_BUFFER_MAX = 512;
const CHAIN_MAX = 8;
const ENUMERATION_WINDOW_MS = 10 * 60_000;
const ENUMERATION_SERVICES_MIN = 3;
const NAME_MAX = 80;
const DESCRIPTION_MAX = 1400;
const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const COVERAGE_NOTE = "record retention and the trails' selectors are not in this evidence";
const ADDRESSES_NOTE = "the workload's own addresses are not in this evidence";

const show = (v: string, max = NAME_MAX): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
const lower = (s: string): string => s.trim().toLowerCase();
const ms = (iso: string): number | null => {
  const t = Date.parse(normalizeTime(iso));
  return Number.isFinite(t) ? t : null;
};
const iso = (t: number): string => new Date(t).toISOString();
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const accountOfArn = (arn: string): string => /^arn:[^:]*:[^:]*:[^:]*:(\d{12}):/.exec(arn)?.[1] ?? "";

// ───────────────────────────── the shapes: exact calls, success only ─────────────────────────────

const call = (source: string, ...names: string[]): string[] => names.map((n) => `${source}|${lower(n)}`);
const ENUMERATION = new Set([
  ...call(
    "ec2",
    "DescribeInstances",
    "DescribeSecurityGroups",
    "DescribeVpcs",
    "DescribeSnapshots",
    "DescribeImages",
    "DescribeVolumes",
  ),
  ...call(
    "iam",
    "ListUsers",
    "ListRoles",
    "ListAccessKeys",
    "ListPolicies",
    "GetAccountAuthorizationDetails",
    "ListAttachedUserPolicies",
    "ListAttachedRolePolicies",
  ),
  ...call("s3", "ListBuckets"),
  ...call("sts", "GetCallerIdentity"),
  ...call("secretsmanager", "ListSecrets"),
  ...call("ssm", "DescribeInstanceInformation", "DescribeParameters"),
  ...call("lambda", "ListFunctions"),
  ...call("organizations", "ListAccounts", "DescribeOrganization"),
  ...call("kms", "ListKeys", "ListAliases"),
  ...call("rds", "DescribeDBInstances"),
  ...call("dynamodb", "ListTables"),
]);
const PRIVILEGED_CHANGE = new Set([
  ...call(
    "iam",
    "CreateUser",
    "CreateAccessKey",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "UpdateAssumeRolePolicy",
    "CreateRole",
    "AddUserToGroup",
    "DeleteUser",
    "DeactivateMFADevice",
  ),
  ...call("kms", "PutKeyPolicy", "ScheduleKeyDeletion", "DisableKey", "CreateGrant"),
  ...call(
    "ec2",
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "CreateSecurityGroup",
    "ModifyInstanceAttribute",
  ),
  ...call("cloudtrail", "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"),
  ...call("organizations", "LeaveOrganization"),
  ...call("s3", "PutBucketPolicy", "PutBucketAcl"),
]);
// Invocation only: deploying code (CreateFunction, UpdateFunctionCode) is not execution of it.
const REMOTE_EXECUTION = new Set([
  ...call("ssm", "SendCommand", "StartSession"),
  ...call("lambda", "Invoke"),
  ...call("ec2-instance-connect", "SendSSHPublicKey"),
]);
const SHAPE_MITRE: Record<AwsLineageShape["kind"], string> = {
  enumeration: "T1580",
  "privileged-change": "T1098",
  "remote-execution": "T1651",
};

/** The service segment of an eventSource (`ec2.amazonaws.com` → `ec2`). */
export const serviceOf = (source: string): string => lower(source).replace(/\.amazonaws\.com.*$/, "");
/** The shape an exact (eventSource, eventName) call is, or null — shared with the compute lifecycle (awsCompute.ts). */
export function shapeOf(source: string, name: string): AwsLineageShape["kind"] | null {
  const k = `${serviceOf(source)}|${lower(name)}`;
  if (ENUMERATION.has(k)) return "enumeration";
  if (PRIVILEGED_CHANGE.has(k)) return "privileged-change";
  if (REMOTE_EXECUTION.has(k)) return "remote-execution";
  return null;
}

// ───────────────────────────── accumulators (bounded) ─────────────────────────────

interface Cited {
  time: number;
  locator: string;
}
interface Source {
  address: string;
  agent: string;
  first: Cited;
  records: number;
}
export interface ShapeHit {
  kind: AwsLineageShape["kind"];
  time: number;
  locator: string;
  call: string;
}
interface Key {
  account: string;
  credentialId: string;
  issuance: (AwsLineageBlock["issuance"] & { at: number }) | null;
  /** Issuance requests of the same role and session whose response was unavailable — listed, never joined. */
  unresolvedRequests: Cited[];
  workload: string;
  uses: number;
  first: Cited | null;
  last: Cited | null;
  locators: string[];
  /** The EARLIEST sources by first use — the second source is exact whatever the file order. */
  sources: Map<string, Source>;
  overflowSources: Set<string>;
  untrackedRecords: number;
  secondSourceAt: number | null;
  /** Enumeration calls, the earliest by time, bounded; the count of every one. */
  enumeration: ShapeHit[];
  enumerationCount: number;
  /** Per kind: the earliest shape, the earliest AFTER the second source (the decisive one), a few more for the words, the count. */
  shapes: Record<
    Exclude<AwsLineageShape["kind"], "enumeration">,
    { earliest: ShapeHit | null; decisive: ShapeHit | null; named: ShapeHit[]; count: number }
  >;
  attempts: number;
  serviceInvoked: number;
  sourceIdentity: string;
  issuerArn: string;
  sessionName: string;
  chained: AwsLineageBlock["chained"];
  top: Severity;
}

function keyFor(keys: Map<string, Key>, account: string, credentialId: string): Key {
  const id = `${lower(account)}|${lower(credentialId)}`;
  return (
    keys.get(id) ??
    keys
      .set(id, {
        account: lower(account),
        credentialId,
        issuance: null,
        unresolvedRequests: [],
        workload: "",
        uses: 0,
        first: null,
        last: null,
        locators: [],
        sources: new Map(),
        overflowSources: new Set(),
        untrackedRecords: 0,
        secondSourceAt: null,
        enumeration: [],
        enumerationCount: 0,
        shapes: {
          "privileged-change": { earliest: null, decisive: null, named: [], count: 0 },
          "remote-execution": { earliest: null, decisive: null, named: [], count: 0 },
        },
        attempts: 0,
        serviceInvoked: 0,
        sourceIdentity: "",
        issuerArn: "",
        sessionName: "",
        chained: [],
        top: "Info",
      })
      .get(id)!
  );
}

/** The account that owns the credential an issuance minted (design round finding 1). */
function owningAccount(issuance: CredentialIssuance, caller: string): string {
  if (issuance.action === "AssumeRoot") {
    const t = issuance.targetPrincipal.trim();
    return accountOfArn(t) || (/^\d{12}$/.test(t) ? t : caller);
  }
  if (issuance.role?.arn) return accountOfArn(issuance.role.arn) || caller;
  return caller;
}

function workloadOf(who: AwsIdentity): string {
  if (who.session.ec2RoleDelivery) return "EC2 instance role";
  const t = who.inScopeOf?.issuerType ?? "";
  if (/lambda/i.test(t)) return "Lambda function";
  if (/ecs/i.test(t)) return "ECS task";
  return "";
}

/** Keep the EARLIEST sources by first use: a later-arriving earlier source evicts the latest tracked one. */
function trackSource(
  k: Key,
  sk: string,
  address: string,
  agent: string,
  time: number,
  locator: string,
): void {
  const src = k.sources.get(sk);
  if (src) {
    src.records += 1;
    if (time < src.first.time) src.first = { time, locator };
    return;
  }
  if (k.sources.size < SOURCES_PER_KEY_MAX) {
    k.sources.set(sk, { address, agent, first: { time, locator }, records: 1 });
    return;
  }
  let latest: [string, Source] | null = null;
  for (const e of k.sources) if (!latest || e[1].first.time > latest[1].first.time) latest = e;
  if (latest && time < latest[1].first.time) {
    k.sources.delete(latest[0]);
    k.overflowSources.add(latest[0]);
    k.sources.set(sk, { address, agent, first: { time, locator }, records: 1 });
    return;
  }
  if (k.overflowSources.size < OVERFLOW_SOURCES_MAX) k.overflowSources.add(sk);
  else k.untrackedRecords += 1;
}

/** Insert an enumeration call into a bounded earliest-by-time buffer (shared with awsCompute.ts). */
export function trackEnumerationInto(buf: ShapeHit[], hit: ShapeHit): void {
  if (buf.length >= ENUMERATION_BUFFER_MAX && hit.time >= buf[buf.length - 1].time) return;
  let i = buf.length;
  while (i > 0 && buf[i - 1].time > hit.time) i -= 1;
  buf.splice(i, 0, hit);
  if (buf.length > ENUMERATION_BUFFER_MAX) buf.pop();
}
function trackEnumeration(k: Key, hit: ShapeHit): void {
  k.enumerationCount += 1;
  trackEnumerationInto(k.enumeration, hit);
}

/** Pass 1: counts, bounds, sources, provenance; the shapes wait for the second source's time. */
function recordUse(
  k: Key,
  rec: Row,
  who: AwsIdentity,
  time: number,
  locator: string,
  severity: Severity,
): void {
  k.uses += 1;
  if (!k.first || time < k.first.time) k.first = { time, locator };
  if (!k.last || time > k.last.time) k.last = { time, locator };
  if (k.locators.length < RAW_RECORDS_MAX) k.locators.push(locator);
  if (RANK[severity] > RANK[k.top]) k.top = severity;
  // AWS CloudTrail's own field, recorded by AWS's own control-plane infrastructure at call time —
  // edge-observed, not client-asserted (#1184 audit).
  const address = cleanIp(str(getCI(rec, "sourceIPAddress"))) || str(getCI(rec, "sourceIPAddress")).trim();
  const agent = str(getCI(rec, "userAgent")).trim();
  trackSource(k, `${address}|${agent}`, address, agent, time, locator);
  if (!k.workload) k.workload = workloadOf(who);
  if (!k.sourceIdentity && who.session.sourceIdentity) k.sourceIdentity = who.session.sourceIdentity;
  if (!k.issuerArn && who.issuer?.arn) k.issuerArn = who.issuer.arn;
  if (!k.sessionName && who.session.name) k.sessionName = who.session.name;
  if (who.invokedBy) k.serviceInvoked += 1;
}

/** Pass 2: the shapes, judged against the second source's time known from pass 1. */
function recordShape(k: Key, rec: Row, time: number, locator: string): void {
  const source = str(getCI(rec, "eventSource"));
  const name = str(getCI(rec, "eventName"));
  const kind = shapeOf(source, name);
  if (!kind) return;
  if (str(getCI(rec, "errorCode")).trim()) {
    k.attempts += 1;
    return;
  }
  const hit: ShapeHit = { kind, time, locator, call: `${serviceOf(source)} ${name}` };
  if (kind === "enumeration") {
    trackEnumeration(k, hit);
    return;
  }
  const slot = k.shapes[kind];
  slot.count += 1;
  if (!slot.earliest || time < slot.earliest.time) slot.earliest = hit;
  if (k.secondSourceAt !== null && time > k.secondSourceAt && (!slot.decisive || time < slot.decisive.time))
    slot.decisive = hit;
  if (slot.named.length < SHAPES_NAMED_MAX) slot.named.push(hit);
}

/** Enumeration is a shape only across ≥ 3 services inside 10 minutes; the first such window is cited (shared with awsCompute.ts). */
export function enumerationWindow(calls: readonly ShapeHit[]): ShapeHit | null {
  for (let i = 0; i < calls.length; i += 1) {
    const services = new Set<string>();
    for (let j = i; j < calls.length && calls[j].time - calls[i].time <= ENUMERATION_WINDOW_MS; j += 1) {
      services.add(calls[j].call.split(" ")[0]);
      if (services.size >= ENUMERATION_SERVICES_MIN)
        return {
          kind: "enumeration",
          time: calls[i].time,
          locator: calls[i].locator,
          call: `${[...services].join(", ")} within 10 min (${calls[i].call} first)`,
        };
    }
  }
  return null;
}
const enumerationShape = (k: Key): ShapeHit | null => enumerationWindow(k.enumeration);

// ───────────────────────────── the pass ─────────────────────────────

interface Scanned {
  rec: Row;
  index: number;
  time: number;
  who: AwsIdentity;
}

/**
 * One record per cross-account action: the replicas sharing a `sharedEventID` are grouped first
 * and the informative one (a named principal, not an account or service view) is read, whichever
 * the file lists first (code round finding 1).
 */
function scan(records: readonly Row[]): Scanned[] {
  const chosen = new Map<string, Scanned>();
  const order: string[] = [];
  records.forEach((rec, index) => {
    if (!str(getCI(rec, "eventName")) || !str(getCI(rec, "eventSource"))) return;
    const time = ms(str(getCI(rec, "eventTime")));
    if (time === null) return;
    const who = readAwsIdentity(rec);
    const replica = str(getCI(rec, "sharedEventID")).trim();
    const own = str(getCI(rec, "eventID")).trim();
    const id = replica ? `shared:${replica}` : own ? `event:${own}` : `record:${index}`;
    const cur = chosen.get(id);
    const informative = !["AWSAccount", "AWSService", "Unknown"].includes(who.kind);
    if (!cur) {
      chosen.set(id, { rec, index, time, who });
      order.push(id);
    } else if (informative && ["AWSAccount", "AWSService", "Unknown"].includes(cur.who.kind))
      chosen.set(id, { rec, index, time, who });
  });
  return order.map((id) => chosen.get(id)!);
}

/** One summary row per credential whose upload records form a lineage; the rows say what they rest on. */
export function awsLineages(records: readonly Row[]): MappedEvent[] {
  const keys = new Map<string, Key>();
  const coverage = { records: 0, first: "", last: "" };
  // Issuance requests whose response was unavailable, by (role arn, session name) — listed beside
  // a key whose uses name that role and session, never joined (design round finding 6).
  const unresolved = new Map<string, Cited[]>();
  const scanned = scan(records);
  // Pass 1: issuances, uses, sources, chaining.
  for (const { rec, index, time, who } of scanned) {
    const t = normalizeTime(str(getCI(rec, "eventTime")));
    coverage.records += 1;
    if (!coverage.first || t < coverage.first) coverage.first = t;
    if (!coverage.last || t > coverage.last) coverage.last = t;
    const locator = `record:${index}`;
    const caller = who.accounts.caller;
    const errorCode = str(getCI(rec, "errorCode")).trim();
    const severity: Severity = errorCode ? "Medium" : "Info";
    const issuance = readCredentialIssuance(
      str(getCI(rec, "eventName")),
      getCI(rec, "requestParameters"),
      getCI(rec, "responseElements"),
      errorCode,
      rec,
      index,
    );
    if (issuance) {
      if (issuance.result === "issued" && issuance.issuedKey) {
        const k = keyFor(keys, owningAccount(issuance, caller), issuance.issuedKey);
        if (!k.issuance || time < k.issuance.at)
          k.issuance = {
            at: time,
            action: issuance.action,
            time: iso(time),
            locator,
            ...(issuance.role?.arn ? { role: issuance.role.arn } : {}),
            ...(issuance.sessionName ? { sessionName: issuance.sessionName } : {}),
            ...(issuance.sourceIdentity ? { sourceIdentity: issuance.sourceIdentity } : {}),
            ...(issuance.mfaSerial ? { mfa: issuance.mfaSerial } : {}),
            by: `${who.kind}${who.arn ? ` ${who.arn}` : ""}`,
          };
        // Chaining: the key that signed this issuance issued the new one.
        const signer = who.credential.accessKeyId;
        if (signer && lower(signer) !== lower(issuance.issuedKey)) {
          const parent = keyFor(keys, caller, signer);
          if (parent.chained.length < CHAIN_MAX)
            parent.chained.push({ credentialId: issuance.issuedKey, direction: "issued", locator });
          if (k.chained.length < CHAIN_MAX)
            k.chained.push({ credentialId: signer, direction: "issued-from", locator });
        }
      } else if (issuance.result === "unknown" && issuance.role?.arn) {
        const rk = `${lower(issuance.role.arn)}|${lower(issuance.sessionName)}`;
        (unresolved.get(rk) ?? unresolved.set(rk, []).get(rk)!).push({ time, locator });
      }
    }
    // The use: every record signed with a key — the issuance call itself is a use of ITS signer.
    const signer = who.credential.accessKeyId || who.credential.credentialId;
    if (!signer || !caller) continue;
    recordUse(keyFor(keys, caller, signer), rec, who, time, locator, severity);
  }
  for (const k of keys.values()) {
    const sorted = [...k.sources.values()].sort((a, b) => a.first.time - b.first.time);
    if (sorted.length >= 2) k.secondSourceAt = sorted[1].first.time;
    if (k.issuerArn && k.sessionName) {
      const rk = `${lower(k.issuerArn.replace(/:sts::/, ":iam::").replace(/assumed-role\/([^/]+)\/.*$/, "role/$1"))}|${lower(k.sessionName)}`;
      k.unresolvedRequests = unresolved.get(rk) ?? [];
    }
  }
  // Pass 2: the shapes, each judged against its key's second source.
  for (const { rec, index, time, who } of scanned) {
    const signer = who.credential.accessKeyId || who.credential.credentialId;
    const caller = who.accounts.caller;
    if (!signer || !caller) continue;
    const k = keys.get(`${lower(caller)}|${lower(signer)}`);
    if (k) recordShape(k, rec, time, `record:${index}`);
  }
  // A row when the upload holds the issuance AND a use, or two sources, or a shape.
  const findings = [...keys.values()]
    .map((k) => ({ k, shapes: shapesOf(k) }))
    .filter(({ k, shapes }) => k.uses > 0 && (k.issuance || k.sources.size >= 2 || shapes.length > 0))
    .map((f) => ({ ...f, grade: gradeOf(f.k, f.shapes) }))
    .sort(
      (a, b) =>
        RANK[b.grade] - RANK[a.grade] ||
        b.k.sources.size - a.k.sources.size ||
        (b.k.first?.time ?? 0) - (a.k.first?.time ?? 0) ||
        a.k.credentialId.localeCompare(b.k.credentialId),
    );
  const rows = findings.slice(0, AWS_LINEAGE_MAX).map((f) => summaryRow(f.k, f.shapes, f.grade, coverage));
  if (findings.length > AWS_LINEAGE_MAX)
    rows.push(omittedRow(findings.length - AWS_LINEAGE_MAX, findings[AWS_LINEAGE_MAX].grade));
  return rows;
}

/** The shapes the row carries: the decisive one first (after the second source), then the earliest, then the named — bounded, deduplicated. */
function shapesOf(k: Key): AwsLineageShape[] {
  const after = (t: number): boolean => k.secondSourceAt !== null && t > k.secondSourceAt;
  const out: ShapeHit[] = [];
  const seen = new Set<string>();
  const push = (h: ShapeHit | null) => {
    if (h && !seen.has(h.locator)) {
      seen.add(h.locator);
      out.push(h);
    }
  };
  for (const kind of ["privileged-change", "remote-execution"] as const) push(k.shapes[kind].decisive);
  for (const kind of ["privileged-change", "remote-execution"] as const) push(k.shapes[kind].earliest);
  push(enumerationShape(k));
  for (const kind of ["privileged-change", "remote-execution"] as const)
    for (const h of k.shapes[kind].named) push(h);
  return out.slice(0, SHAPES_NAMED_MAX).map((h) => ({
    kind: h.kind,
    time: iso(h.time),
    locator: h.locator,
    call: h.call,
    afterSecondSource: after(h.time),
  }));
}

/** High: a privileged change or remote execution after the first use from a second source; Medium: a shape or a second source; Low: a lineage. Never below the top use row. */
function gradeOf(k: Key, shapes: readonly AwsLineageShape[]): Severity {
  const high = shapes.some((s) => s.afterSecondSource && s.kind !== "enumeration");
  const floor: Severity = high ? "High" : shapes.length || k.sources.size >= 2 ? "Medium" : "Low";
  return RANK[k.top] > RANK[floor] ? k.top : floor;
}

// ───────────────────────────── the row ─────────────────────────────

function summaryRow(
  k: Key,
  shapes: readonly AwsLineageShape[],
  grade: Severity,
  coverage: { records: number; first: string; last: string },
): MappedEvent {
  const sources = [...k.sources.values()].sort((a, b) => a.first.time - b.first.time);
  const range = `(${coverage.records} records, ${coverage.first.slice(0, 19)} → ${coverage.last.slice(0, 19)})`;
  const issuanceWords = k.issuance
    ? `issued ${k.issuance.time} by ${k.issuance.action}${k.issuance.role ? ` of ${show(k.issuance.role)}` : ""}${k.issuance.sessionName ? ` as session ${show(k.issuance.sessionName, 40)}` : ""}${k.issuance.by ? ` by ${show(k.issuance.by)}` : ""}${k.issuance.mfa ? ` (MFA device ${show(k.issuance.mfa, 40)})` : " (MFA not recorded on the issuance)"}${k.issuance.sourceIdentity ? `; stated human identity ${show(k.issuance.sourceIdentity, 40)}` : ""} — ${k.issuance.locator}`
    : k.workload
      ? `delivered by the service to the ${k.workload}; no STS record is expected`
      : `no issuance record in this upload exposes this credential id ${range}`;
  const unresolvedWords = k.unresolvedRequests.length
    ? [
        `${plural(k.unresolvedRequests.length, "issuance request")} for this role and session ${k.unresolvedRequests
          .slice(0, 3)
          .map((u) => `at ${iso(u.time)} (${u.locator})`)
          .join(
            ", ",
          )} ${k.unresolvedRequests.length === 1 ? "has" : "have"} no response in the record — not joined`,
      ]
    : [];
  const sourceWords = sources
    .slice(0, SOURCES_NAMED_MAX)
    .map(
      (s) =>
        `${show(s.address, 45) || "(no address)"}${s.agent ? ` ${show(s.agent, 40)}` : ""} at ${iso(s.first.time)} (${s.first.locator}, ${plural(s.records, "record")})`,
    );
  const beyondSources = sources.length - Math.min(sources.length, SOURCES_NAMED_MAX) + k.overflowSources.size;
  const shapeLine = (s: AwsLineageShape) =>
    `${s.kind === "privileged-change" ? "privileged change" : s.kind === "remote-execution" ? "remote execution" : "enumeration"}: ${show(s.call, 120)} at ${s.time} (${s.locator})${s.afterSecondSource ? " — after the second source" : ""}`;
  // The decisive shape — the one the grade rests on — is packed with the tail, never clipped.
  const decisive = shapes.find((s) => s.afterSecondSource && s.kind !== "enumeration");
  const shapeCount =
    k.shapes["privileged-change"].count +
    k.shapes["remote-execution"].count +
    (shapes.some((s) => s.kind === "enumeration") ? 1 : 0);
  const parts = [
    issuanceWords,
    ...unresolvedWords,
    `uses: ${plural(k.uses, "record")} ${iso(k.first!.time)} (${k.first!.locator}) → ${iso(k.last!.time)} (${k.last!.locator})`,
    `first use from each source: ${sourceWords.join("; ")}${beyondSources ? `; +${plural(beyondSources, "more source")}` : ""}${k.untrackedRecords ? `; ${plural(k.untrackedRecords, "record")} from untracked sources` : ""}`,
    ...(k.secondSourceAt !== null
      ? [
          `second source ${Math.round((k.secondSourceAt - (k.issuance?.at ?? k.first!.time)) / 60_000)} min after ${k.issuance ? "the issuance" : "the first use"}; ${ADDRESSES_NOTE}`,
        ]
      : k.workload
        ? [ADDRESSES_NOTE]
        : []),
    ...shapes.filter((s) => s !== decisive).map(shapeLine),
    ...(shapeCount > shapes.length ? [`+${shapeCount - shapes.length} more shape records`] : []),
    ...(k.enumerationCount > k.enumeration.length
      ? [`${k.enumerationCount - k.enumeration.length} enumeration calls beyond the scanned buffer`]
      : []),
    ...(k.attempts ? [`attempts: ${plural(k.attempts, "denied call")} of these shapes — not counted`] : []),
    ...(k.serviceInvoked
      ? [`${plural(k.serviceInvoked, "record")} made by an AWS service on the caller's behalf`]
      : []),
    ...(k.sourceIdentity && !k.issuance?.sourceIdentity
      ? [`stated human identity ${show(k.sourceIdentity, 40)}`]
      : []),
    ...k.chained
      .slice(0, CHAIN_MAX)
      .map((c) =>
        c.direction === "issued"
          ? `chained: issued ${show(c.credentialId, 30)} (${c.locator})`
          : `issued from a session of ${show(c.credentialId, 30)} (${c.locator})`,
      ),
  ];
  // One deduplicated evidence list: the issuance, the bounds, the decisive shape, then every other
  // contributing record up to the cap; `notCited` is what that list leaves out.
  const reserved = [
    ...(k.issuance ? [k.issuance.locator] : []),
    k.first!.locator,
    k.last!.locator,
    ...(decisive ? [decisive.locator] : []),
  ];
  const cited = [...new Set([...reserved, ...k.locators])].slice(0, RAW_RECORDS_MAX);
  const notCited = Math.max(0, k.uses + (k.issuance ? 1 : 0) - cited.length);
  const tail = [
    ...(decisive ? [shapeLine(decisive)] : []),
    ...(notCited ? [`${plural(notCited, "further record")} not individually cited`] : []),
    COVERAGE_NOTE,
    k.workload
      ? `workload key (${k.workload})`
      : k.issuance
        ? `issuance and ${plural(k.uses, "use")} in this upload`
        : `${plural(k.uses, "use")}, issuance not in this upload`,
  ].join("; ");
  const head = `AWS credential lineage: ${show(k.credentialId, 40)}${k.account ? ` (account ${show(k.account, 12)})` : ""}`;
  const room = DESCRIPTION_MAX - head.length - tail.length - 6;
  const lead = parts.join("; ");
  const description = `${head} [${lead.length > room ? `${lead.slice(0, Math.max(0, room - 1))}…` : lead}; ${tail}]`;
  const identity = createHash("sha256")
    .update(`${k.account.length}:${k.account}|${k.credentialId.length}:${k.credentialId}`)
    .digest("hex")
    .slice(0, 32);
  const block: AwsLineageBlock = {
    credentialId: k.credentialId,
    ...(k.account ? { account: k.account } : {}),
    ...(k.issuance ? { issuance: (({ at: _at, ...rest }) => rest)(k.issuance) } : {}),
    workload: k.workload,
    uses: {
      records: k.uses,
      first: { time: iso(k.first!.time), locator: k.first!.locator },
      last: { time: iso(k.last!.time), locator: k.last!.locator },
    },
    sources: sources.map((s) => ({
      address: s.address,
      agent: s.agent,
      firstUse: { time: iso(s.first.time), locator: s.first.locator },
      records: s.records,
    })),
    sourcesBeyond: k.overflowSources.size,
    shapes: [...shapes],
    attempts: k.attempts,
    chained: k.chained,
    notCited,
    coverage,
    basis:
      "records of this upload only; joined through the access key id; the workload's addresses are not in this evidence",
  };
  const observed = k.issuance?.time ?? iso(k.first!.time);
  return {
    timestamp: normalizeTime(observed),
    description,
    severity: grade,
    mitre: grade === "Low" ? [] : [...new Set(shapes.map((s) => SHAPE_MITRE[s.kind]))],
    aggKey: boundedAggKey(`aws-credential-lineage|${identity}`),
    sources: ["AWS CloudTrail"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "credential-lineage", action: "lineage", outcome: "success" },
      actor: { kind: "account", name: k.issuerArn || k.credentialId },
      ...(sources[0]?.address
        ? { network: { source: { address: sources[0].address, provenance: "edge-observed" } } }
        : {}),
      authentication: { credentialId: k.credentialId, ...(k.issuerArn ? { issuer: k.issuerArn } : {}) },
      cloud: { provider: "aws", ...(k.account ? { accountId: k.account } : {}) },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: { rawRecords: cited.map((l) => ({ source: "cloudtrail", locator: l })) },
      producer: {
        importer: "aws-cloudtrail",
        parserVersion: "1",
        mappingVersion: "aws-credential-lineage-v1",
        ruleVersions: ["aws-lineage-v1"],
      },
      awsLineage: block,
    }),
  };
}

function omittedRow(count: number, severity: Severity): MappedEvent {
  const description = `AWS credential lineage: ${count} further credential${count === 1 ? "" : "s"} with a lineage in this upload beyond the ${AWS_LINEAGE_MAX} reported — not shown`;
  return {
    timestamp: "",
    description,
    severity,
    mitre: [],
    aggKey: boundedAggKey(`aws-credential-lineage|omitted|${count}`),
    sources: ["AWS CloudTrail"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "credential-lineage", action: "omitted" },
      cloud: { provider: "aws" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "cloudtrail", locator: "omitted" }] },
      producer: {
        importer: "aws-cloudtrail",
        parserVersion: "1",
        mappingVersion: "aws-credential-lineage-v1",
      },
    }),
  };
}
