// GCP per-service-account join (#931 item 12, second half — #1065): every fact ONE export states
// about one service account, joined by unique id when the export ever states one for an email,
// email otherwise — built over the export's un-aggregated records, the `gwsOAuthLifecycle.ts` /
// `gwsDriveExposure.ts` pattern (a summary row per resource, joined by an identity).
//
// What one row rests on, and what it never says:
//   - a row exists only when this account is named DIRECTLY by a binding, a credential, a key, an
//     attachment, or a call authenticated as it — never by a parent-scope binding alone;
//   - access-to-member, authority-over-service-account and parent-scope are three separate facts,
//     never merged; a parent-scope binding is counted ONLY on this account's own project (exact
//     id/number match) and NEVER on a folder or organization — ancestry is not derivable from an
//     email or a project id, so a folder/org delta is excluded from this join entirely and can
//     never create a row by itself;
//   - alias folding follows `gwsOAuthLifecycle.ts`'s own rule: an email that maps to exactly one
//     uniqueId anywhere in the export folds under it; an email seen with two different uniqueIds
//     is a conflict and is never resolved — every record naming only that email keys on the email
//     string itself;
//   - the grade is the highest severity already computed for any admitted fact (never a call that
//     produced none); it is upgraded to at least High for exactly one pattern — a non-denied
//     control-granting binding over this account followed by a non-denied credential mint, key
//     creation or authenticated call at a strictly later, parseable time — never for two facts of
//     one category, never on a tie or a missing time;
//   - every SA named directly is fully accumulated (bounded per-category) before the export's rows
//     are ranked and sliced to the bound, so the kept set never depends on record order;
//   - no effective permission is ever evaluated or claimed.

import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { GcpProjectRef } from "./canonicalGcp.js";
import type { GcpServiceAccountJoinBlock } from "./canonicalGcpServiceAccountJoin.js";
import {
  field,
  lower,
  principalOf,
  projectRefOf,
  readDelegation,
  readPrincipal,
  show,
} from "./gcpIdentity.js";
import { decodeGcpAction } from "./gcpIamRecord.js";
import { matchGcpRule } from "./gcpSeverityRules.js";
import { getCI, isObject, normalizeTime, str, worst, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

export const GCP_SA_JOIN_MAX = 4096;
// Every fact is accumulated in full (grading and the control-then-use upgrade must see every
// admitted fact, or the kept set and the grade would depend on which facts happened to arrive
// before a cap — the #1064 lesson, applied here from the start). These bound only how many facts
// are SHOWN in the row's words and envelope; the rest are counted (`…Beyond`), never dropped from
// grading.
const BINDINGS_SHOWN_MAX = 1024;
const CREDENTIALS_SHOWN_MAX = 1024;
const KEYS_SHOWN_MAX = 512;
const ATTACHMENTS_SHOWN_MAX = 512;
const CALLS_SHOWN_MAX = 4096;
const DESCRIPTION_MAX = 1600;
const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const CONTROL_ROLES = new Set([
  "roles/iam.serviceaccounttokencreator",
  "roles/iam.serviceaccountkeyadmin",
  "roles/iam.serviceaccountadmin",
  "roles/iam.workloadidentityuser",
]);
const UNIQUE_ID = /^\d{15,25}$/;
const BASIS =
  "records of this export only; joined by unique id when present, else email; no effective permission is evaluated; a parent-scope binding is counted on this account's own project only, never attributed";

const iso = (t: number): string => new Date(t).toISOString();
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const refKey = (r: GcpProjectRef): string => `${r.namespace}/${r.kind}/${lower(r.value)}`;

// ───────────────────────────── the raw record → pp/method/service ─────────────────────────────

function gcpPayload(rec: Row): { pp: Row; method: string; service: string } | null {
  const pp = isObject(getCI(rec, "protoPayload"))
    ? (getCI(rec, "protoPayload") as Row)
    : isObject(getCI(rec, "jsonPayload"))
      ? (getCI(rec, "jsonPayload") as Row)
      : null;
  if (!pp) return null;
  const method = str(getCI(pp, "methodName")).trim();
  const service = str(getCI(pp, "serviceName")).trim();
  if (!method) return null;
  return { pp, method, service };
}

// ───────────────────────────── alias learning (gwsOAuthLifecycle's own rule) ─────────────────────────────

function learnAliases(pairs: readonly { email: string; uniqueId: string }[]): (email: string) => string {
  const byEmail = new Map<string, string>();
  const conflicts = new Set<string>();
  for (const { email, uniqueId } of pairs) {
    if (!email || !uniqueId) continue;
    const e = lower(email);
    const prev = byEmail.get(e);
    if (prev && prev !== uniqueId) conflicts.add(e);
    else byEmail.set(e, uniqueId);
  }
  return (email: string): string => {
    const e = lower(email);
    return conflicts.has(e) ? e : (byEmail.get(e) ?? e);
  };
}

// ───────────────────────────── the accumulator ─────────────────────────────

// Working shapes carry `time` as an epoch number for comparison, and the severity/mitre/denied
// facts grading needs — every one is admitted in full (see the bound comment above); each
// converts to the schema's ISO string, and is sliced to its shown bound, only when the row is built.
interface WorkingBindingFact {
  time: number;
  locator: string;
  role: string;
  member?: string;
  resource: string;
  action: string;
  denied: boolean;
  severity: Severity;
  mitre: string[];
}
interface WorkingCredentialFact {
  time: number;
  locator: string;
  fact: string;
  denied: boolean;
  severity: Severity;
}
interface WorkingKeyFact {
  time: number;
  locator: string;
  action: string;
  denied: boolean;
  severity: Severity;
}
interface WorkingAttachmentFact {
  time: number;
  locator: string;
  workloadKind: string;
  workloadVersion?: string;
  workloadName?: string;
  identityRole: string;
  severity: Severity;
}
interface WorkingCallFact {
  time: number;
  locator: string;
  keyName?: string;
  delegation: string[];
  denied: boolean;
  severity: Severity;
}
const toIso = <T extends { time: number }>(f: T): Omit<T, "time"> & { time: string } => ({
  ...f,
  time: iso(f.time),
});
/** Slice to the shown bound; the rest are counted, never dropped from the facts already graded. */
const shown = <T>(facts: readonly T[], max: number): { kept: T[]; beyond: number } => ({
  kept: facts.slice(0, max),
  beyond: Math.max(0, facts.length - max),
});

interface SaAgg {
  emails: Set<string>;
  uniqueIds: Set<string>;
  bindingsAsMember: WorkingBindingFact[];
  bindingsAsResource: WorkingBindingFact[];
  credentials: WorkingCredentialFact[];
  keys: WorkingKeyFact[];
  attachments: WorkingAttachmentFact[];
  callsAsPrincipal: WorkingCallFact[];
  projectsTouched: Map<string, GcpProjectRef>;
}

function newAgg(): SaAgg {
  return {
    emails: new Set(),
    uniqueIds: new Set(),
    bindingsAsMember: [],
    bindingsAsResource: [],
    credentials: [],
    keys: [],
    attachments: [],
    callsAsPrincipal: [],
    projectsTouched: new Map(),
  };
}

function aggFor(aggs: Map<string, SaAgg>, identity: string): SaAgg {
  return aggs.get(identity) ?? aggs.set(identity, newAgg()).get(identity)!;
}

function touchProjects(agg: SaAgg, ...refs: (GcpProjectRef | undefined)[]): void {
  for (const r of refs) if (r) agg.projectsTouched.set(refKey(r), r);
}

/** One export's per-service-account join rows. */
export function gcpServiceAccountJoins(records: readonly Row[]): MappedEvent[] {
  const coverage = { records: 0, first: "", last: "" };
  const aliasPairs: { email: string; uniqueId: string }[] = [];
  const scanned: { pp: Row; rec: Row; method: string; service: string; time: number; locator: string }[] = [];

  records.forEach((rec, i) => {
    if (!isObject(rec)) return;
    const g = gcpPayload(rec);
    if (!g) return;
    coverage.records += 1;
    // Alias source 1: a `service_account`-typed LogEntry names both the email and the unique id —
    // learned from EVERY such record, whether or not this record's own time parses (the alias is
    // a fact about the address, not about this record's placement in time).
    const emailId = field(rec, "resource", "labels", "email_id");
    const uniqueId = field(rec, "resource", "labels", "unique_id");
    if (emailId && uniqueId) aliasPairs.push({ email: emailId, uniqueId });
    const observed = str(getCI(rec, "timestamp")) || str(getCI(rec, "receiveTimestamp"));
    const t = normalizeTime(observed);
    if (!coverage.first || t < coverage.first) coverage.first = t;
    if (!coverage.last || t > coverage.last) coverage.last = t;
    const time = Date.parse(t);
    if (!Number.isFinite(time)) return;
    scanned.push({ pp: g.pp, rec, method: g.method, service: g.service, time, locator: `record:${i}` });
  });

  // Pass 1: decode every record once (reusing gcpIamRecord.ts's own readings — never re-derived),
  // and collect alias source 2: a credential/key reading naming both email and uniqueId together.
  const decoded = scanned.map((s) => ({ ...s, readings: decodeGcpAction(s.pp, s.rec, s.method, s.service) }));
  for (const d of decoded)
    for (const r of d.readings)
      if (r.serviceAccount?.email && r.serviceAccount?.uniqueId)
        aliasPairs.push({ email: r.serviceAccount.email, uniqueId: r.serviceAccount.uniqueId });
  const resolveEmail = learnAliases(aliasPairs);
  const identityOf = (email?: string, uniqueId?: string): string => {
    if (uniqueId && UNIQUE_ID.test(uniqueId)) return uniqueId;
    if (email) return resolveEmail(email);
    return "";
  };

  const aggs = new Map<string, SaAgg>();
  const parentScopeByProject = new Map<string, number>();

  // Pass 2: attribute every reading and every "authenticated as this SA" call. Every fact is
  // admitted in full here — bounding happens only when the row's words/envelope are built.
  for (const d of decoded) {
    for (const r of d.readings) {
      if (r.kind === "binding" && r.binding) {
        const b = r.binding;
        if (b.direction === "authority-over-service-account" && r.serviceAccount) {
          const identity = identityOf(r.serviceAccount.email, r.serviceAccount.uniqueId);
          if (!identity) continue;
          const agg = aggFor(aggs, identity);
          if (r.serviceAccount.email) agg.emails.add(lower(r.serviceAccount.email));
          if (r.serviceAccount.uniqueId) agg.uniqueIds.add(r.serviceAccount.uniqueId);
          agg.bindingsAsResource.push({
            time: d.time,
            locator: d.locator,
            role: b.role,
            member: b.member,
            resource: b.resource,
            action: b.action,
            denied: b.denied,
            severity: r.severity,
            mitre: r.mitre,
          });
        } else if (b.direction === "access-to-member" && b.memberKind === "service-account") {
          const email = b.member.replace(/^serviceAccount:/i, "");
          const identity = identityOf(email, undefined);
          if (!identity) continue;
          const agg = aggFor(aggs, identity);
          agg.emails.add(lower(email));
          agg.bindingsAsMember.push({
            time: d.time,
            locator: d.locator,
            role: b.role,
            member: b.member,
            resource: b.resource,
            action: b.action,
            denied: b.denied,
            severity: r.severity,
            mitre: r.mitre,
          });
        } else if (b.direction === "parent-scope" && b.resourceKind === "project") {
          const ref = projectRefOf(b.resource);
          if (ref) parentScopeByProject.set(refKey(ref), (parentScopeByProject.get(refKey(ref)) ?? 0) + 1);
        }
      } else if (r.kind === "credential" && r.credential) {
        const identity = identityOf(r.serviceAccount?.email, r.serviceAccount?.uniqueId);
        if (!identity) continue;
        const agg = aggFor(aggs, identity);
        if (r.serviceAccount?.email) agg.emails.add(lower(r.serviceAccount.email));
        if (r.serviceAccount?.uniqueId) agg.uniqueIds.add(r.serviceAccount.uniqueId);
        agg.credentials.push({
          time: d.time,
          locator: d.locator,
          fact: r.credential.fact,
          denied: r.credential.denied,
          severity: r.severity,
        });
      } else if (r.kind === "key" && r.key) {
        const identity = identityOf(r.serviceAccount?.email, r.serviceAccount?.uniqueId);
        if (!identity) continue;
        const agg = aggFor(aggs, identity);
        if (r.serviceAccount?.email) agg.emails.add(lower(r.serviceAccount.email));
        if (r.serviceAccount?.uniqueId) agg.uniqueIds.add(r.serviceAccount.uniqueId);
        agg.keys.push({
          time: d.time,
          locator: d.locator,
          action: r.key.action,
          denied: r.key.denied,
          severity: r.severity,
        });
      } else if (r.kind === "attachment" && r.attachment) {
        const identity = identityOf(r.serviceAccount?.email, undefined);
        if (!identity) continue;
        const agg = aggFor(aggs, identity);
        if (r.serviceAccount?.email) agg.emails.add(lower(r.serviceAccount.email));
        agg.attachments.push({
          time: d.time,
          locator: d.locator,
          workloadKind: r.attachment.workloadKind,
          ...(r.attachment.workloadVersion ? { workloadVersion: r.attachment.workloadVersion } : {}),
          ...(r.attachment.workloadName ? { workloadName: r.attachment.workloadName } : {}),
          identityRole: r.attachment.identityRole,
          severity: r.severity,
        });
      }
    }
    // Calls authenticated AS this account — independent of whatever the record's readings concern.
    const principal = readPrincipal(d.pp);
    if (principal.kind === "service-account" && principal.email) {
      const identity = identityOf(principal.email, undefined);
      if (identity) {
        const agg = aggFor(aggs, identity);
        agg.emails.add(lower(principal.email));
        const delegation = readDelegation(d.pp)
          .map((del) => (del.kind === "third-party" ? "(third-party principal)" : (del.value ?? "")))
          .filter(Boolean);
        const statusCode = Number(field(d.pp, "status", "code")) || 0;
        const denied = statusCode !== 0;
        const ruleSeverity = matchGcpRule(d.method)?.severity ?? "Low";
        const severity = denied ? worst(ruleSeverity, "Medium") : ruleSeverity;
        agg.callsAsPrincipal.push({
          time: d.time,
          locator: d.locator,
          ...(principal.keyName ? { keyName: principal.keyName } : {}),
          delegation,
          denied,
          severity,
        });
      }
    }
  }

  const rows = [...aggs.entries()]
    .map(([identity, agg]) => buildRow(identity, agg, parentScopeByProject, coverage))
    .filter((r): r is { row: MappedEvent; grade: Severity; tier: 1 | 2 | 3 } => r !== null)
    .sort(
      (a, b) => b.tier - a.tier || RANK[b.grade] - RANK[a.grade] || a.row.aggKey.localeCompare(b.row.aggKey),
    );

  const kept = rows.slice(0, GCP_SA_JOIN_MAX).map((r) => r.row);
  if (rows.length > GCP_SA_JOIN_MAX)
    kept.push(omittedRow(rows.length - GCP_SA_JOIN_MAX, rows[GCP_SA_JOIN_MAX].grade));
  return kept;
}

// ───────────────────────────── the row ─────────────────────────────

function buildRow(
  identity: string,
  agg: SaAgg,
  parentScopeByProject: ReadonlyMap<string, number>,
  coverage: { records: number; first: string; last: string },
): { row: MappedEvent; grade: Severity; tier: 1 | 2 | 3 } | null {
  const hasDirect =
    agg.bindingsAsMember.length ||
    agg.bindingsAsResource.length ||
    agg.credentials.length ||
    agg.keys.length ||
    agg.attachments.length ||
    agg.callsAsPrincipal.length;
  if (!hasDirect) return null;

  const tier: 1 | 2 | 3 =
    agg.credentials.length || agg.keys.length || agg.attachments.length
      ? 3
      : agg.bindingsAsMember.length || agg.bindingsAsResource.length
        ? 2
        : 1;

  // Home project: the first known email whose documented address shape yields one.
  let homeProject: GcpProjectRef | undefined;
  for (const email of agg.emails) {
    const p = principalOf(email);
    if (p.homeProject) {
      homeProject = p.homeProject;
      break;
    }
  }
  const parentScopeCount = homeProject ? (parentScopeByProject.get(refKey(homeProject)) ?? 0) : 0;

  // Grade: the highest severity among every admitted fact that carries one.
  let top: Severity = "Info";
  const mitreSet = new Set<string>();
  for (const b of [...agg.bindingsAsResource, ...agg.bindingsAsMember]) {
    if (RANK[b.severity] > RANK[top]) top = b.severity;
    for (const x of b.mitre) mitreSet.add(x);
  }
  for (const c of agg.credentials) if (RANK[c.severity] > RANK[top]) top = c.severity;
  for (const k of agg.keys) if (RANK[k.severity] > RANK[top]) top = k.severity;
  for (const a of agg.attachments) if (RANK[a.severity] > RANK[top]) top = a.severity;
  for (const c of agg.callsAsPrincipal) if (RANK[c.severity] > RANK[top]) top = c.severity;

  // Upgrade: a non-denied control grant over this account, followed by a non-denied credential
  // mint, key creation or authenticated call at a strictly later, parseable time.
  const controlGrants = agg.bindingsAsResource.filter(
    (b) => CONTROL_ROLES.has(lower(b.role)) && lower(b.action) === "add" && !b.denied,
  );
  const uses: { time: number; locator: string }[] = [
    ...agg.credentials.filter((c) => !c.denied).map((c) => ({ time: c.time, locator: c.locator })),
    ...agg.keys.filter((k) => !k.denied).map((k) => ({ time: k.time, locator: k.locator })),
    ...agg.callsAsPrincipal.filter((c) => !c.denied).map((c) => ({ time: c.time, locator: c.locator })),
  ];
  let upgrade: { controlLocator: string; useLocator: string } | undefined;
  outer: for (const g of controlGrants)
    for (const u of uses)
      if (u.time > g.time) {
        upgrade = { controlLocator: g.locator, useLocator: u.locator };
        break outer;
      }
  if (upgrade && RANK[top] < RANK.High) top = "High";

  // Projects touched: from every admitted binding's own RESOURCE, when it is itself a project
  // (never the member — a member is an identity, not the resource the binding is on).
  for (const b of [...agg.bindingsAsMember, ...agg.bindingsAsResource])
    touchProjects(agg, projectRefOf(b.resource));
  if (homeProject) touchProjects(agg, homeProject);
  const projectsTouched = [...agg.projectsTouched.values()];

  const who = [...agg.emails][0] ?? identity;
  const head = `GCP service account join: ${show(who, 60)}${homeProject ? ` (project ${show(homeProject.value, 40)}, ${homeProject.kind === "id" ? "an id" : "a number"})` : ""}`;

  const bindingsAsResourceShown = shown(agg.bindingsAsResource, BINDINGS_SHOWN_MAX);
  const bindingsAsMemberShown = shown(agg.bindingsAsMember, BINDINGS_SHOWN_MAX);
  const credentialsShown = shown(agg.credentials, CREDENTIALS_SHOWN_MAX);
  const keysShown = shown(agg.keys, KEYS_SHOWN_MAX);
  const attachmentsShown = shown(agg.attachments, ATTACHMENTS_SHOWN_MAX);
  const callsShown = shown(agg.callsAsPrincipal, CALLS_SHOWN_MAX);

  const parts: string[] = [];
  if (upgrade)
    parts.push(
      `control-then-use: a control-granting binding (${upgrade.controlLocator}) preceded a credential mint, key creation or authenticated use (${upgrade.useLocator}) — graded up to High`,
    );
  if (agg.bindingsAsResource.length)
    parts.push(
      `authority granted over this account: ${bindingsAsResourceShown.kept
        .slice(0, 4)
        .map((b) => `${b.role} ${b.action}${b.denied ? " (denied)" : ""} ${iso(b.time)} (${b.locator})`)
        .join(
          "; ",
        )}${agg.bindingsAsResource.length > 4 ? ` +${agg.bindingsAsResource.length - 4} more` : ""}${bindingsAsResourceShown.beyond ? `; ${plural(bindingsAsResourceShown.beyond, "further binding")} beyond the retained bound` : ""}`,
    );
  if (agg.bindingsAsMember.length)
    parts.push(
      `access granted to this account as a member: ${bindingsAsMemberShown.kept
        .slice(0, 4)
        .map((b) => `${b.role} ${b.action}${b.denied ? " (denied)" : ""} ${iso(b.time)} (${b.locator})`)
        .join(
          "; ",
        )}${agg.bindingsAsMember.length > 4 ? ` +${agg.bindingsAsMember.length - 4} more` : ""}${bindingsAsMemberShown.beyond ? `; ${plural(bindingsAsMemberShown.beyond, "further binding")} beyond the retained bound` : ""}`,
    );
  if (agg.credentials.length)
    parts.push(
      `credentials minted: ${credentialsShown.kept
        .slice(0, 4)
        .map((c) => `${c.fact}${c.denied ? " (denied)" : ""} ${iso(c.time)} (${c.locator})`)
        .join(
          "; ",
        )}${agg.credentials.length > 4 ? ` +${agg.credentials.length - 4} more` : ""}${credentialsShown.beyond ? `; ${plural(credentialsShown.beyond, "further credential")} beyond the retained bound` : ""}`,
    );
  if (agg.keys.length)
    parts.push(
      `${plural(agg.keys.length, "key action")}: ${keysShown.kept
        .slice(0, 4)
        .map((k) => `${k.action}${k.denied ? " (denied)" : ""} ${iso(k.time)} (${k.locator})`)
        .join(
          "; ",
        )}${agg.keys.length > 4 ? ` +${agg.keys.length - 4} more` : ""}${keysShown.beyond ? `; ${plural(keysShown.beyond, "further key action")} beyond the retained bound` : ""}`,
    );
  if (agg.attachments.length)
    parts.push(
      `attached to: ${attachmentsShown.kept
        .slice(0, 4)
        .map(
          (a) =>
            `${a.workloadKind}${a.workloadVersion ? ` ${a.workloadVersion}` : ""} ${show(a.workloadName || "(name not recorded)", 60)} (${a.identityRole}) ${iso(a.time)} (${a.locator})`,
        )
        .join(
          "; ",
        )}${agg.attachments.length > 4 ? ` +${agg.attachments.length - 4} more` : ""}${attachmentsShown.beyond ? `; ${plural(attachmentsShown.beyond, "further attachment")} beyond the retained bound` : ""}`,
    );
  if (agg.callsAsPrincipal.length)
    parts.push(
      `authenticated principal of ${plural(agg.callsAsPrincipal.length, "call")} in this export${callsShown.beyond ? ` (+${callsShown.beyond} beyond the retained bound)` : ""}`,
    );
  if (agg.bindingsAsMember.length && agg.callsAsPrincipal.length)
    parts.push(
      `this account is also a direct member of ${plural(agg.bindingsAsMember.length, "other binding")} and the authenticated principal of ${plural(agg.callsAsPrincipal.length, "call")} — a co-occurrence, not a causal link`,
    );
  if (parentScopeCount)
    parts.push(
      `${plural(parentScopeCount, "parent-scope binding")} recorded on this account's own project${homeProject ? ` (${show(homeProject.value, 40)})` : ""} in this export — nominally may apply to this account; inheritance not evaluated`,
    );
  parts.push("no effective permission is ever claimed");
  parts.push(
    `${plural(coverage.records, "record")} of this export read (${coverage.first.slice(0, 10)} → ${coverage.last.slice(0, 10)})`,
  );

  const description = `${head} — ${parts.join(" — ")}`.slice(0, DESCRIPTION_MAX);

  const block: GcpServiceAccountJoinBlock = {
    identity,
    emails: [...agg.emails],
    uniqueIds: [...agg.uniqueIds],
    ...(homeProject ? { homeProject } : {}),
    bindingsAsMember: bindingsAsMemberShown.kept.map(toIso),
    bindingsAsMemberBeyond: bindingsAsMemberShown.beyond,
    bindingsAsResource: bindingsAsResourceShown.kept.map(toIso),
    bindingsAsResourceBeyond: bindingsAsResourceShown.beyond,
    parentScopeCount,
    credentials: credentialsShown.kept.map(toIso),
    credentialsBeyond: credentialsShown.beyond,
    keys: keysShown.kept.map(toIso),
    keysBeyond: keysShown.beyond,
    attachments: attachmentsShown.kept.map(toIso),
    attachmentsBeyond: attachmentsShown.beyond,
    callsAsPrincipal: callsShown.kept.map(toIso),
    callsAsPrincipalBeyond: callsShown.beyond,
    projectsTouched,
    ...(upgrade ? { upgrade } : {}),
    admissionTier: tier,
    coverage,
    basis: BASIS,
  };

  const allTimes = [
    ...agg.bindingsAsResource.map((b) => b.time),
    ...agg.bindingsAsMember.map((b) => b.time),
    ...agg.credentials.map((c) => c.time),
    ...agg.keys.map((k) => k.time),
    ...agg.attachments.map((a) => a.time),
    ...agg.callsAsPrincipal.map((c) => c.time),
  ];
  const firstTime = allTimes.length ? Math.min(...allTimes) : NaN;
  const observed = Number.isFinite(firstTime) ? iso(firstTime) : coverage.first;

  const locators = [
    ...new Set([
      ...agg.bindingsAsResource.map((b) => b.locator),
      ...agg.bindingsAsMember.map((b) => b.locator),
      ...agg.credentials.map((c) => c.locator),
      ...agg.keys.map((k) => k.locator),
      ...agg.attachments.map((a) => a.locator),
      ...agg.callsAsPrincipal.map((c) => c.locator),
    ]),
  ].slice(0, 256);

  const row: MappedEvent = {
    timestamp: normalizeTime(observed),
    description,
    severity: top,
    mitre: [...mitreSet],
    aggKey: boundedAggKey(`gcp-sa-join|${lower(identity)}`),
    sources: ["GCP Audit"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "service-account-join", action: "join", outcome: "success" },
      actor: { kind: "cloud_principal", id: identity, name: who },
      cloud: {
        provider: "gcp",
        principalId: who,
        principalType: "service-account",
        ...(homeProject?.namespace === "projects" ? { tenant: homeProject.value } : {}),
      },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: {
        rawRecords: (locators.length ? locators : ["none"]).map((l) => ({ source: "gcp-audit", locator: l })),
      },
      producer: {
        importer: "gcp-audit",
        parserVersion: "1",
        mappingVersion: "gcp-sa-join-v1",
        ruleVersions: ["gcp-sa-join-v1"],
      },
      gcpServiceAccountJoin: block,
    }),
  };
  return { row, grade: top, tier };
}

function omittedRow(count: number, severity: Severity): MappedEvent {
  const description = `GCP service account join: ${count} further account${count === 1 ? "" : "s"} with a join in this export beyond the ${GCP_SA_JOIN_MAX} reported — not shown`;
  return {
    timestamp: "",
    description,
    severity,
    mitre: [],
    aggKey: boundedAggKey(`gcp-sa-join|omitted|${count}`),
    sources: ["GCP Audit"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "service-account-join", action: "omitted" },
      cloud: { provider: "gcp" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "gcp-audit", locator: "omitted" }] },
      producer: { importer: "gcp-audit", parserVersion: "1", mappingVersion: "gcp-sa-join-v1" },
    }),
  };
}
