// The mailbox-compromise chain (#931 item 2, chain half — #975): sign-in → mailbox access →
// rule / forwarding / permission → send / delete, in ONE mailbox, built over the records of ONE
// m365 export inside the importer (the sign-in and owner-access rows are Info and leave the
// forensic timeline at import, so no merge-time pass could see them).
//
// What one row rests on, and what it never says:
//   - identity: the mailbox by GUID, or by UPN when a record of this export states no GUID for it;
//     an alias, a name or a DN joins nothing and is counted;
//   - the join: a session id when the records carry one; else actor + client address inside a
//     window, joined only when exactly ONE session of that mailbox matches — and said on the row;
//   - stages count only in order, only for a successful, positive record (no attempt, no partial,
//     no dry run, no removal); a UAL logon is a sign-in only when every outcome field says so;
//   - "configured", never "forwarded"; "accessed" / "bound", never "read"; counts are the items the
//     records LIST; an absent stage is "not present among the supplied records" with the export's
//     own counts, and continuous coverage is never claimed.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { MailboxChainBlock, MailboxChainStep } from "./canonicalMailbox.js";
import { decodeExchangeRecord, type ExchangeChange } from "./exchangeAudit.js";
import { isExchangeRecord } from "./exchangeAuditImport.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { getCI, normalizeTime, str, type MappedEvent } from "./siemImport.js";
import { isEntraSignIn, isUalLogon, readEntraSignIn, readUalLogon, type EntraSignIn } from "./ualLogon.js";

type Row = Record<string, unknown>;

export const MAILBOX_CHAIN_WINDOW_HOURS = 24;
export const MAILBOX_CHAINS_MAX = 256;
/** Steps kept per mailbox and stage kind, the earliest first; the rest are counted. */
export const STEPS_PER_STAGE_MAX = 1024;
const RISK_JOIN_MINUTES = 10;
const STEPS_NAMED_MAX = 8;
const RAW_RECORDS_MAX = 256;
const NAME_MAX = 80;
// A chain row names up to four stages, their extras and the coverage clause: wider than a record row.
const DESCRIPTION_MAX = 1400;
const WINDOW_MS = MAILBOX_CHAIN_WINDOW_HOURS * 3_600_000;
const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const COVERAGE_NOTE =
  "continuous coverage of the window is not established by this export; licence, audit configuration and retention are not in this evidence";
const DELIVERY_NOTE = "delivery through the forwarding is not in this evidence";
const SYNC_NOTE = "possible offline copy after a folder sync — inferred, not observed";

const show = (v: string, max = NAME_MAX): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
const lower = (s: string): string => s.trim().toLowerCase();
const ms = (iso: string): number | null => {
  const t = Date.parse(normalizeTime(iso));
  return Number.isFinite(t) ? t : null;
};
const iso = (t: number | null): string => (t === null ? "(no time)" : new Date(t).toISOString());
const isGuid = (s: string): boolean =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s.trim());
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

// ───────────────────────────── steps ─────────────────────────────

type Stage = MailboxChainStep["stage"];

interface Step {
  stage: Stage | "excluded";
  time: number | null;
  locator: string;
  /** The record's own id when it carries one — stable across a shuffled export; else the locator. */
  recordId: string;
  actor: string;
  ip: string;
  session: string;
  words: string;
  severity: Severity;
  mitre: readonly string[];
  itemsListed: number | null;
  operations: number | null;
  forwardsOutside: boolean;
  sync: boolean;
  joinedBy: "session" | "actor-address";
}

const CONSEQUENCE_OPS = new Set([
  "send",
  "sendas",
  "sendonbehalf",
  "harddelete",
  "softdelete",
  "movetodeleteditems",
]);
const BIND_OPS = new Set(["messagebind", "folderbind"]);
/** The stage a record's kind and operation establish; null for an item operation the chain does not read as a stage. */
function stageOf(c: ExchangeChange): Stage | null {
  if (c.kind === "access" || c.kind === "aggregate") return "access";
  if (c.kind === "rule" || c.kind === "forwarding" || c.kind === "permission") return "persistence";
  const op = lower(c.operation);
  if (CONSEQUENCE_OPS.has(op)) return "consequence";
  if (BIND_OPS.has(op)) return "access";
  return null;
}

/** One Exchange record as a step: a stage when it counts, an excluded line when it does not. */
function exchangeStep(c: ExchangeChange, index: number): Step {
  const base: Omit<Step, "stage" | "words"> = {
    time: ms(c.time),
    locator: `record:${index}`,
    recordId: c.recordId || `record:${index}`,
    actor: c.actor,
    ip: c.ip,
    session: c.session,
    severity: c.severity,
    mitre: c.mitre,
    itemsListed: c.itemsListed,
    operations: c.operations,
    forwardsOutside: c.forwardsOutside,
    sync: c.kind === "access" && /^syncs /.test(c.posture),
    joinedBy: c.session ? "session" : "actor-address",
  };
  const how = [c.logon ? `as ${c.logon}` : "", c.client ? `via ${show(c.client, 40)}` : ""]
    .filter(Boolean)
    .join(" ");
  const body = `${c.posture}${c.words ? ` ${c.words}` : ""}${how ? ` ${how}` : ""}`;
  if (c.attempted || c.outcome === "partial")
    return { ...base, stage: "excluded", severity: "Info", mitre: [], words: `attempt: ${show(body, 160)}` };
  if (c.polarity === "simulates")
    return {
      ...base,
      stage: "excluded",
      severity: "Info",
      mitre: [],
      words: `simulation: ${show(body, 160)}`,
    };
  if (c.polarity === "removes")
    return { ...base, stage: "excluded", severity: "Info", mitre: [], words: `reversal: ${show(body, 160)}` };
  const stage = stageOf(c);
  if (c.polarity === "none" || stage === null)
    return {
      ...base,
      stage: "excluded",
      severity: "Info",
      mitre: [],
      words: `not a stage: ${show(body, 160)}`,
    };
  const lead = stage === "access" ? "accessed: " : stage === "persistence" ? "configured: " : "";
  const notes = [
    ...(stage === "persistence" && (c.forwardsOutside || (c.kind !== "permission" && c.target))
      ? [DELIVERY_NOTE]
      : []),
    ...(base.sync ? [SYNC_NOTE] : []),
  ];
  return {
    ...base,
    stage,
    words: `${lead}${show(body, 160)}${notes.length ? ` — ${notes.join("; ")}` : ""}`,
  };
}

interface Logon {
  step: Step;
  user: string;
  tenant: string;
}

/** A UAL logon as a sign-in step (established) or an excluded line (outcome not established). */
function logonStep(rec: Row, index: number, signIns: readonly EntraSignIn[]): Logon {
  const l = readUalLogon(rec);
  const time = ms(l.observed);
  const base: Omit<Step, "stage" | "words"> = {
    time,
    locator: `record:${index}`,
    recordId: l.recordId || `record:${index}`,
    actor: l.user,
    ip: l.ip,
    session: l.session,
    severity: "Info",
    mitre: [],
    itemsListed: null,
    operations: null,
    forwardsOutside: false,
    sync: false,
    joinedBy: l.session ? "session" : "actor-address",
  };
  if (!l.established)
    return {
      user: l.user,
      tenant: l.tenant,
      step: {
        ...base,
        stage: "excluded",
        words: `logon record — outcome not established${l.errorNumber ? ` (ErrorNumber ${show(l.errorNumber, 12)})` : l.logonError ? ` (${show(l.logonError, 40)})` : ""}`,
      },
    };
  // A contemporaneous interactive sign-in of the same user, address and tenant carries a risk
  // verdict — contemporaneous, never established as the same sign-in (design round finding 3).
  const risk =
    time === null || !l.tenant
      ? undefined
      : signIns.find(
          (s) =>
            s.interactive &&
            lower(s.user) === lower(l.user) &&
            s.ip &&
            s.ip === l.ip &&
            (s.homeTenant === lower(l.tenant) || s.resourceTenant === lower(l.tenant)) &&
            ms(s.observed) !== null &&
            Math.abs(ms(s.observed)! - time) <= RISK_JOIN_MINUTES * 60_000,
        );
  const riskWords = risk
    ? ` — a contemporaneous sign-in in the sign-in log (${Math.round(Math.abs(ms(risk.observed)! - time!) / 60_000)} min apart) carries risk: ${show(risk.riskState || "none", 24)}${risk.riskLevel ? `, ${show(risk.riskLevel, 12)}` : ""} — not established as the same sign-in`
    : "";
  return {
    user: l.user,
    tenant: l.tenant,
    step: {
      ...base,
      stage: "sign-in",
      words: `signed in${l.ip ? ` from ${l.ip}` : ""}${l.userAgent ? ` (${show(l.userAgent, 40)})` : ""}${l.requestType ? ` ${show(l.requestType, 30)}` : ""}${riskWords}`,
    },
  };
}

// ───────────────────────────── mailbox identity ─────────────────────────────

interface MailboxRef {
  key: string;
  kind: "guid" | "upn";
  name: string;
}

/**
 * The mailbox a record names, as an identity: its GUID; else its UPN, resolved to the GUID a
 * record of this export states beside that UPN (conflicts teach nothing); an alias, name or DN
 * resolves to nothing.
 */
function learnMailboxes(changes: readonly ExchangeChange[]): (c: ExchangeChange) => MailboxRef | null {
  const byUpn = new Map<string, string>();
  const conflicts = new Set<string>();
  for (const c of changes) {
    if (!isGuid(c.mailboxId) || !c.mailbox.includes("@")) continue;
    const upn = lower(c.mailbox);
    const prev = byUpn.get(upn);
    if (prev && prev !== lower(c.mailboxId)) conflicts.add(upn);
    else byUpn.set(upn, lower(c.mailboxId));
  }
  return (c) => {
    if (c.mailboxId && isGuid(c.mailboxId)) return { key: lower(c.mailboxId), kind: "guid", name: c.mailbox };
    if (!c.mailbox.includes("@")) return null;
    const upn = lower(c.mailbox);
    const guid = conflicts.has(upn) ? "" : (byUpn.get(upn) ?? "");
    return guid
      ? { key: guid, kind: "guid", name: c.mailbox }
      : { key: `upn:${upn}`, kind: "upn", name: c.mailbox };
  };
}

// ───────────────────────────── episodes ─────────────────────────────

interface Episode {
  join: MailboxChainBlock["join"];
  steps: Step[];
  first: number;
  last: number;
  actor: string;
  ip: string;
}

const hasJoinFacts = (s: Step): boolean => !!lower(s.actor) && !!s.ip;
const sameActor = (e: Episode, s: Step): boolean => lower(e.actor) === lower(s.actor) && e.ip === s.ip;

/** A sessionless step joins the ONE session of the mailbox sharing its actor and address inside the window. */
function candidatesFor(step: Step, sessions: readonly Episode[]): Episode[] {
  if (step.time === null || !hasJoinFacts(step)) return [];
  return sessions.filter(
    (e) => sameActor(e, step) && step.time! >= e.first - WINDOW_MS && step.time! <= e.last + WINDOW_MS,
  );
}

/** Open an episode at a step; the key is the step's own id and time, stable whatever the file order. */
function open(kind: MailboxChainBlock["join"]["kind"], key: string, s: Step): Episode {
  return { join: { kind, key }, steps: [s], first: s.time!, last: s.time!, actor: s.actor, ip: s.ip };
}

/**
 * Group one mailbox's steps (already sorted by time, then record id) into episodes: by session id
 * — one actor and address per episode, split at the window — then sessionless steps by the
 * stated rule. A step with no time, or no actor and address to join by, joins nothing.
 */
function episodesOf(steps: readonly Step[]): { episodes: Episode[]; ambiguous: number; incomplete: number } {
  const sessions: Episode[] = [];
  const openBySession = new Map<string, Episode>();
  const sessionless: Step[] = [];
  let incomplete = 0;
  for (const s of steps) {
    if (s.time === null) {
      incomplete += 1;
      continue;
    }
    if (!s.session) {
      sessionless.push(s);
      continue;
    }
    // One session id, one actor, one address: a record that shares the id with another actor or
    // address is its own episode (a reused or placeholder id joins nothing it should not).
    const k = `${s.session}|${lower(s.actor)}|${s.ip}`;
    const cur = openBySession.get(k);
    if (cur && s.time <= cur.first + WINDOW_MS) {
      cur.steps.push(s);
      cur.last = Math.max(cur.last, s.time);
      continue;
    }
    const e = open("session", `${s.session}|${lower(s.actor)}|${s.ip}|${iso(s.time)}`, s);
    openBySession.set(k, e);
    sessions.push(e);
  }
  let ambiguous = 0;
  const loose: Step[] = [];
  for (const s of sessionless) {
    if (!hasJoinFacts(s)) {
      incomplete += 1;
      continue;
    }
    const c = candidatesFor(s, sessions);
    if (c.length === 1) {
      c[0].steps.push({ ...s, joinedBy: "actor-address" });
      c[0].last = Math.max(c[0].last, s.time!);
    } else if (c.length > 1) ambiguous += 1;
    else loose.push(s);
  }
  // Steps that match no session form actor + address episodes of their own, from the earliest
  // step, split at the window.
  const own: Episode[] = [];
  const openByActor = new Map<string, Episode>();
  for (const s of loose) {
    const k = `${lower(s.actor)}|${s.ip}`;
    const cur = openByActor.get(k);
    if (cur && s.time! <= cur.first + WINDOW_MS) {
      cur.steps.push(s);
      cur.last = Math.max(cur.last, s.time!);
      continue;
    }
    const e = open("actor-address", `${s.recordId}@${iso(s.time)}`, s);
    openByActor.set(k, e);
    own.push(e);
  }
  return { episodes: [...sessions, ...own], ambiguous, incomplete };
}

// ───────────────────────────── the chain of one episode ─────────────────────────────

interface Chain {
  episode: Episode;
  stages: Partial<Record<Stage, Step>>;
  ordered: Step[];
  /** Every joined record the counts come from, in order — the envelope's evidence. */
  cited: Step[];
  outOfOrder: Step[];
  excluded: Step[];
  others: Record<Stage, Step[]>;
  stageCount: number;
  grade: Severity;
  itemsListed: number;
  operationsUnlisted: number;
}

const STAGES = ["sign-in", "access", "persistence", "consequence"] as const;

/**
 * The ordered subsequence sign-in < access < persistence < consequence, each strictly after the
 * previous, with the most stages; among equal counts the one whose steps grade highest, then the
 * one reaching the later stages (a rule outranks a bind it precedes). Sixteen stage subsets, the
 * earliest qualifying step per chosen stage.
 */
function pickStages(sorted: readonly Step[]): Partial<Record<Stage, Step>> {
  let best: { picked: Partial<Record<Stage, Step>>; count: number; rank: number; mask: number } | null = null;
  for (let mask = 1; mask < 16; mask += 1) {
    const picked: Partial<Record<Stage, Step>> = {};
    let after = -Infinity;
    let ok = true;
    let rank = 0;
    for (let i = 0; i < STAGES.length && ok; i += 1) {
      if (!(mask & (1 << i))) continue;
      const stage = STAGES[i];
      const pick = sorted.find((s) => s.stage === stage && s.time !== null && s.time > after);
      if (!pick) ok = false;
      else {
        picked[stage] = pick;
        after = pick.time!;
        rank += RANK[pick.severity];
      }
    }
    if (!ok) continue;
    const count = Object.keys(picked).length;
    if (
      !best ||
      count > best.count ||
      (count === best.count && (rank > best.rank || (rank === best.rank && mask > best.mask)))
    )
      best = { picked, count, rank, mask };
  }
  return best?.picked ?? {};
}

/** The chain of one episode: the picked stages, the rest listed beside them, the grade. */
function chainOf(episode: Episode): Chain | null {
  const sorted = [...episode.steps].sort(
    (a, b) => (a.time ?? Infinity) - (b.time ?? Infinity) || a.locator.localeCompare(b.locator),
  );
  const stages = pickStages(sorted);
  const others: Record<Stage, Step[]> = { "sign-in": [], access: [], persistence: [], consequence: [] };
  const outOfOrder: Step[] = [];
  for (const s of sorted) {
    if (s.stage === "excluded") continue;
    if (stages[s.stage] === s) continue;
    const chosen = stages[s.stage];
    // A step of a counted stage that sits before the stage it should follow is out of order.
    const previous = (["sign-in", "access", "persistence", "consequence"] as const)
      .slice(0, ["sign-in", "access", "persistence", "consequence"].indexOf(s.stage))
      .map((k) => stages[k])
      .filter((x): x is Step => !!x)
      .pop();
    if (!chosen && previous && s.time !== null && s.time <= previous.time!) outOfOrder.push(s);
    else others[s.stage].push(s);
  }
  const counted = Object.values(stages).filter((s): s is Step => !!s);
  const stageCount = counted.length;
  if (stageCount < 2) return null;
  // The row is a finding only when something in it is above the owner's own routine: a step graded
  // Low or above (a delegate or admin access, a rule, a forwarding, a permission, a cross-mailbox
  // move). An owner signing in, reading and sending their own mail is all Info — no row.
  const top = counted.reduce<Severity>((m, s) => (RANK[s.severity] > RANK[m] ? s.severity : m), "Info");
  if (top === "Info") return null;
  const persistence = stages.persistence;
  const floor: Severity =
    stageCount >= 3 && persistence
      ? persistence.forwardsOutside
        ? "High"
        : "Medium"
      : stageCount >= 3
        ? "Medium"
        : "Low";
  const grade = RANK[top] > RANK[floor] ? top : floor;
  // The records the row cites — every joined step that contributes to a count — bounded.
  const listing = [...counted, ...Object.values(others).flat()].slice(0, RAW_RECORDS_MAX);
  return {
    episode,
    stages,
    ordered: counted,
    outOfOrder,
    excluded: sorted.filter((s) => s.stage === "excluded"),
    others,
    cited: listing,
    stageCount,
    grade,
    itemsListed: listing.reduce((n, s) => n + (s.itemsListed ?? 0), 0),
    operationsUnlisted: listing.reduce((n, s) => n + (s.itemsListed === null ? (s.operations ?? 0) : 0), 0),
  };
}

// ───────────────────────────── the pass ─────────────────────────────

interface Coverage {
  records: number;
  earliest: string;
  latest: string;
}
type ExportCoverage = Record<"mailboxAudit" | "logons" | "signIns", Coverage | null>;

const byTime = (a: Step, b: Step): number =>
  (a.time ?? Infinity) - (b.time ?? Infinity) || a.recordId.localeCompare(b.recordId);

/** One summary row per (tenant, mailbox, join) whose export records form a chain; the rows say what they rest on. */
export function mailboxChains(records: readonly Row[]): MappedEvent[] {
  const coverage = new Map<string, ExportCoverage>();
  const cover = (tenant: string, kind: keyof ExportCoverage, time: string) => {
    const k = lower(tenant);
    const c = coverage.get(k) ?? coverage.set(k, { mailboxAudit: null, logons: null, signIns: null }).get(k)!;
    const t = normalizeTime(time);
    const cur = c[kind] ?? { records: 0, earliest: t, latest: t };
    c[kind] = {
      records: cur.records + 1,
      earliest: t && (!cur.earliest || t < cur.earliest) ? t : cur.earliest,
      latest: t && (!cur.latest || t > cur.latest) ? t : cur.latest,
    };
  };
  // First pass: every Exchange record counted for coverage (narrated or not), every logon, every
  // interactive sign-in.
  const changes: { c: ExchangeChange; index: number }[] = [];
  const logonRecords: { rec: Row; index: number }[] = [];
  const signIns: EntraSignIn[] = [];
  records.forEach((rec, index) => {
    if (isExchangeRecord(rec)) {
      cover(str(getCI(rec, "OrganizationId")), "mailboxAudit", str(getCI(rec, "CreationTime")));
      const c = decodeExchangeRecord(rec, index);
      if (c) changes.push({ c, index });
    } else if (isUalLogon(rec)) {
      const l = readUalLogon(rec);
      cover(l.tenant, "logons", l.observed);
      logonRecords.push({ rec, index });
    } else if (isEntraSignIn(rec)) {
      const s = readEntraSignIn(rec);
      cover(s.resourceTenant || s.homeTenant, "signIns", s.observed);
      signIns.push(s);
    }
  });
  // Logons indexed by tenant + session and tenant + actor + address: a logon joins a mailbox's
  // steps only inside its own tenant (both stated and equal), never across.
  const logonsBySession = new Map<string, Step[]>();
  const logonsByActor = new Map<string, Step[]>();
  for (const { rec, index } of logonRecords) {
    const l = logonStep(rec, index, signIns);
    const tenant = lower(l.tenant);
    if (!tenant) continue;
    if (l.step.session) {
      const k = `${tenant}|${l.step.session}`;
      (logonsBySession.get(k) ?? logonsBySession.set(k, []).get(k)!).push(l.step);
    } else if (lower(l.step.actor) && l.step.ip) {
      const k = `${tenant}|${lower(l.step.actor)}|${l.step.ip}`;
      (logonsByActor.get(k) ?? logonsByActor.set(k, []).get(k)!).push(l.step);
    }
  }
  const refOf = learnMailboxes(changes.map((x) => x.c));

  // Steps per (tenant, mailbox): the Exchange records, then the logons their sessions / actors
  // name, sorted by (time, record id) and bounded per stage kind — deterministic whatever the file
  // order (design round finding 8; code round findings 5 and 8).
  const perMailbox = new Map<string, { tenant: string; ref: MailboxRef; steps: Step[]; beyond: number }>();
  const unlinked = new Map<string, number>();
  for (const { c, index } of changes) {
    const ref = refOf(c);
    if (!ref) {
      unlinked.set(lower(c.tenant), (unlinked.get(lower(c.tenant)) ?? 0) + 1);
      continue;
    }
    const k = `${lower(c.tenant)}|${ref.key}`;
    const m =
      perMailbox.get(k) ?? perMailbox.set(k, { tenant: lower(c.tenant), ref, steps: [], beyond: 0 }).get(k)!;
    m.steps.push(exchangeStep(c, index));
  }
  for (const m of perMailbox.values()) {
    if (m.tenant) {
      const seenLogon = new Set<Step>();
      const sessions = new Set(m.steps.map((s) => s.session).filter(Boolean));
      const actors = new Set(m.steps.filter(hasJoinFacts).map((s) => `${lower(s.actor)}|${s.ip}`));
      for (const sid of sessions)
        for (const l of logonsBySession.get(`${m.tenant}|${sid}`) ?? []) seenLogon.add(l);
      for (const a of actors) for (const l of logonsByActor.get(`${m.tenant}|${a}`) ?? []) seenLogon.add(l);
      m.steps.push(...seenLogon);
    }
    m.steps.sort(byTime);
    const kept: Step[] = [];
    const seen = new Map<string, number>();
    for (const s of m.steps) {
      const n = seen.get(s.stage) ?? 0;
      if (n < STEPS_PER_STAGE_MAX) {
        kept.push(s);
        seen.set(s.stage, n + 1);
      } else m.beyond += 1;
    }
    m.steps = kept;
  }

  const findings = [...perMailbox.values()]
    .flatMap((m) => {
      const { episodes, ambiguous, incomplete } = episodesOf(m.steps);
      return episodes
        .map((e) => chainOf(e))
        .filter((c): c is Chain => c !== null)
        .map((chain) => ({ m, chain, ambiguous, incomplete, beyond: m.beyond }));
    })
    .sort(
      (a, b) =>
        RANK[b.chain.grade] - RANK[a.chain.grade] ||
        b.chain.stageCount - a.chain.stageCount ||
        b.chain.episode.first - a.chain.episode.first ||
        a.m.ref.key.localeCompare(b.m.ref.key) ||
        a.chain.episode.join.key.localeCompare(b.chain.episode.join.key),
    );
  const rows = findings.slice(0, MAILBOX_CHAINS_MAX).map((f) =>
    summaryRow(
      f.m.tenant,
      f.m.ref,
      f.chain,
      {
        ambiguous: f.ambiguous,
        incomplete: f.incomplete,
        beyond: f.beyond,
        unlinked: unlinked.get(f.m.tenant) ?? 0,
      },
      coverage.get(f.m.tenant),
    ),
  );
  // The omitted row carries the highest grade among the omitted, so a severity floor that keeps
  // any omitted finding keeps the count too.
  if (findings.length > MAILBOX_CHAINS_MAX)
    rows.push(omittedRow(findings.length - MAILBOX_CHAINS_MAX, findings[MAILBOX_CHAINS_MAX].chain.grade));
  return rows;
}

// ───────────────────────────── the row ─────────────────────────────

interface Counts {
  ambiguous: number;
  incomplete: number;
  beyond: number;
  unlinked: number;
}

function summaryRow(
  tenant: string,
  ref: MailboxRef,
  chain: Chain,
  counts: Counts,
  coverage: ExportCoverage | undefined,
): MappedEvent {
  const { ambiguous, incomplete, beyond, unlinked } = counts;
  const e = chain.episode;
  const stepWords = (s: Step) =>
    `${iso(s.time)} ${s.words}${e.join.kind === "session" && s.joinedBy === "actor-address" ? " (joined by actor + address, not by session)" : ""}`;
  const named = (steps: Step[], label: string): string[] => {
    const shown = steps.slice(0, STEPS_NAMED_MAX).map(stepWords);
    return [
      ...shown,
      ...(steps.length > STEPS_NAMED_MAX ? [`+${steps.length - STEPS_NAMED_MAX} more ${label}`] : []),
    ];
  };
  const absence = (kind: keyof ExportCoverage, what: string): string => {
    const c = coverage?.[kind];
    const log =
      kind === "mailboxAudit" ? "Exchange mailbox-audit" : kind === "logons" ? "UAL logon" : "sign-in";
    return c
      ? `no ${what} among the ${c.records} supplied ${log} records (earliest ${c.earliest.slice(0, 10)}, latest ${c.latest.slice(0, 10)})`
      : `${log} log not in this export`;
  };
  const s = chain.stages;
  const parts = [
    ...(s["sign-in"]
      ? [stepWords(s["sign-in"])]
      : [absence("logons", "established logon record for this actor")]),
    ...named(chain.others["sign-in"], "logons"),
    ...(s.access ? [stepWords(s.access)] : [absence("mailboxAudit", "access record for this mailbox")]),
    ...named(chain.others.access, "accesses"),
    ...(s.persistence
      ? [stepWords(s.persistence)]
      : [absence("mailboxAudit", "rule, forwarding or permission change for this mailbox")]),
    ...named(chain.others.persistence, "changes"),
    ...(s.consequence
      ? [stepWords(s.consequence)]
      : [absence("mailboxAudit", "send, move or deletion for this mailbox")]),
    ...named(chain.others.consequence, "items"),
    ...(chain.outOfOrder.length
      ? [`before the stage it would follow, not counted: ${named(chain.outOfOrder, "steps").join("; ")}`]
      : []),
    ...named(chain.excluded, "non-steps"),
  ];
  // The counts, the coverage clause and the stage sentence are packed first; the step words are
  // cut to what remains.
  const tail = [
    `items listed: ${chain.itemsListed} across the ${plural(chain.cited.length, "cited record")}${chain.operationsUnlisted ? `; ${chain.operationsUnlisted} operations in aggregated records, items not listed` : ""}`,
    COVERAGE_NOTE,
    ...(ambiguous
      ? [
          `${plural(ambiguous, "record")} by this actor from this address inside the window match${ambiguous === 1 ? "es" : ""} two or more sessions — not joined`,
        ]
      : []),
    ...(incomplete
      ? [`${plural(incomplete, "record")} with no time, or no actor and address to join by — not joined`]
      : []),
    ...(unlinked
      ? [
          `${plural(unlinked, "change")} name${unlinked === 1 ? "s" : ""} a mailbox by an alias or name no record of this export links — not joined`,
        ]
      : []),
    ...(beyond ? [`${plural(beyond, "step")} beyond the bound, not evaluated`] : []),
    chain.stageCount >= 4
      ? "four stages in order"
      : chain.stageCount === 3
        ? "three of four stages"
        : "two of four stages",
  ].join("; ");
  const joinWords =
    e.join.kind === "session"
      ? `join: session ${show(e.join.key.split("|")[0], 16)}`
      : `join: actor + address, ${MAILBOX_CHAIN_WINDOW_HOURS}-hour window`;
  const head = `Mailbox chain: ${show(ref.name || ref.key)} (${joinWords})`;
  const room = DESCRIPTION_MAX - head.length - tail.length - 6;
  const lead = parts.join("; ");
  const description = `${head} [${lead.length > room ? `${lead.slice(0, Math.max(0, room - 1))}…` : lead}; ${tail}]`;
  const identity = createHash("sha256")
    .update(`${tenant.length}:${tenant}|${ref.key.length}:${ref.key}|${e.join.key.length}:${e.join.key}`)
    .digest("hex")
    .slice(0, 32);
  const steps: MailboxChainStep[] = chain.ordered.map((x) => ({
    stage: x.stage as Stage,
    time: iso(x.time),
    locator: x.locator,
    ...(x.session ? { session: x.session } : {}),
    joinedBy: x.joinedBy,
    ...(x.itemsListed !== null ? { itemsListed: x.itemsListed } : {}),
    ...(x.operations !== null ? { operations: x.operations } : {}),
  }));
  const block: MailboxChainBlock = {
    mailbox: ref.key,
    mailboxIdKind: ref.kind,
    ...(tenant ? { tenant } : {}),
    join: e.join,
    windowHours: MAILBOX_CHAIN_WINDOW_HOURS,
    stages: chain.stageCount,
    steps,
    itemsListed: chain.itemsListed,
    operationsUnlisted: chain.operationsUnlisted,
    ambiguous,
    incomplete,
    coverage: {
      ...(coverage?.mailboxAudit ? { mailboxAudit: coverage.mailboxAudit } : {}),
      ...(coverage?.logons ? { logons: coverage.logons } : {}),
      ...(coverage?.signIns ? { signIns: coverage.signIns } : {}),
    },
    basis:
      "records of this export only; joined through the mailbox and the stated join; configured, not delivered; accessed, not read",
  };
  const first = chain.ordered[0];
  const observed = iso(e.first);
  return {
    timestamp: normalizeTime(observed),
    description,
    severity: chain.grade,
    mitre: [...new Set(chain.ordered.flatMap((x) => x.mitre))],
    aggKey: boundedAggKey(`mailbox-chain|${identity}`),
    sources: ["Microsoft 365"],
    canonical: createCanonicalEvent({
      event: { category: "email", type: "mailbox-chain", action: "chain", outcome: "success" },
      actor: { kind: "account", name: first.actor || e.actor },
      object: { kind: "mailbox", id: ref.key, name: ref.name || ref.key },
      // Inherited from the chain's own earliest step — an Exchange audit record or a UAL sign-in
      // record (readUalLogon), both Microsoft-recorded audit log fields, never raw email header
      // content — edge-observed, not client-asserted (#1184 audit).
      ...(first.ip ? { network: { source: { address: first.ip } } } : {}),
      cloud: { provider: "m365", ...(tenant ? { tenant } : {}), principalType: "user" },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: { rawRecords: chain.cited.map((x) => ({ source: "m365-ual", locator: x.locator })) },
      producer: {
        importer: "m365-audit",
        parserVersion: "1",
        mappingVersion: "m365-mailbox-chain-v1",
        ruleVersions: ["mailbox-chain-v1"],
      },
      mailboxChain: block,
    }),
  };
}

function omittedRow(count: number, severity: Severity): MappedEvent {
  const description = `Mailbox chain: ${count} further mailbox chain${count === 1 ? "" : "s"} in this export beyond the ${MAILBOX_CHAINS_MAX} reported — not shown`;
  return {
    timestamp: "",
    description,
    severity,
    mitre: [],
    aggKey: boundedAggKey(`mailbox-chain|omitted|${count}`),
    sources: ["Microsoft 365"],
    canonical: createCanonicalEvent({
      event: { category: "email", type: "mailbox-chain", action: "omitted" },
      cloud: { provider: "m365" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "m365-ual", locator: "omitted" }] },
      producer: { importer: "m365-audit", parserVersion: "1", mappingVersion: "m365-mailbox-chain-v1" },
    }),
  };
}
