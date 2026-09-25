import type { Finding, ForensicEvent, InvestigationState } from "./stateTypes.js";
import { assertsAbsence, CONTRADICTION_RULES, matchesRule } from "./answerContradiction.js";
import type { RefereeFlag, SecondOpinion, SecondOpinionDelta } from "./secondOpinion.js";

// The guard on referee dismissals (#1596).
//
// An A-only delta the referee marks accept_b DISMISSES Model A's finding. On INC-2026-005 the
// referee dismissed the ransomware script block and the ransom-note contact address as "already
// covered" — while "What was the impact?" answered "no file-encryption, ransom-note ... event" and
// an open thread still asked what that address was. It removed the only evidence for both, with a
// reason that quoted nothing, and the one-click "follow referee" accepted it.
//
// Two halves, one calculation. Before the verdicts, the referee is shown the case's open threads and
// unresolved or negative answers, and every A-only finding that is the last support for one of them
// is marked. After the verdicts, the same calculation runs in code: a dismissal of the last support,
// or one whose reason quotes nothing from the cited events, is flagged, and no bulk action accepts a
// flagged delta. The analyst can still accept it by hand. Deterministic, pure, no AI.

/** An unresolved item the referee must not remove the evidence for. */
export type OpenItem =
  | { kind: "thread"; id: string; description: string }
  | {
      kind: "question";
      id: string;
      question: string;
      answer: string;
      pointer: string;
      relatedFindingIds: readonly string[];
      negative: boolean; // the answer asserts an absence ("no X observed")
    };

/** What the guard reads from the case. `events` is the scoped forensic timeline the referee saw. */
export interface GuardCase {
  findings: readonly Finding[];
  openItems: readonly OpenItem[];
  events: readonly ForensicEvent[];
}

// How many items the PROMPT lists. The deterministic check always uses every item.
const PROMPT_ITEMS_MAX = 40;
const ITEM_TEXT_MAX = 200;

/** Open threads, plus key questions not yet answered or answered with an absence. */
export function openItemsOf(state: Pick<InvestigationState, "openThreads" | "keyQuestions">): OpenItem[] {
  const threads: OpenItem[] = (state.openThreads ?? [])
    .filter((t) => t.status === "open")
    .map((t) => ({ kind: "thread", id: t.id, description: t.description ?? "" }));
  const questions: OpenItem[] = [];
  for (const q of state.keyQuestions ?? []) {
    const negative = assertsAbsence(q.answer);
    if (q.status === "answered" && !negative) continue;
    questions.push({
      kind: "question",
      id: q.id,
      question: q.question ?? "",
      answer: q.answer ?? "",
      pointer: q.pointer ?? "",
      relatedFindingIds: q.relatedFindingIds ?? [],
      negative,
    });
  }
  return [...threads, ...questions];
}

export const guardCaseOf = (state: InvestigationState, events: readonly ForensicEvent[]): GuardCase => ({
  findings: state.findings,
  openItems: openItemsOf(state),
  events,
});

// --- Does a finding's evidence bear on an item? -------------------------------------------------

const lower = (s: string | undefined): string => String(s ?? "").toLowerCase();

function citedEventsOf(f: Finding, byId: ReadonlyMap<string, ForensicEvent>): ForensicEvent[] {
  return (f.relatedEventIds ?? []).flatMap((id) => {
    const e = byId.get(id);
    return e ? [e] : [];
  });
}

const eventText = (e: ForensicEvent): string => `${lower(e.description)} ${lower(e.path)}`;

interface Evidence {
  findingId: string;
  text: string; // finding title + description + cited event text, lower-cased
  techniques: readonly string[];
}

function evidenceOf(f: Finding, byId: ReadonlyMap<string, ForensicEvent>): Evidence {
  const events = citedEventsOf(f, byId);
  return {
    findingId: f.id,
    text: [lower(f.title), lower(f.description), ...events.map(eventText)].join("\n"),
    techniques: [...(f.mitreTechniques ?? []), ...events.flatMap((e) => e.mitreTechniques ?? [])].map((t) =>
      String(t).toUpperCase(),
    ),
  };
}

// A token that names one thing: an address, a file, a path, an extension, a hash, an id with digits.
const TOKEN_TRIM = /^[^a-z0-9.@\\/_]+|[^a-z0-9]+$/g;
function indicators(text: string): string[] {
  const out = new Set<string>();
  for (const raw of lower(text).split(/[\s"'`()[\]{},;<>|]+/)) {
    const t = raw.replace(TOKEN_TRIM, "");
    if (t.length < 5) continue;
    if (/[.@\\/_]/.test(t) || (/\d/.test(t) && /[a-z]/.test(t))) out.add(t);
  }
  return [...out];
}

// Words a negative answer uses that name nothing specific.
const GENERIC = new Set(
  (
    "about above activity activities after against along attacker attackers based because before being " +
    "between beyond confirm confirmed could currently destructive detect detected during either evidence " +
    "event events found further happened hosts identified impact indicate indication indicator indicators " +
    "malicious might network observed occurred other present process processes related review seen shows " +
    "signs since suspicious system systems there these those through timeline under until users where " +
    "which while within without would affected available collected currently data files"
  ).split(" "),
);
const STEM = 6;
const stems = (text: string): Set<string> =>
  new Set(
    lower(text)
      .split(/[^a-z0-9]+/)
      .filter((w) => w.length >= 5 && !GENERIC.has(w))
      .map((w) => w.slice(0, STEM)),
  );

// Ransomware / destruction evidence: its words differ from the question's ("what was the impact?"),
// so a term match alone would miss the exact case this guard exists for.
const IMPACT_QUESTION = /impact|ransom|encrypt|destruct|wip(e|ing)|damage/;
const IMPACT_EVIDENCE =
  /encrypt|decrypt|ransom|recovery\.txt|readme.*\.txt|shadow ?cop|vssadmin|wbadmin|bcdedit|cipher(\.exe)? \/w|\bwipe/;
const IMPACT_TECHNIQUES = ["T1486", "T1485", "T1490", "T1491", "T1561"];

const hasPrefix = (techniques: readonly string[], prefixes: readonly string[]): boolean =>
  techniques.some((t) => prefixes.some((p) => t === p || t.startsWith(`${p}.`)));

/** The first reason `ev` bears on `item`, or undefined. */
export function bearing(item: OpenItem, ev: Evidence): string | undefined {
  const idRe = new RegExp(
    `(^|[^a-z0-9-])${ev.findingId.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}($|[^a-z0-9-])`,
  );
  const itemText =
    item.kind === "thread" ? item.description : `${item.question}\n${item.answer}\n${item.pointer}`;
  if (item.kind === "question" && item.relatedFindingIds.includes(ev.findingId)) return `cited by ${item.id}`;
  if (idRe.test(lower(itemText))) return `named in ${item.id}`;
  const shared = indicators(itemText).find((t) => ev.text.includes(t));
  if (shared) return `"${shared}"`;
  if (item.kind !== "question") return undefined;
  const qText = lower(`${item.id} ${item.question}`);
  if (IMPACT_QUESTION.test(qText)) {
    const m = IMPACT_EVIDENCE.exec(ev.text);
    if (m) return `"${m[0]}"`;
    if (hasPrefix(ev.techniques, IMPACT_TECHNIQUES)) return "an impact technique";
  }
  const rule = CONTRADICTION_RULES.find((r) => matchesRule(item, r));
  if (rule && hasPrefix(ev.techniques, rule.techniquePrefixes))
    return `a ${rule.key.replace(/_/g, " ")} technique`;
  if (item.negative) {
    const evStems = stems(ev.text);
    const term = [...stems(item.answer)].find((s) => evStems.has(s));
    if (term) return `"${term}…"`;
  }
  return undefined;
}

// --- The one calculation: which findings are the LAST support for an item ---------------------

export interface Protection {
  item: OpenItem;
  why: string;
}

/**
 * For each finding in `removing`, the open items it bears on that no finding outside `removed`
 * still bears on. `removed` is every finding that would be gone: already dismissed, accepted for
 * dismissal, or proposed for dismissal in the same batch. A plain duplicate keeps no protection:
 * its twin still bears on the same item. Pure.
 */
export function lastSupport(
  gc: GuardCase,
  removing: ReadonlySet<string>,
  removed: ReadonlySet<string>,
): Map<string, Protection[]> {
  const byId = new Map(gc.events.map((e) => [e.id, e]));
  const evidence = new Map(gc.findings.map((f) => [f.id, evidenceOf(f, byId)]));
  const survivors = gc.findings.filter(
    (f) => f.status !== "dismissed" && !removed.has(f.id) && !removing.has(f.id),
  );
  const out = new Map<string, Protection[]>();
  for (const id of removing) {
    const ev = evidence.get(id);
    if (!ev) continue;
    const hits: Protection[] = [];
    for (const item of gc.openItems) {
      const why = bearing(item, ev);
      if (!why) continue;
      const supported = survivors.some((s) => bearing(item, evidence.get(s.id)!) !== undefined);
      if (!supported) hits.push({ item, why });
    }
    if (hits.length) out.set(id, hits);
  }
  return out;
}

const isFreshAOnly = (d: SecondOpinionDelta): boolean => d.kind === "a_only" && !d.carriedFrom && !!d.finding;

/** Findings already gone from the case or accepted for dismissal. */
function alreadyRemoved(gc: GuardCase, so: SecondOpinion): Set<string> {
  const ids = new Set(gc.findings.filter((f) => f.status === "dismissed").map((f) => f.id));
  for (const d of so.deltas)
    if (d.kind === "a_only" && d.status === "accepted" && d.finding) ids.add(d.finding.id);
  return ids;
}

// --- Before the verdicts: what the referee is shown --------------------------------------------

const clip = (s: string): string => {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > ITEM_TEXT_MAX ? `${t.slice(0, ITEM_TEXT_MAX)}…` : t;
};

function renderItem(item: OpenItem): string {
  if (item.kind === "thread") return `- [${item.id}] (open thread) ${clip(item.description)}`;
  const label = item.negative ? "negative answer" : "open question";
  const answer = item.answer.trim() ? ` — answer: "${clip(item.answer)}"` : "";
  return `- [${item.id}] (${label}) ${clip(item.question)}${answer}`;
}

/**
 * The warning printed under each pending A-only delta, keyed by delta id. Worst case: every pending
 * A-only finding is treated as dismissed, so a hint marks a finding that could be the last support.
 */
export function refereeHints(gc: GuardCase, so: SecondOpinion): Map<string, string> {
  const pending = so.deltas.filter((d) => isFreshAOnly(d) && d.status === "pending");
  const removing = new Set(pending.map((d) => d.finding!.id));
  const protectedBy = lastSupport(gc, removing, alreadyRemoved(gc, so));
  const out = new Map<string, string>();
  for (const d of pending) {
    const hits = protectedBy.get(d.finding!.id);
    if (hits)
      out.set(
        d.id,
        `! may be the only evidence for ${hits.map((h) => `${h.item.id} (${h.why})`).join(", ")}`,
      );
  }
  return out;
}

/** The runtime context block appended to the referee's user prompt. Empty when no A-only delta. */
export function refereeContextBlock(gc: GuardCase, deltas: readonly SecondOpinionDelta[]): string {
  if (!deltas.some((d) => d.kind === "a_only")) return "";
  // Negative answers first, then open questions, then threads: a cap drops the threads first.
  const rank = (i: OpenItem): number => (i.kind === "thread" ? 2 : i.negative ? 0 : 1);
  const ordered = [...gc.openItems].sort((x, y) => rank(x) - rank(y));
  const shown = ordered.slice(0, PROMPT_ITEMS_MAX);
  const items = shown.length ? shown.map(renderItem) : ["- (none)"];
  const more = ordered.length - shown.length;
  return [
    `OPEN QUESTIONS AND NEGATIVE ANSWERS (${gc.openItems.length}) — what this case has not settled:`,
    ...items,
    ...(more > 0 ? [`- … +${more} more open threads not listed (the system still checks them)`] : []),
    "",
    "RULES FOR A-ONLY FINDINGS (accept_b dismisses Model A's finding):",
    "- Before you recommend accept_b, check whether the finding's cited events bear on any item above.",
    '  If they do, recommend keep_a and start the rationale with "keep — answers <item id>".',
    '- A delta marked "! may be the only evidence for" is the last finding that bears on that item.',
    "- Every accept_b rationale on an A-only finding must quote, in double quotes, the exact text of",
    '  the cited events that shows why it can go (for "duplicate of f1": the text the two share).',
  ].join("\n");
}

// --- After the verdicts: the deterministic flags -----------------------------------------------

const QUOTE_MIN = 8;
const QUOTED = /"([^"]+)"|“([^”]+)”|`([^`]+)`|'([^']+)'/g;
const squash = (s: string): string => lower(s).replace(/\s+/g, " ").trim();

/** True when the rationale quotes, verbatim, at least QUOTE_MIN characters of the cited events. */
export function quotesEvidence(rationale: string, eventsText: string): boolean {
  const hay = squash(eventsText);
  for (const m of rationale.matchAll(QUOTED)) {
    const span = m[1] ?? m[2] ?? m[3] ?? m[4] ?? "";
    // A model may elide the middle of a long line; each kept piece must still be verbatim.
    const pieces = span
      .split(/\.\.\.|…/)
      .map(squash)
      .filter((p) => p.length >= QUOTE_MIN);
    if (pieces.length && pieces.every((p) => hay.includes(p))) return true;
  }
  return false;
}

function flagsFor(
  d: SecondOpinionDelta,
  protectedBy: ReadonlyMap<string, Protection[]>,
  byId: ReadonlyMap<string, ForensicEvent>,
): RefereeFlag[] {
  const flags: RefereeFlag[] = (protectedBy.get(d.finding!.id) ?? []).map((p) => ({
    kind: "answers_open_item" as const,
    itemId: p.item.id,
    itemKind:
      p.item.kind === "thread"
        ? ("thread" as const)
        : p.item.negative
          ? ("negative" as const)
          : ("question" as const),
    text: clip(p.item.kind === "thread" ? p.item.description : p.item.question),
  }));
  const events = citedEventsOf(d.finding!, byId);
  // A finding that cites nothing has nothing to quote; the prompt already calls it ungrounded.
  if (events.length && !quotesEvidence(d.rationale, events.map(eventText).join("\n")))
    flags.push({ kind: "unquoted_reason" });
  return flags;
}

/**
 * Stamp `refereeFlags` on every fresh, pending A-only delta the referee marked accept_b, and clear
 * them everywhere else. Run after every verdict fold. Pure.
 */
export function flagRefereeDismissals(so: SecondOpinion, gc: GuardCase): SecondOpinion {
  const isProposed = (d: SecondOpinionDelta): boolean =>
    isFreshAOnly(d) && d.status === "pending" && d.recommendation === "accept_b";
  const proposed = so.deltas.filter(isProposed);
  const removing = new Set(proposed.map((d) => d.finding!.id));
  const protectedBy = lastSupport(gc, removing, alreadyRemoved(gc, so));
  const byId = new Map(gc.events.map((e) => [e.id, e]));
  return {
    ...so,
    deltas: so.deltas.map((d) => {
      const { refereeFlags: _stale, ...rest } = d;
      if (!isProposed(d)) return rest;
      const flags = flagsFor(d, protectedBy, byId);
      return flags.length ? { ...rest, refereeFlags: flags } : rest;
    }),
  };
}

/** A flagged delta is for the analyst alone: no bulk action may accept it. */
export const heldForAnalyst = (d: SecondOpinionDelta): boolean => (d.refereeFlags?.length ?? 0) > 0;
