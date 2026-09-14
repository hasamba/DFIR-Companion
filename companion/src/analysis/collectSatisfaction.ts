// Import-satisfaction detection for collection directives (investigation-guidance #8, phase 2). The
// single worst anti-pattern in a guidance surface: the tool keeps rendering "collect Security.evtx on
// DC01" AFTER the analyst already collected and imported it — that stale-recommendation loop is what
// teaches analysts to stop trusting the guidance. This deterministic check closes the loop: an open
// collect target (from the prior run's nextSteps/unknown questions) whose host now HAS matching events
// in the case is SATISFIED — the next synthesis is told to stop re-recommending it and to re-evaluate
// the question it served with the evidence now in hand.
//
// PURE — no I/O. Matching is deliberately conservative (host must match AND a logSource/artifact token
// must appear in the event's source/artifactName/description) so a satisfied mark means "evidence for
// this collection is present", never a coincidental hit.
//
// "Present" means IMPORTED AFTER THE DIRECTIVE WAS ISSUED. The model writes a collect request because
// of the evidence it can already see; handing that same evidence back as the request's result tells
// it the collection happened and invites it to narrate an outcome that was never observed
// (a case on 2026-09-14: the two WMI Sigma hits that prompted a "baseline this consumer" request
// satisfied it on the next run and became a "golden-image comparison confirms benign" finding).
// Every forensic event id is `<import-seq>e<n>`, so ordering needs no clock: a directive is stamped
// with the case's import high-water mark when first issued and only a higher-sequence event counts.

import type { CollectDirective, ForensicEvent, InvestigationState } from "./stateTypes.js";
import { isActionableCollect, collectTargetKey, collectSummary } from "./collectDirective.js";
import { shortHost } from "./iocAnchors.js";

export interface OpenCollectTarget {
  key: string; // collectTargetKey (host|source)
  host: string;
  source: string; // logSource || artifact (what to look for)
  from: "nextStep" | "question";
  refId: string; // the nextStep/question id it came from
  question?: string; // the question text (for the prompt), when from a question
  summary: string; // human one-liner
  issuedAfterImportSeq?: number; // CollectDirective.issuedAfterImportSeq; absent ⇒ never satisfiable
}

// The import sequence an event id encodes (`<seq>e<n>`), or undefined for any other id shape (a manual
// entry, a legacy fixture) — such an event cannot be ordered against a directive and never counts.
export function eventImportSeq(eventId: string): number | undefined {
  const m = /^(\d+)e\d+$/.exec(eventId);
  return m ? Number(m[1]) : undefined;
}

// The case's import high-water mark: the highest import sequence any event carries; 0 when none do.
export function highestImportSeq(events: readonly ForensicEvent[]): number {
  let highest = 0;
  for (const e of events) {
    const seq = eventImportSeq(e.id);
    if (seq !== undefined && seq > highest) highest = seq;
  }
  return highest;
}

// The actionable collect targets currently open in the case: every nextStep with an actionable collect,
// and every unknown/partial keyQuestion with one. De-duped by target key (first occurrence wins).
export function openCollectTargets(
  state: Pick<InvestigationState, "nextSteps" | "keyQuestions">,
): OpenCollectTarget[] {
  const out: OpenCollectTarget[] = [];
  const seen = new Set<string>();
  const add = (t: OpenCollectTarget): void => {
    if (!t.key || seen.has(t.key)) return;
    seen.add(t.key);
    out.push(t);
  };
  for (const s of state.nextSteps ?? []) {
    if (!isActionableCollect(s.collect)) continue;
    add({
      key: collectTargetKey(s.collect),
      host: s.collect.host!,
      source: (s.collect.logSource || s.collect.artifact || "").trim(),
      from: "nextStep",
      refId: s.id,
      summary: collectSummary(s.collect),
      issuedAfterImportSeq: s.collect.issuedAfterImportSeq,
    });
  }
  for (const q of state.keyQuestions ?? []) {
    if (q.status === "answered") continue;
    if (!isActionableCollect(q.collect)) continue;
    add({
      key: collectTargetKey(q.collect),
      host: q.collect.host!,
      source: (q.collect.logSource || q.collect.artifact || "").trim(),
      from: "question",
      refId: q.id,
      question: q.question,
      summary: collectSummary(q.collect),
      issuedAfterImportSeq: q.collect.issuedAfterImportSeq,
    });
  }
  return out;
}

// Stamp every actionable directive in `next` (the state a synthesis is about to persist) with the
// import high-water mark of `prev` (the state that synthesis read). A target `prev` already carried,
// by key, keeps its ORIGINAL stamp — the model re-emits open requests every run, and re-stamping would
// push the bar past the very import that fulfilled them. Directives without a host are left untouched
// (nothing can satisfy them anyway). Returns a new state; neither input is mutated.
export function stampCollectDirectives(next: InvestigationState, prev: InvestigationState): InvestigationState {
  const highWater = highestImportSeq(prev.forensicTimeline ?? []);
  const carried = new Map<string, number>();
  const remember = (c: CollectDirective | undefined): void => {
    if (!isActionableCollect(c) || c.issuedAfterImportSeq === undefined) return;
    const key = collectTargetKey(c);
    if (!carried.has(key)) carried.set(key, c.issuedAfterImportSeq);
  };
  for (const s of prev.nextSteps ?? []) remember(s.collect);
  for (const q of prev.keyQuestions ?? []) remember(q.collect);

  const stamp = (c: CollectDirective | undefined): CollectDirective | undefined => {
    if (!isActionableCollect(c)) return c;
    const issuedAfterImportSeq = c.issuedAfterImportSeq ?? carried.get(collectTargetKey(c)) ?? highWater;
    return issuedAfterImportSeq === c.issuedAfterImportSeq ? c : { ...c, issuedAfterImportSeq };
  };
  return {
    ...next,
    nextSteps: (next.nextSteps ?? []).map((s) => (s.collect ? { ...s, collect: stamp(s.collect) } : s)),
    keyQuestions: (next.keyQuestions ?? []).map((q) => (q.collect ? { ...q, collect: stamp(q.collect) } : q)),
  };
}

const GENERIC = new Set(["log", "logs", "the", "and", "for", "from", "evtx", "event", "events"]);

// Significant lowercase tokens of a log-source string (drop generic words + very short tokens). "evtx"/
// "event" are dropped as too generic on their own — an EVTX artifact tag would match nearly anything.
function sourceTokens(source: string): string[] {
  return source
    .toLowerCase()
    .split(/[^a-z0-9.]+/i)
    .filter((t) => t.length >= 3 && !GENERIC.has(t));
}

// The event ids in `events` that satisfy `target`: the event was imported AFTER the target was issued,
// is on the target host, AND at least one of the source's significant tokens appears in the event's
// sources / artifactName / description. Empty ⇒ not satisfied. When the source names nothing specific
// (no significant tokens), a host match alone counts — the directive only asked for "something from
// that host". An unstamped target (persisted before stamps existed) is never satisfied: its age is
// unknown, and the safe failure is a re-recommendation, not a fabricated result.
export function collectSatisfiedBy(target: OpenCollectTarget, events: readonly ForensicEvent[]): string[] {
  const issuedAfter = target.issuedAfterImportSeq;
  if (issuedAfter === undefined) return [];
  const host = shortHost(target.host);
  const tokens = sourceTokens(target.source);
  const hits: string[] = [];
  for (const e of events) {
    const seq = eventImportSeq(e.id);
    if (seq === undefined || seq <= issuedAfter) continue;
    if (!e.asset || shortHost(e.asset) !== host) continue;
    if (!tokens.length) {
      hits.push(e.id);
      continue;
    }
    const hay = [e.sources?.join(" ") ?? "", e.artifactName ?? "", e.description ?? ""]
      .join(" ")
      .toLowerCase();
    if (tokens.some((t) => hay.includes(t))) hits.push(e.id);
  }
  return hits;
}

export interface SatisfiedCollection {
  target: OpenCollectTarget;
  matchedEventIds: string[];
}

// All open targets that are now satisfied by the case events (capped event ids per target for display).
export function detectSatisfiedCollections(
  state: Pick<InvestigationState, "nextSteps" | "keyQuestions">,
  events: readonly ForensicEvent[],
  maxEventsPerTarget = 3,
): SatisfiedCollection[] {
  const out: SatisfiedCollection[] = [];
  for (const target of openCollectTargets(state)) {
    const matched = collectSatisfiedBy(target, events);
    if (matched.length)
      out.push({ target, matchedEventIds: matched.slice(0, Math.max(1, maxEventsPerTarget)) });
  }
  return out;
}

// The SATISFIED COLLECTIONS prompt block: tells the model these were already collected — do not
// re-recommend them; re-evaluate the question they served using the evidence now present. "" when none.
export function buildSatisfiedCollectionsBlock(satisfied: readonly SatisfiedCollection[]): string {
  if (!satisfied.length) return "";
  const lines = satisfied.map((s) => {
    const served =
      s.target.from === "question" && s.target.question ? ` (served: "${s.target.question}")` : "";
    return `- ${s.target.summary}${served} — evidence now present: ${s.matchedEventIds.join(", ")}`;
  });
  return (
    "SATISFIED COLLECTIONS (the investigator already collected and imported these — do NOT re-recommend " +
    "them as nextSteps; instead USE the evidence now present and re-evaluate the question each one served):\n" +
    lines.join("\n") +
    "\n\n"
  );
}
