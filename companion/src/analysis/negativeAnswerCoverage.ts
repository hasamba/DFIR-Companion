// Negative-answer coverage backstop (#1588). A "no" is only as good as the evidence that could have
// said "yes". On the INC-2026-005 lab — a ransomware simulation that DID encrypt files — synthesis
// answered q_impact "No confirmed data encryption was observed." The case held only Chainsaw/Sigma
// hits built on Sysmon: no raw Sysmon events and no file listing of the victim folder, so nothing
// that COULD have shown the encryption. A rule feed's silence is the ruleset's silence, not the
// artifact's. The same run's next step n6 asked for Security 4624/4625 although the case itself
// recorded that the Security log had been cleared — a collection that would return nothing from the
// period that mattered.
//
// This is a PURE, deterministic post-synthesis pass over the collection inventory built in code
// (collectionInventory.ts). No AI call. Two passes:
//   A. An ANSWERED keyQuestion whose answer asserts an absence, about an evidence class the subject
//      hosts never collected raw, is downgraded to "partial": the answer gets one qualification
//      sentence, a collect directive when the model gave none, and ONE next step to settle it (or to
//      search the archive, when the artifact is already there).
//   B. A next step that asks for a log the case shows was cleared is demoted to "low" and warned —
//      never dropped — with the un-cleared alternative named when there is one.
// keyQuestions only, by design: they carry a status to downgrade and a collect to fill. Findings and
// uncertainties get the prompt rule (NEGATIVE_ANSWER_RULES) instead — rewriting their prose would
// compete with grounding and the second-opinion diff. Running the pass twice changes nothing more.

import { assertsAbsence } from "./answerContradiction.js";
import {
  CLASS_COLLECTION,
  coveredOnAll,
  emptySettledClasses,
  type ClearedLog,
  type CollectionInventory,
} from "./collectionInventory.js";
import { requiredEvidenceClasses, type EvidenceClass } from "./refutationGate.js";
import type {
  CollectDirective,
  ForensicEvent,
  InvestigationQuestion,
  InvestigationState,
  NextStep,
} from "./stateTypes.js";

export interface NegativeAnswerCoverageOptions {
  /** Resolve an event's raw `asset` to the inventory's canonical host (alias index). */
  hostOf?: (raw: string) => string;
  /** The events synthesis reasoned over (in scope, not dismissed); the host fallback reads these. */
  scopedEvents?: readonly ForensicEvent[];
}

const STEP_ID_PREFIX = "ns-coverage-";
const QUALIFICATION_MARK = "Not settled — ";
const CLEAR_WARNING_MARK = "⚠ The case shows the ";
const SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational";
const SECURITY_ASK_RE = /\bsecurity\b|\b(4624|4625|4634|4648|4672|4688|4720|4732|4768|4769|4776)\b/i;

const lower = (s: string | undefined): string => (s ?? "").trim().toLowerCase();
const slug = (s: string): string =>
  lower(s)
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "any";
const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// A whole-word match that also refuses "ws01" inside "ws010" or "ws01-backup".
const namesWord = (text: string, word: string): boolean =>
  !!word && new RegExp(`(?:^|[^\\w.-])${escapeRe(word)}(?![\\w-])`, "i").test(text);

// ---- A. subject hosts ----------------------------------------------------------------------------

function uniqueHosts(events: readonly ForensicEvent[], hostOf: (raw: string) => string): string[] {
  const out = new Set<string>();
  for (const e of events) {
    const raw = (e.asset ?? "").trim();
    const h = raw ? hostOf(raw) : "";
    if (h) out.add(h);
  }
  return [...out].sort();
}

function hostsNamedIn(text: string, inv: CollectionInventory): string[] {
  return inv.hosts.filter((h) => namesWord(text, h) || namesWord(text, h.split(".")[0]));
}

function hostsOfCitedEvents(
  q: InvestigationQuestion,
  state: InvestigationState,
  hostOf: (raw: string) => string,
): string[] {
  const findingIds = new Set(q.relatedFindingIds ?? []);
  if (!findingIds.size) return [];
  const eventIds = new Set(
    state.findings.filter((f) => findingIds.has(f.id)).flatMap((f) => f.relatedEventIds ?? []),
  );
  return uniqueHosts(
    state.forensicTimeline.filter((e) => eventIds.has(e.id)),
    hostOf,
  );
}

// Named in the text → hosts of the events the answer's findings cite → hosts with High/Critical
// activity → every host. Coverage must then hold on EVERY one (coveredOnAll), like refutationGate.
function subjectHosts(
  q: InvestigationQuestion,
  state: InvestigationState,
  inv: CollectionInventory,
  hostOf: (raw: string) => string,
  scopedEvents: readonly ForensicEvent[],
): string[] {
  const named = hostsNamedIn(`${q.question} ${q.answer}`, inv);
  if (named.length) return named;
  const cited = hostsOfCitedEvents(q, state, hostOf);
  if (cited.length) return cited;
  // The events synthesis reasoned over (in scope, not dismissed) — not the whole stored timeline.
  const hot = uniqueHosts(
    scopedEvents.filter((e) => e.severity === "High" || e.severity === "Critical"),
    hostOf,
  ).filter((h) => inv.hosts.includes(h));
  return hot.length ? hot : [...inv.hosts];
}

// ---- A. the gap and its remedy -------------------------------------------------------------------

interface CoverageGap {
  missing: EvidenceClass[];
  uncoveredHosts: string[];
  artifact: string;
  logSource: string;
  archiveOnly: boolean;
}

function coverageGap(
  q: InvestigationQuestion,
  hosts: string[],
  inv: CollectionInventory,
): CoverageGap | null {
  const required = requiredEvidenceClasses(`${q.question} ${q.answer}`);
  if (!required.length) return null;
  const covered = coveredOnAll(inv, hosts);
  // A clean zero-row fleet-wide hunt of a single-record-type artifact is evidence of absence.
  const settled = emptySettledClasses(inv);
  const missing = required.filter((c) => !covered.has(c) && !settled.has(c));
  if (!missing.length) return null;
  const uncoveredHosts = hosts.filter((h) => missing.some((c) => !inv.byHost.get(h)?.has(c)));
  const { artifact, logSource } = CLASS_COLLECTION[missing[0]];
  const archiveOnly = inv.hunts.some((h) => h.state === "archive-only" && h.artifact === artifact);
  return { missing, uncoveredHosts, artifact, logSource, archiveOnly };
}

function hostsText(gap: CoverageGap, none: string): string {
  return gap.uncoveredHosts.join(", ") || none;
}

function qualification(gap: CoverageGap): string {
  const verb = gap.archiveOnly ? "search the archive for" : "collect";
  return (
    `${QUALIFICATION_MARK}${gap.missing.join(", ")} evidence was not collected raw on ` +
    `${hostsText(gap, "any host in this case")}; ${verb} ${gap.artifact} (${gap.logSource}).`
  );
}

function directive(gap: CoverageGap): CollectDirective {
  const host = gap.uncoveredHosts[0];
  return {
    ...(host ? { host } : {}),
    artifact: gap.artifact,
    logSource: gap.logSource,
    expectedOutcome: `would show whether ${gap.missing[0]} activity occurred`,
  };
}

function coverageStep(q: InvestigationQuestion, gap: CoverageGap): NextStep {
  const where = hostsText(gap, "the affected hosts");
  const action = gap.archiveOnly
    ? `Search the archive for ${gap.artifact} on ${where} and promote the relevant rows to settle: ${q.question}`
    : `Collect ${gap.artifact} (${gap.logSource}) on ${where} to settle: ${q.question}`;
  return {
    id: `${STEP_ID_PREFIX}${slug(q.id)}-${slug(gap.uncoveredHosts[0] ?? "")}`,
    priority: "high",
    action,
    rationale:
      `The answer says the activity was not observed, but the ${gap.missing.join(", ")} evidence that ` +
      `could have shown it was not collected raw on ${where}; a detection feed's silence is not evidence of absence.`,
    pointer: gap.logSource,
    ...(gap.archiveOnly ? {} : { collect: directive(gap) }),
    relatedFindingIds: [...(q.relatedFindingIds ?? [])],
  };
}

const GENERIC_EVTX = "windows.eventlogs.evtx";

// The model paraphrases log sources ("Sysmon EID 11"), so a duplicate is the same host and artifact.
// The generic EVTX artifact carries any channel, so there it must also be about Sysmon — a model
// step for Security EVTX on the same host is a different collection (and may be a cleared log).
function sameTarget(existing: NextStep, host: string, artifact: string): boolean {
  const c = existing.collect;
  if (!c || lower(c.host) !== lower(host) || lower(c.artifact) !== lower(artifact)) return false;
  if (lower(artifact) !== GENERIC_EVTX) return true;
  return /sysmon/i.test(`${c.logSource ?? ""} ${existing.action} ${existing.pointer}`);
}

// An archive search has no collect; it is a duplicate when another search names the same artifact
// and host.
function sameArchiveSearch(existing: NextStep, host: string, artifact: string): boolean {
  const text = lower(`${existing.action} ${existing.pointer}`);
  return /\bsearch\b/.test(text) && text.includes(lower(artifact)) && (!host || text.includes(lower(host)));
}

function isDuplicateStep(step: NextStep, gap: CoverageGap, steps: readonly NextStep[]): boolean {
  const host = gap.uncoveredHosts[0] ?? "";
  return steps.some(
    (s) =>
      s.id === step.id ||
      (gap.archiveOnly ? sameArchiveSearch(s, host, gap.artifact) : sameTarget(s, host, gap.artifact)),
  );
}

function qualifyQuestion(q: InvestigationQuestion, gap: CoverageGap): InvestigationQuestion {
  const answer = q.answer.includes(QUALIFICATION_MARK)
    ? q.answer
    : `${q.answer.trimEnd()} ${qualification(gap)}`;
  const collect = q.collect ?? (gap.archiveOnly ? undefined : directive(gap));
  return { ...q, status: "partial", answer, ...(collect ? { collect } : {}) };
}

// An answered negative, or one answerContradiction already downgraded to partial because a
// detection contradicts it — that detection is still no raw collection, so the gap stands (#1588
// review). A model-authored partial answer is left alone: the model already owes it a collect.
function isCandidate(q: InvestigationQuestion): boolean {
  if (!assertsAbsence(q.answer)) return false;
  return q.status === "answered" || (q.status === "partial" && !!q.contradicted);
}

function applyUncoveredNegatives(
  state: InvestigationState,
  inv: CollectionInventory,
  hostOf: (raw: string) => string,
  scopedEvents: readonly ForensicEvent[],
): Pick<InvestigationState, "keyQuestions" | "nextSteps"> {
  const nextSteps = [...state.nextSteps];
  const keyQuestions = state.keyQuestions.map((q) => {
    if (!isCandidate(q)) return q;
    const gap = coverageGap(q, subjectHosts(q, state, inv, hostOf, scopedEvents), inv);
    if (!gap) return q;
    const step = coverageStep(q, gap);
    if (!isDuplicateStep(step, gap, nextSteps)) nextSteps.push(step);
    return qualifyQuestion(q, gap);
  });
  return { keyQuestions, nextSteps };
}

// ---- B. steps that ask for a cleared log ---------------------------------------------------------

function asksForChannel(text: string, channel: string): boolean {
  return lower(channel) === "security" ? SECURITY_ASK_RE.test(text) : namesWord(text, channel);
}

function clearedLogFor(step: NextStep, inv: CollectionInventory): ClearedLog | undefined {
  const host = lower(step.collect?.host);
  const text = [step.action, step.pointer, step.collect?.logSource, step.collect?.artifact]
    .filter(Boolean)
    .join(" ");
  return inv.cleared.find(
    (c) => !!c.channel && (!host || !c.host || lower(c.host) === host) && asksForChannel(text, c.channel),
  );
}

function clearWarning(cleared: ClearedLog, inv: CollectionInventory): string {
  const where = cleared.host ? ` on ${cleared.host}` : "";
  const sysmonCleared = inv.cleared.some(
    (c) =>
      lower(c.channel) === lower(SYSMON_CHANNEL) &&
      (!c.host || !cleared.host || lower(c.host) === lower(cleared.host)),
  );
  const prefer = sysmonCleared
    ? ""
    : ` Prefer ${CLASS_COLLECTION.execution.artifact} on ${SYSMON_CHANNEL}, which was not cleared.`;
  return (
    `${CLEAR_WARNING_MARK}${cleared.channel} log${where} was cleared at ${cleared.at}; ` +
    `this collection will likely return nothing from before then.${prefer}`
  );
}

function demoteClearedLogSteps(steps: readonly NextStep[], inv: CollectionInventory): NextStep[] {
  if (!inv.cleared.length) return [...steps];
  return steps.map((step) => {
    // The backstop's own steps already name the source to collect; a warning there is only noise.
    if (step.id.startsWith(STEP_ID_PREFIX) || step.rationale.startsWith(CLEAR_WARNING_MARK)) return step;
    const cleared = clearedLogFor(step, inv);
    if (!cleared) return step;
    const rationale = `${clearWarning(cleared, inv)} ${step.rationale}`.trimEnd();
    return { ...step, priority: "low", rationale };
  });
}

// ---- entry point ---------------------------------------------------------------------------------

export function applyNegativeAnswerCoverage(
  state: InvestigationState,
  inv: CollectionInventory,
  opts: NegativeAnswerCoverageOptions = {},
): InvestigationState {
  const hostOf = opts.hostOf ?? ((raw: string) => raw);
  const scoped = opts.scopedEvents ?? state.forensicTimeline;
  const { keyQuestions, nextSteps } = applyUncoveredNegatives(state, inv, hostOf, scoped);
  return { ...state, keyQuestions, nextSteps: demoteClearedLogSteps(nextSteps, inv) };
}
