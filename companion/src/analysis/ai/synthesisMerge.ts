import { flagContradictedAnswers } from "../answerContradiction.js";
import { buildAssetGraph } from "../assetGraph.js";
import { buildEvidenceGraph } from "../evidenceGraph.js";
import { applyFalsePositive, type FalsePositiveMarker } from "../falsePositive.js";
import {
  capIntelOnlyFindings,
  buildIntelCorroborationSteps,
  groundAndScoreFindings,
} from "../findingGrounding.js";
import { scoreFindingsRelevance } from "../findingRelevance.js";
import { reconsiderKeyQuestions } from "../fpCascade.js";
import { backfillSilenceGapFindings, detectTimelineGaps, gapEnvOptions } from "../gapDetect.js";
import { backfillHighSeverityFindings } from "../highSeverityFindings.js";
import type { HostAliasIndex } from "../hostAlias.js";
import { shortHost } from "../iocAnchors.js";
import { extractCveIds, matchKevEntries, type KevCatalog } from "../kev.js";
import type { PlaybookTask } from "../playbook.js";
import { demoteCompletedNextSteps } from "../priorWork.js";
import { unionEventTechniques } from "../reconTechniques.js";
import type { deltaSchema } from "../responseSchema.js";
import type { SourceTrustMap } from "../sourceTrust.js";
import type { StateStore } from "../stateStore.js";
import type { ForensicEvent, InvestigationQuestion, InvestigationState } from "../stateTypes.js";
import { mergeDelta, type WindowContext } from "../stateMerge.js";

/**
 * Folding the model's delta back into the case (#418).
 *
 * The second half of `synthesize`, split out for the same reason the prompt builder was: it is a
 * different kind of work. Nothing here talks to a model. It takes one parsed delta and applies a
 * fixed sequence of DETERMINISTIC corrections to it — and each step in that sequence is a safety net
 * someone added after the model got something wrong:
 *
 *   - findings and techniques are REPLACED, IOCs and events PRESERVED (a text-only pass cannot
 *     re-derive 400 hashes a THOR import found)
 *   - anything the analyst confirmed a false positive is dropped again even if the model re-added it
 *   - every Critical/High event the model left uncovered gets a finding anyway
 *   - a key question that still cites a rejected finding is forced back to "unknown"
 *   - an answer asserting an absence the timeline contradicts is downgraded to "partial"
 *   - an uncited, single-source or intel-only finding has its confidence and severity capped
 *
 * Every one of them only ever LOWERS a claim. That is the invariant worth protecting here: the
 * deterministic passes can refuse to believe the model, never the other way round.
 */

/** Keep analyst-pinned questions across a synthesis (it replaces keyQuestions wholesale). */
function mergePinnedQuestions(
  pinned: InvestigationQuestion[],
  current: InvestigationQuestion[],
): InvestigationQuestion[] {
  if (pinned.length === 0) return current;
  const byId = new Map(current.map((q) => [q.id, q]));
  for (const p of pinned) {
    const cur = byId.get(p.id);
    byId.set(p.id, cur ? { ...cur, pinned: true } : p);
  }
  return [...byId.values()];
}

/** What folding one delta needs. No providers and no AI — this half never calls a model. */
export interface DeltaFoldContext {
  readonly opts: { stateStore: StateStore };
  mergeWithAliases(
    state: InvestigationState,
    delta: Parameters<typeof mergeDelta>[1],
    ctx: WindowContext,
  ): Promise<InvestigationState>;
}

export interface DeltaFoldInput {
  caseId: string;
  /** The correlated pre-call snapshot the model reasoned over. */
  state: InvestigationState;
  delta: ReturnType<typeof deltaSchema.parse>;
  markers: FalsePositiveMarker[];
  scopedEvents: ForensicEvent[];
  playbookTasks: PlaybookTask[];
}

export interface DeltaFoldResult {
  next: InvestigationState;
  /** How many findings the safety net had to add — a proxy for what the model missed (#74). */
  highSeverityBackfillCount: number;
  /** The scoped event ids synthesis considered; the grading pass grounds against these. */
  eligibleIds: Set<string>;
  /** Delta finding ids that survived the false-positive filter. */
  surviving: Set<string>;
}

/**
 * The fixed sequence, in order. Each step is one deterministic correction; the order matters and is
 * pinned by `synthesizeCharacterisation`, so read this as the spec and the helpers below as detail.
 *
 * Dry run (second-opinion Pass 1) uses the same path: the result is returned WITHOUT persisting or
 * any side effect, and without folding in accepted deltas, so model B stays an independent opinion.
 */
export async function foldSynthesisDelta(
  ctx: DeltaFoldContext,
  input: DeltaFoldInput,
): Promise<DeltaFoldResult> {
  const { caseId, state, delta, markers, scopedEvents, playbookTasks } = input;
  // Anchor finding timestamps to the last real event time (fallback: existing state time).
  const ts = state.forensicTimeline[state.forensicTimeline.length - 1]?.timestamp || state.updatedAt;
  const merged = await replaceConclusions(ctx, state, delta, ts);
  // Safety net: drop anything confirmed false-positive even if the model re-introduced it.
  const filtered = applyFalsePositive(merged, markers);
  const surviving = new Set(filtered.findings.map((f) => f.id));
  const linked = linkEventsToFindings(filtered, delta, surviving);

  // The backfills are restricted to the events synthesis actually considered.
  const eligibleIds = new Set(scopedEvents.map((e) => e.id));
  const netted = applyBackfills(linked, scopedEvents, eligibleIds, ts);
  const pinned = await preservePinnedQuestions(ctx, caseId, netted.state);
  let next = correctKeyQuestions(pinned, state, scopedEvents);
  // Union the deterministically-identified ATT&CK techniques carried by the (in-scope) timeline into
  // the synthesized MITRE table, so techniques the model didn't echo — especially the Info/Low
  // discovery phase (whoami/net group/findstr password/cat .env) tagged by the importers — still
  // appear in the case's MITRE table and report. Same scoped events synthesis saw; pure + idempotent.
  next = { ...next, mitreTechniques: unionEventTechniques(next.mitreTechniques, scopedEvents) };
  next = demoteCompletedSteps(next, playbookTasks);

  return {
    next,
    highSeverityBackfillCount: netted.highSeverityBackfillCount,
    eligibleIds,
    surviving,
  };
}

/**
 * Synthesis is an authoritative holistic reassessment: replace the CONCLUSIONS (findings, MITRE
 * techniques) rather than accumulate, so anything no longer supported by the in-scope timeline (e.g.
 * out-of-scope or removed events) is dropped.
 *
 * IOCs are OBSERVED INDICATORS (often from deterministic imports like THOR — 100s of hashes the
 * text-only synthesis can't re-derive), so they are PRESERVED and merged (deduped by value);
 * scope/legitimate still filter them at projection. Threads and the forensic timeline are preserved.
 */
function replaceConclusions(
  ctx: DeltaFoldContext,
  state: InvestigationState,
  delta: DeltaFoldInput["delta"],
  ts: string,
): Promise<InvestigationState> {
  const base = { ...state, findings: [], mitreTechniques: [] };
  return ctx.mergeWithAliases(base, delta, {
    windowSequence: 0,
    timestamp: ts,
    sourceScreenshots: [],
  });
}

/**
 * Back-link forensic events to the CORRECT findings using the synthesis output (each finding lists
 * the event ids it's based on). Replaces the extraction pass's guesses.
 */
function linkEventsToFindings(
  filtered: InvestigationState,
  delta: DeltaFoldInput["delta"],
  surviving: Set<string>,
): InvestigationState {
  const eventToFindings = new Map<string, string[]>();
  for (const f of delta.findings) {
    if (!surviving.has(f.id)) continue;
    for (const eid of f.relatedEventIds ?? []) {
      const arr = eventToFindings.get(eid) ?? [];
      if (!arr.includes(f.id)) arr.push(f.id);
      eventToFindings.set(eid, arr);
    }
  }
  return {
    ...filtered,
    forensicTimeline: filtered.forensicTimeline.map((e) => ({
      ...e,
      relatedFindingIds: eventToFindings.get(e.id) ?? [],
    })),
  };
}

/**
 * The two heuristic safety nets, in order.
 *
 * A Critical/High artifact row is almost always a finding: any in-scope, non-legitimate
 * high-severity event that synthesis left WITHOUT one gets it auto-created, so a severe detection
 * can never be silently missed. How many had to be added (#74) is a proxy for what the model missed.
 *
 * Log gap analysis (#83): a COMPLETE-silence gap — a window where every source went dark — is the
 * classic signature of cleared logs / a stopped collector, so it is escalated to a finding too. Gaps
 * are derived on read (not persisted); only the complete ones earn a persisted finding, and the
 * finding id is derived from the bounding events, so re-synthesis over the same gap is idempotent.
 */
function applyBackfills(
  linked: InvestigationState,
  scopedEvents: ForensicEvent[],
  eligibleIds: Set<string>,
  ts: string,
): { state: InvestigationState; highSeverityBackfillCount: number } {
  const backfilled = backfillHighSeverityFindings(linked, eligibleIds, ts);
  const highSeverityBackfillCount = backfilled.findings.length - linked.findings.length;
  const gapOpts = gapEnvOptions();
  const gaps = detectTimelineGaps(scopedEvents, gapOpts);
  return {
    state: backfillSilenceGapFindings(backfilled, gaps, ts, gapOpts.maxFindings),
    highSeverityBackfillCount,
  };
}

/**
 * Preserve analyst-pinned questions (synthesis replaces keyQuestions wholesale). Re-reads the LATEST
 * state, not the pre-AI snapshot, so a question added DURING the seconds-long AI call isn't
 * clobbered by this write (read-modify-write race).
 */
async function preservePinnedQuestions(
  ctx: DeltaFoldContext,
  caseId: string,
  gapFilled: InvestigationState,
): Promise<InvestigationState> {
  const pinnedNow = (await ctx.opts.stateStore.load(caseId)).keyQuestions.filter((q) => q.pinned);
  if (!pinnedNow.length) return gapFilled;
  return { ...gapFilled, keyQuestions: mergePinnedQuestions(pinnedNow, gapFilled.keyQuestions) };
}

/**
 * Deterministic backstop for the prompt's reanswerBlock instruction: if the model still cited a
 * now-dead finding — whether via a structured relatedFindingIds link or only in the free-text
 * pointer/answer prose (the only signal available for a question predating relatedFindingIds) —
 * force the question back to "unknown", clearing the stale answer. ANY dependency on a rejected
 * finding forces the reset, not just total loss of support: a partial answer that still names a
 * finding the analyst just confirmed is NOT a threat is misleading even when another finding also
 * backs it, and we can't safely guess what the finding-minus-the-FP'd-one answer should say without
 * asking the model again. Shared with the FP-mark route's synchronous cascade
 * (investigation-guidance #12); here it runs as the AUTHORITATIVE recompute (staleReSynth off →
 * clears any interim stale badge), guaranteeing a key question can never keep citing a dead finding.
 *
 * Then the answer-contradiction validator (investigation-guidance #3): a key question whose answer
 * asserts an ABSENCE ("no data exfiltration confirmed") while in-scope events carry the matching
 * ATT&CK techniques is a dangerous false negative — force it to "partial" and cite the contradicting
 * events. Runs AFTER the FP reset so a reset-to-unknown answer isn't re-flagged. Pure + idempotent.
 */
function correctKeyQuestions(
  next: InvestigationState,
  priorState: InvestigationState,
  scopedEvents: ForensicEvent[],
): InvestigationState {
  const reconsidered = reconsiderKeyQuestions(next.keyQuestions, {
    survivingFindingIds: new Set(next.findings.map((f) => f.id)),
    priorFindingIds: priorState.findings.map((f) => f.id), // ids that existed going into this run
  }).questions;
  return { ...next, keyQuestions: flagContradictedAnswers(reconsidered, scopedEvents) };
}

/**
 * Prior-work safety net (investigation-guidance #2): even with the PLAYBOOK PROGRESS prompt block,
 * the model may still echo a nextStep that repeats a COMPLETED task. Deterministically DEMOTE (not
 * drop) any such step to priority "low" with an annotation, requiring a shared host/artifact token so
 * a same-verb different-target step survives. Keeps the top of the next-steps list actionable.
 */
function demoteCompletedSteps(next: InvestigationState, playbookTasks: PlaybookTask[]): InvestigationState {
  if (!playbookTasks.length) return next;
  const doneTitles = playbookTasks.filter((t) => t.status === "done").map((t) => t.title);
  if (!doneTitles.length) return next;
  const { steps, demotedIds } = demoteCompletedNextSteps(next.nextSteps, doneTitles);
  return demotedIds.length ? { ...next, nextSteps: steps } : next;
}

export interface FindingGradeInput {
  next: InvestigationState;
  delta: ReturnType<typeof deltaSchema.parse>;
  surviving: Set<string>;
  eligibleIds: Set<string>;
  sourceTrust: SourceTrustMap;
  kevCatalog: KevCatalog | undefined;
  aliasIndex?: HostAliasIndex;
}

/**
 * Grade the FINAL finding set: ground each finding in its supporting events, roll up corroboration,
 * cap what is uncited or intel-only, and place each one relative to the main attack component.
 *
 * Runs last so it sees the backfills and any accepted second-opinion deltas. Deterministic and
 * idempotent, and — the property that makes it safe to run over model output — it only ever lowers
 * a confidence or a severity. The AI's own relevance verdict can refine a disconnected finding into
 * "a genuine separate issue", but it can never upgrade a rabbit hole into a lead.
 */
export function gradeFindings(input: FindingGradeInput): InvestigationState {
  const { delta, surviving, eligibleIds, sourceTrust, kevCatalog } = input;
  const next = input.next;
  const evidenceGraph = buildEvidenceGraph(next);
  const inScope = next.forensicTimeline.filter((e) => eligibleIds.has(e.id));
  const hostNames = new Set(
    buildAssetGraph(next, undefined, input.aliasIndex)
      .assets.filter((a) => a.type === "host")
      .map((a) => shortHost(a.name)),
  );

  const grounded = groundAndScoreFindings({
    findings: next.findings,
    scopedEvents: inScope,
    iocs: next.iocs,
    graphLinkedEventIds: new Set(evidenceGraph.edges.flatMap((e) => e.eventIds)),
    kevCveIds: collectKevCveIds(inScope, next.iocs, kevCatalog),
    sourceTrust,
  });
  // Intel-verdict gate (investigation-guidance #7): floor an intel-ONLY High/Critical finding (no
  // behavioral corroboration, all its verdict IOCs lone-intel/conflicted) to Medium/≤60 — the
  // northpeak stale-CTI-on-own-server class. Runs after grounding so it sees the corroboration rollup.
  const capped = capIntelOnlyFindings({
    findings: grounded,
    iocs: next.iocs,
    scopedEvents: inScope,
    hostNames,
  });
  const scored = {
    ...next,
    findings: scoreFindingsRelevance({
      findings: capped,
      scopedEvents: inScope,
      graph: evidenceGraph,
      aiRelevanceById: aiRelevanceOf(delta, surviving),
    }),
  };
  return addCorroborationSteps(scored, inScope, hostNames);
}

/**
 * KEV-linked confidence signal (issue #61): the CVEs mentioned in-scope (events + IOCs) that match
 * the CISA KEV catalog. Undefined when no catalog is loaded, so the signal is simply never set then.
 */
function collectKevCveIds(
  inScope: ForensicEvent[],
  iocs: InvestigationState["iocs"],
  kevCatalog: KevCatalog | undefined,
): Set<string> | undefined {
  if (!kevCatalog || kevCatalog.size === 0) return undefined;
  const cveIds = new Set<string>();
  for (const e of inScope) {
    extractCveIds(e.description).forEach((id) => cveIds.add(id));
    if (e.message) extractCveIds(e.message).forEach((id) => cveIds.add(id));
  }
  for (const i of iocs) extractCveIds(i.value).forEach((id) => cveIds.add(id));
  return new Set(matchKevEntries([...cveIds], kevCatalog).map((m) => m.cveID));
}

/**
 * Rabbit-hole detection (investigation-guidance #13): the model's per-finding relevance verdict,
 * which refines a graph-DISCONNECTED finding into 'unrelated-but-real' (a genuine separate issue)
 * vs undetermined noise. The deterministic component linkage stays authoritative — this can only
 * explain a disconnected finding, never upgrade a rabbit hole into a lead.
 */
function aiRelevanceOf(
  delta: FindingGradeInput["delta"],
  surviving: Set<string>,
): Map<string, "connected" | "unrelated-but-real" | "undetermined"> {
  return new Map(
    (delta.findings ?? [])
      .filter(
        (f): f is typeof f & { relevance: "connected" | "unrelated-but-real" | "undetermined" } =>
          !!f.relevance && surviving.has(f.id),
      )
      .map((f) => [f.id, f.relevance] as const),
  );
}

/**
 * Auto "corroborate <ioc>" next-steps (investigation-guidance #7, deferred): for every finding the
 * intel gate just floored to intel-only, add a concrete "go get the behavioral evidence" step so the
 * capped lead becomes a directed action, not a dead end. Idempotent ids; prepended so the
 * verification steps sit near the top, skipping any step the model already emitted with the same id.
 */
function addCorroborationSteps(
  next: InvestigationState,
  inScope: ForensicEvent[],
  hostNames: Set<string>,
): InvestigationState {
  const steps = buildIntelCorroborationSteps({
    findings: next.findings,
    iocs: next.iocs,
    scopedEvents: inScope,
    hostNames,
  });
  if (!steps.length) return next;
  const existing = new Set((next.nextSteps ?? []).map((s) => s.id));
  const fresh = steps.filter((s) => !existing.has(s.id));
  return fresh.length ? { ...next, nextSteps: [...fresh, ...(next.nextSteps ?? [])] } : next;
}
