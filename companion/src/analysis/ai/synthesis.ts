import { createHash } from "node:crypto";
import type { AIProvider } from "../../providers/provider.js";
import type { Logger } from "../../logging/logger.js";
import { recordSynthesisRun } from "../analysisRunRecorders.js";
import type { AnalysisRunStore } from "../analysisRunStore.js";
import type { AiControlStore } from "../aiControl.js";
import { toAnonPolicy, type AnonControlStore } from "../anonControl.js";
import { alignedEpoch, detectClockSkew, effectiveOffsets } from "../clockSkew.js";
import type { ClockSkewStore } from "../clockSkewStore.js";
import { correlateEvents, correlationGroups, type CorrelateOptions } from "../correlate.js";
import { CorrelationProfileStore } from "../correlationProfile.js";
import { filterFalsePositiveEvents } from "../falsePositive.js";
import { diffFindings, type FindingsDiff } from "../findingsDiff.js";
import { sortByEventTime } from "../forensicSort.js";
import { renderPriorHuntsBlock } from "../huntOutcomes.js";
import { sanitizeHypotheses } from "../hypothesis.js";
import type { HypothesisStore } from "../hypothesisStore.js";
import type { IncidentTypeStore } from "../incidentTypeStore.js";
import { renderIncidentTypeBlock } from "../incidentTypes.js";
import { rankConnectiveIocs } from "../iocAnchors.js";
import type { NotebookStore } from "../notebookStore.js";
import type { PlaybookStore } from "../playbookStore.js";
import { renderPlaybookProgressBlock, renderRefutedHypothesesBlock } from "../priorWork.js";
import { deltaSchema, stripAiExtractedFrom } from "../responseSchema.js";
import { filterEventsByScope, hasScope, NO_SCOPE, type ScopeWindow } from "../scope.js";
import {
  buildSecondLookPlan,
  buildSecondLookRequests,
  deriveWindow,
  resolveSecondLookRequests,
  summarizeSecondLook,
  type ModelEvidenceRequest,
} from "../secondLook.js";
import { applyAcceptedSecondOpinion } from "../secondOpinion.js";
import type { SecondOpinionStore } from "../secondOpinionStore.js";
import { effectiveTrustMap } from "../sourceTrust.js";
import type { SourceTrustStore } from "../sourceTrustStore.js";
import type { StateLock } from "../stateLock.js";
import { mergeDelta, type WindowContext } from "../stateMerge.js";
import type { ForensicEvent, InvestigationState, TimelineEntry } from "../stateTypes.js";
import type { SuperTimelineStore } from "../superTimelineStore.js";
import type { SecondLookMeta, SynthMetaStore } from "../synthMeta.js";
import { resolveSynthThinkingBudget, type SynthThinkingInput } from "../synthThinking.js";
import { getSynthesisPrompt } from "./prompts/index.js";
import type { AiCallContext } from "./aiContext.js";
import { loadHuntOutcomes, type HuntContext } from "./hunts.js";
import { buildSynthesisPrompt, type SynthesisPromptContext } from "./synthesisPrompt.js";
import { foldSynthesisDelta, gradeFindings } from "./synthesisMerge.js";

/**
 * Synthesis: the AI call that turns the case's timeline into its conclusions (#418).
 *
 * The last and hardest of the extractions this issue owns, and the one #384 stopped short of. It is
 * hard because this is not a report — it REWRITES the case. Findings and ATT&CK techniques are
 * replaced wholesale, key questions are re-answered, IOCs are preserved and merged, and the write
 * has to survive whatever an import or an analyst did during the seconds the model was thinking.
 *
 * Prompt construction and the coverage audit live in ai/synthesisPrompt.ts. What is left here is the
 * orchestration: load, correlate, decide whether to run at all, call, fold the delta back in,
 * persist under the lock, record, notify, and sweep once for what the sampler did not show.
 *
 * WHY THE CONTEXT IS SO WIDE. Every other family in this directory takes a narrow interface because
 * a report genuinely touches little. Synthesis touches most of PipelineOptions, and pretending
 * otherwise by threading twenty parameters would hide that rather than fix it. The interface still
 * earns its place: it names exactly which stores participate, so adding one to synthesis becomes a
 * visible edit here instead of an invisible reach through `this`.
 */

/** What synthesis needs. Wide by nature — see the note above. */
export interface SynthesisContext extends AiCallContext, HuntContext, SynthesisPromptContext {
  readonly log: Logger;
  readonly opts: AiCallContext["opts"] &
    HuntContext["opts"] &
    SynthesisPromptContext["opts"] & {
      provider?: AIProvider;
      correlationProfileStore?: CorrelationProfileStore;
      sourceTrustStore?: SourceTrustStore;
      clockSkewStore?: ClockSkewStore;
      notebookStore?: NotebookStore;
      aiControlStore?: AiControlStore;
      hypothesisStore?: HypothesisStore;
      playbookStore?: PlaybookStore;
      incidentTypeStore?: IncidentTypeStore;
      secondOpinionStore?: SecondOpinionStore;
      superTimelineStore?: SuperTimelineStore;
      synthMetaStore?: SynthMetaStore;
      analysisRunStore?: AnalysisRunStore;
      anonStore?: AnonControlStore;
      stateLock?: StateLock;
      synthesisModelLabel?: string;
      onSynth?: (caseId: string, diff: FindingsDiff, state: InvestigationState) => void;
      onState?: (state: InvestigationState) => void;
    };
  /** mergeDelta plus the case's analyst IOC-merge aliases (#82). */
  mergeWithAliases(
    state: InvestigationState,
    delta: Parameters<typeof mergeDelta>[1],
    ctx: WindowContext,
  ): Promise<InvestigationState>;
  /** Promote raw super-timeline rows into the forensic timeline — the second-look sweep's seam. */
  promoteSuperTimeline(
    caseId: string,
    events: ForensicEvent[],
    opts: { importedAt: string; tagById?: Record<string, string[]>; note?: string },
  ): Promise<InvestigationState>;
  /** Once per process: warn that a configured prompt override is missing shipped capabilities. */
  warnOnPromptDrift(): void;
  /**
   * Hash of the last successfully-synthesized inputs per case. Owned by the pipeline so it lives as
   * long as the process does: a fresh process (or an explicit `force`) always synthesizes.
   */
  readonly lastSynthHash: Map<string, string>;
}

async function detectSkew(
  ctx: SynthesisContext,
  caseId: string,
  preMerge: ForensicEvent[],
  opts: CorrelateOptions,
): Promise<((e: ForensicEvent) => number | undefined) | undefined> {
  const store = ctx.opts.clockSkewStore;
  if (!store) return undefined;
  let record;
  try {
    const report = detectClockSkew(correlationGroups(preMerge, { ...opts, crossHostArtifacts: true }), opts);
    record = await store.recordDetection(caseId, report);
  } catch {
    try {
      record = await store.load(caseId);
    } catch {
      return undefined;
    }
  }
  if (!record.alignEnabled) return undefined;
  const offsets = effectiveOffsets(record.results, record.overrides);
  if (offsets.size === 0) return undefined;
  return (e: ForensicEvent) => alignedEpoch(e, offsets);
}

export async function synthesize(
  ctx: SynthesisContext,
  caseId: string,
  opts: {
    force?: boolean;
    dryRun?: boolean;
    provider?: AIProvider;
    signal?: AbortSignal;
    skipSecondLook?: boolean;
    observationsBlock?: string;
    analysisParentRunId?: string;
  } & SynthThinkingInput = {},
): Promise<InvestigationState> {
  const observationsBlock = opts.observationsBlock ?? "";
  const synthProvider = opts.provider ?? ctx.opts.synthesisProvider ?? ctx.requireProvider("synthesis");
  ctx.warnOnPromptDrift(); // once per process: a stale synthesis-prompt override silently drops shipped capabilities
  const loaded = await ctx.opts.stateStore.load(caseId);
  if (loaded.forensicTimeline.length === 0) return loaded;

  // Correlate the same artifact across tools first: deduplicate into one corroborated event and
  // one finding with both sources. This is idempotent and the correlated timeline is persisted.
  const envWindow = Number(process.env.DFIR_CORRELATE_WINDOW_S);
  const corrProfile = await ctx.opts.correlationProfileStore?.load(caseId);
  const windowSeconds = Number.isFinite(envWindow) ? envWindow : (corrProfile?.windowSeconds ?? 2);
  // Source trust (#66) selects merge wording and caps low-trust-only findings.
  const trustOverrides = ctx.opts.sourceTrustStore ? await ctx.opts.sourceTrustStore.load(caseId) : undefined;
  const sourceTrust = effectiveTrustMap(trustOverrides);
  // Measure clock skew pre-merge (#228), before correlation erases the disagreeing anchors.
  // Aligned times guide windows; persisted events retain recorded timestamps.
  const skew = await detectSkew(ctx, caseId, loaded.forensicTimeline, { windowSeconds, sourceTrust });
  const state: InvestigationState = {
    ...loaded,
    forensicTimeline: correlateEvents(loaded.forensicTimeline, { windowSeconds, sourceTrust, epochOf: skew }),
  };

  const markers = ctx.opts.falsePositiveStore ? await ctx.opts.falsePositiveStore.load(caseId) : [];

  // Scope: only events inside the investigation window feed synthesis, so
  // findings/IOCs/attacker-path/questions reflect only in-scope activity.
  // Then drop events the client confirmed legitimate so the model never derives
  // conclusions from benign activity (the raw events stay in state — reversible).
  const scope = ctx.opts.scopeStore ? await ctx.opts.scopeStore.load(caseId) : NO_SCOPE;
  // Split the two filter stages so the coverage audit (#62) can attribute omissions: `inWindowEvents`
  // is after the scope filter (out-of-window events dropped); `scopedEvents` is after the additional
  // false-positive/legitimate filter. The budget cap below drops the rest from the prompt.
  const inWindowEvents = filterEventsByScope(state.forensicTimeline, scope);
  const scopedEvents = filterFalsePositiveEvents(inWindowEvents, markers);

  // Analyst notebook context: when both notebookStore and aiControlStore are wired and the
  // analyst has opted in (includeNotebook: true in ai-control.json), append the notebook
  // entries to the synthesis prompt so the AI incorporates investigator hypotheses.
  // Loaded here (before the hash) so notebook changes also trigger a fresh synthesis.
  let notebookBlock = "";
  if (ctx.opts.notebookStore && ctx.opts.aiControlStore) {
    const aiCtrl = await ctx.opts.aiControlStore.load(caseId);
    if (aiCtrl.includeNotebook) {
      const notebookEntries = await ctx.opts.notebookStore.load(caseId);
      if (notebookEntries.length) {
        notebookBlock =
          "ANALYST NOTEBOOK (investigator notes and open questions — take these into account when synthesizing findings and the attacker path):\n" +
          notebookEntries.map((e) => `[${e.type.toUpperCase()}] ${e.text}`).join("\n") +
          "\n\n";
      }
    }
  }

  // Analyst hypotheses as steering (issue #140): feed the investigator's OPEN, analyst-owned
  // hypotheses into the prompt so the model actively hunts evidence to support/refute them and
  // reflects it in findings/events + its own hypotheses output. We do NOT ask it to flip the
  // analyst's hypothesis status — those are frozen by mergeHypotheses (the analyst stays in
  // control); the steering shows up as findings/events the analyst then uses to judge. Only
  // analyst-authored or analyst-touched OPEN ones (pure inputs, never rewritten by synthesis),
  // so including them in the hash below can't cause a re-synthesis loop. Bounded for prompt size.
  let analystHypothesesBlock = "";
  // Refuted hypotheses fed back as NEGATIVE KNOWLEDGE (investigation-guidance #2): a theory the
  // analyst ruled out must not be re-asserted or re-opened. Loaded from the same store, once.
  let refutedHypothesesBlock = "";
  if (ctx.opts.hypothesisStore) {
    // ACH exhaustion (investigation-guidance #14): before reading, flag hypotheses whose linked or
    // technique-matched hunts have come back empty — so the negative-knowledge block below and the
    // "to test" list reflect them. Derived from collected hunt outcomes; persisted; idempotent.
    const exhaustionOutcomes = await loadHuntOutcomes(ctx, caseId);
    const huntSignals = exhaustionOutcomes
      .filter((o) => o.status === "collected")
      .map((o) => ({
        ...(o.relatedHypothesisId ? { relatedHypothesisId: o.relatedHypothesisId } : {}),
        techniques: o.mitreTechniques ?? [],
        missed: o.foundEvidence === false,
        title: o.title,
      }));
    if (huntSignals.some((s) => s.missed))
      await ctx.opts.hypothesisStore.applyExhaustion(caseId, huntSignals);

    const allHypotheses = await ctx.opts.hypothesisStore.load(caseId);
    const open = allHypotheses
      .filter((h) => h.status === "open" && !h.exhausted && (h.source === "analyst" || h.analystTouched))
      .slice(0, 15);
    if (open.length) {
      analystHypothesesBlock =
        "ANALYST HYPOTHESES TO TEST (the investigator proposed these — actively look for evidence that " +
        "SUPPORTS or REFUTES each and surface it in findings/events; you may add a corroborating hypothesis, " +
        "but do NOT mark the analyst's own hypothesis resolved):\n" +
        open
          .map((h) => `- ${h.title}${h.expectedOutcome ? ` (decided by: ${h.expectedOutcome})` : ""}`)
          .join("\n") +
        "\n\n";
    }
    refutedHypothesesBlock = renderRefutedHypothesesBlock(allHypotheses);
  }

  // Prior-work feedback (investigation-guidance #2): the hunt hit/miss ledger (#157, previously fed
  // only to the hunt prompts) and the playbook DONE/SKIPPED digest, so synthesis builds on completed
  // work and dead hunts instead of re-recommending them. Loaded before the hash so completing a task
  // or collecting a hunt triggers a fresh synthesis (a hit is a pivot; a miss is negative evidence).
  const priorHuntsBlock = renderPriorHuntsBlock(await loadHuntOutcomes(ctx, caseId));
  const playbookTasks = ctx.opts.playbookStore ? await ctx.opts.playbookStore.load(caseId) : [];
  const playbookProgressBlock = renderPlaybookProgressBlock(playbookTasks);

  // Incident-type framing (#236): the one-line hint for the type the analyst picked at case
  // creation, so the model prioritizes ransomware / BEC / exfil techniques. A pure INPUT synthesis
  // never rewrites, and cheap (one short line) — but changing the type must re-synthesize, so it
  // joins the skip-if-unchanged hash below.
  const incidentTypeBlock = renderIncidentTypeBlock(
    ctx.opts.incidentTypeStore ? await ctx.opts.incidentTypeStore.loadType(caseId) : null,
  );

  // Skip-if-unchanged: hash only the STABLE INPUTS to synthesis — the in-scope timeline,
  // the IOCs (value + intel verdicts), the scope, the legitimate markers, and (when opted
  // in) the notebook entries. NOT the findings / MITRE / threads / summary, which synthesis
  // itself rewrites (including those would make two consecutive runs hash differently and
  // never skip). If the inputs are identical to the last successful run, return the saved
  // state — no AI call.
  const synthHash = createHash("sha1")
    .update(
      JSON.stringify({
        ev: scopedEvents.map((e) => [e.id, e.severity, e.timestamp, e.description]),
        io: state.iocs.map((i) => [i.id, i.value, (i.enrichments ?? []).map((e) => e.verdict).join(",")]),
        sc: scope,
        lg: markers.map((m) => m.id),
        nb: notebookBlock,
        hy: analystHypothesesBlock,
        // Prior-work feedback (#2): completing a task, collecting a hunt, or refuting a hypothesis
        // changes these strings, so an otherwise-identical timeline re-synthesizes to fold in the
        // new negative knowledge instead of skipping. Pure inputs — synthesis never rewrites them.
        pw: priorHuntsBlock + playbookProgressBlock + refutedHypothesesBlock,
        // Re-picking the incident type reframes what the model should prioritize — an otherwise
        // identical timeline must re-synthesize rather than skip.
        it: incidentTypeBlock,
        // Deep-pass observations are a pure INPUT synthesis never rewrites, but they change what the
        // model can see — so a run carrying fresh ones must never be skipped as "inputs unchanged".
        ob: observationsBlock,
      }),
    )
    .digest("hex");
  if (!opts.force && !opts.dryRun && ctx.lastSynthHash.get(caseId) === synthHash) return loaded;

  // The prompt, and the coverage audit that describes exactly what it showed the model.
  const {
    userPrompt,
    representedEvents,
    shownIds,
    selection,
    coverage: synthCoverage,
    maxEvents: SYNTH_MAX_EVENTS,
    omittedInfo,
  } = await buildSynthesisPrompt(ctx, {
    caseId,
    state,
    scope,
    markers,
    inWindowEvents,
    scopedEvents,
    observationsBlock,
    notebookBlock,
    analystHypothesesBlock,
    refutedHypothesesBlock,
    priorHuntsBlock,
    playbookProgressBlock,
    incidentTypeBlock,
  });

  const synthStart = Date.now();
  const retries = ctx.opts.retries ?? 3;
  const backoffMs = ctx.opts.backoffMs ?? 500;
  // Chain-of-Thought / extended thinking for the complex synthesis call (issue #121, feature 1).
  // Budget resolved per-run: an explicit value or the dashboard "deep reasoning" toggle wins, else
  // the global DFIR_AI_SYNTH_THINKING_TOKENS default (off when unset). The Anthropic provider maps
  // it to extended thinking; OpenRouter to its unified `reasoning`; other providers ignore it. Only
  // synthesis reasons step-by-step — extraction stays cheap.
  const synthThinkingTokens = resolveSynthThinkingBudget(
    opts,
    Number(process.env.DFIR_AI_SYNTH_THINKING_TOKENS) || 0,
  );
  // Per-model quality telemetry (#74): count retries the synthesis call actually needed (a failed
  // parse/schema-mismatch attempt increments this). Counted on catch INSIDE the retried closure
  // rather than via ctx.withRetry's onRetry hook, because that hook is the shared server-logging
  // callback — routing through ctx.withRetry keeps master's per-attempt WARN logging intact while
  // the local catch keeps the count. Surfaced on synth-meta so a flaky model shows up empirically.
  let synthParseRetries = 0;
  const delta = await ctx.withRetry(
    caseId,
    "synthesis",
    async () => {
      try {
        const parsed = await ctx.analyzeRestored(
          caseId,
          state,
          synthProvider,
          {
            systemPrompt: getSynthesisPrompt(),
            userPrompt,
            images: [],
            ...(synthThinkingTokens > 0 ? { thinkingTokens: synthThinkingTokens } : {}),
            ...(opts.signal ? { signal: opts.signal } : {}),
          },
          "synthesis",
        );
        return stripAiExtractedFrom(deltaSchema.parse(parsed));
      } catch (err) {
        synthParseRetries++;
        throw err;
      }
    },
    retries,
    backoffMs,
  );

  const {
    next: folded,
    highSeverityBackfillCount,
    eligibleIds,
    surviving,
  } = await foldSynthesisDelta(ctx, {
    caseId,
    state,
    delta,
    markers,
    scopedEvents,
    playbookTasks,
  });
  let next = folded;
  if (opts.dryRun) return next;

  // Durability (issue #116): re-apply any analyst-ACCEPTED second-opinion deltas after the
  // wholesale findings rewrite, so a confirmed model-B finding/severity/technique is never lost
  // on re-synthesis. Pure + idempotent; a no-op when the store or record is absent/empty.
  if (ctx.opts.secondOpinionStore) {
    next = applyAcceptedSecondOpinion(next, await ctx.opts.secondOpinionStore.load(caseId));
  }

  // Per-finding grounding + corroboration (investigation-guidance #6): resolve each finding's
  // supporting in-scope events (forward relatedEventIds AND reverse forensicTimeline links, so the
  // deterministic backfill findings ground correctly), roll up { tools, hosts, intel, graph-linked },
  // flag an uncited finding as `ungrounded`, and CAP an ungrounded/single-source finding's confidence.
  // Also catches the subtler case where cited ids resolve but the finding's own claimed IP never
  // appears in their text (`contentMismatch`) — floors High/Critical to Medium (veridia-deep-pass
  // 2026-07-22). Deterministic + idempotent; only ever lowers confidence/severity. Runs last, so it
  // grades the FINAL finding set (incl. backfills + accepted second-opinion deltas).
  next = gradeFindings({
    next,
    delta,
    surviving,
    eligibleIds,
    sourceTrust,
    kevCatalog: await ctx.getKevCatalog(),
  });

  // What this run changed vs the pre-AI findings. Findings are FINAL here — neither persistLatest
  // nor the hypothesis auto-gen below touch them — so it's computed once and reused for the
  // Investigation-Log entry (#165), the synth-meta record, and the notify hook.
  const findingsDiff = diffFindings(loaded.findings, next.findings);

  // Lost-update guard (mirrors the pinned-questions re-load above): a manual event/IOC/thread
  // added DURING the seconds-long AI call would otherwise be clobbered by this write, because
  // `next` was derived from the snapshot taken before the call. Re-read the LATEST state and
  // carry forward only items NEW since that snapshot (by id/value), so synthesis's conclusions
  // and its correlation/legitimate work on the snapshot timeline are preserved while concurrent
  // analyst additions survive. Reference the RAW snapshot (`loaded`), not the in-memory
  // correlated `state`, so events deduped by correlateEvents aren't re-added.
  const persistLatest = async () => {
    const latest = await ctx.opts.stateStore.load(caseId);
    const snapEventIds = new Set(loaded.forensicTimeline.map((e) => e.id));
    const nextEventIds = new Set(next.forensicTimeline.map((e) => e.id));
    const addedEvents = latest.forensicTimeline.filter(
      (e) => !snapEventIds.has(e.id) && !nextEventIds.has(e.id),
    );
    const snapIocVals = new Set(loaded.iocs.map((i) => i.value.toLowerCase()));
    const nextIocVals = new Set(next.iocs.map((i) => i.value.toLowerCase()));
    const latestIocByVal = new Map(latest.iocs.map((i) => [i.value.toLowerCase(), i]));
    const mergedIocs = [
      ...next.iocs.map((i) => latestIocByVal.get(i.value.toLowerCase()) ?? i),
      ...latest.iocs.filter(
        (i) => !snapIocVals.has(i.value.toLowerCase()) && !nextIocVals.has(i.value.toLowerCase()),
      ),
    ];
    const snapThreadIds = new Set(loaded.openThreads.map((t) => t.id));
    const nextThreadIds = new Set(next.openThreads.map((t) => t.id));
    const addedThreads = latest.openThreads.filter(
      (t) => !snapThreadIds.has(t.id) && !nextThreadIds.has(t.id),
    );
    // Investigation Log (#165): carry forward any timeline line a CONCURRENT import appended during
    // the AI call (dedupe by timestamp+sequence+text), so the synthesis write doesn't clobber it.
    const tlKey = (t: TimelineEntry) => `${t.timestamp}|${t.windowSequence}|${t.description}`;
    const snapTimeline = new Set(loaded.timeline.map(tlKey));
    const nextTimeline = new Set(next.timeline.map(tlKey));
    const addedTimeline = latest.timeline.filter(
      (t) => !snapTimeline.has(tlKey(t)) && !nextTimeline.has(tlKey(t)),
    );
    next = {
      ...next,
      forensicTimeline: addedEvents.length
        ? sortByEventTime([...next.forensicTimeline, ...addedEvents])
        : next.forensicTimeline,
      iocs: mergedIocs,
      openThreads: addedThreads.length ? [...next.openThreads, ...addedThreads] : next.openThreads,
      timeline: addedTimeline.length ? [...next.timeline, ...addedTimeline] : next.timeline,
    };
    // Record THIS synthesis run as a durable, cross-session Investigation-Log line (#165) — imports
    // already log via timelineNote; synthesis didn't. Final merged counts; one entry per real run.
    const synthLogEntry: TimelineEntry = {
      timestamp: new Date().toISOString(),
      windowSequence: 0,
      description:
        `Synthesis: ${next.findings.length} finding(s) (${findingsDiff.added.length} new, ` +
        `${findingsDiff.severityChanged.length} reclassified), ${next.forensicTimeline.length} event(s), ` +
        `${next.iocs.length} IOC(s)`,
      sourceScreenshots: [],
    };
    next = { ...next, timeline: [...next.timeline, synthLogEntry] };
    await ctx.opts.stateStore.save(next);
  };
  if (ctx.opts.stateLock) await ctx.opts.stateLock.runExclusive(caseId, persistLatest);
  else await persistLatest();

  // Auto-generate hypotheses (issue #140). Merge the model's hypotheses into the per-case store,
  // refreshing pristine auto ones and FREEZING any the analyst touched (see mergeHypotheses). Only
  // when the model actually returned some — an omitted field must never prune the analyst's set.
  // Sanitized against the FINAL event/IOC ids so evidence links can't dangle. Side store, not
  // InvestigationState; runs after the state is persisted so a failure here can't lose the synthesis.
  if (ctx.opts.hypothesisStore && delta.hypotheses && delta.hypotheses.length) {
    const validEventIds = new Set(next.forensicTimeline.map((e) => e.id));
    const validIocIds = new Set(next.iocs.map((i) => i.id));
    const seeds = sanitizeHypotheses(delta.hypotheses, validEventIds, validIocIds);
    await ctx.opts.hypothesisStore.applyAutoGenerated(caseId, seeds, new Date().toISOString());
  }

  ctx.lastSynthHash.set(caseId, synthHash); // remember these inputs so an identical re-run skips the AI call
  // Record what this run changed (findingsDiff computed above) and when it ran — surfaced on the
  // dashboard. Only reached on a real run; skips return early above.
  await ctx.opts.synthMetaStore?.record(caseId, findingsDiff, new Date().toISOString(), {
    durationMs: Date.now() - synthStart,
    eventCount: next.forensicTimeline.length,
    iocCount: next.iocs.length,
    selectionCounts: { ...selection.counts }, // #4: the evidence mix the model saw
    coverage: synthCoverage, // #62: included/omitted coverage audit
    synthModel: ctx.opts.synthesisModelLabel ?? `${synthProvider.name}/${synthProvider.model}`, // #74
    findingsCount: next.findings.length, // #74
    highSeverityBackfillCount, // #74
    parseRetries: synthParseRetries, // #74
  });
  const anonPolicy = toAnonPolicy(ctx.opts.anonStore ? await ctx.opts.anonStore.load(caseId) : null);
  await recordSynthesisRun(ctx.opts.analysisRunStore, caseId, {
    parentRunId: opts.analysisParentRunId,
    startedAt: new Date(synthStart).toISOString(),
    provider: synthProvider.name,
    model: synthProvider.model,
    eventIds: [...shownIds],
    inputState: state,
    outputState: next,
    prompt: getSynthesisPrompt(),
    maxEvents: SYNTH_MAX_EVENTS,
    thinkingTokens: synthThinkingTokens,
    correlationWindowSeconds: windowSeconds,
    anonymizationPolicy: anonPolicy,
    scope,
    falsePositiveMarkers: markers.length,
    infoEventsExcluded: omittedInfo > 0,
    observationsIncluded: observationsBlock.length > 0,
    parseRetries: synthParseRetries,
    coverage: synthCoverage,
  });
  // Notify on new/escalated findings (issue #58). Best-effort, fire-and-forget — never blocks or
  // fails synthesis. Only on a real run, so a skipped (unchanged) re-synthesis sends nothing.
  ctx.opts.onSynth?.(caseId, findingsDiff, next);
  ctx.opts.onState?.(next);

  // Second-look loop (investigation-guidance #11): now that this run has conclusions + (open)
  // hypotheses + key questions, re-query the COMPLETE raw record (the super-timeline + the scoped
  // events the sampler omitted) for the terms those open questions imply, promote the matches, and
  // trigger EXACTLY ONE bounded re-synthesis so the conclusions fold them in. `skipSecondLook` on that
  // re-synthesis (and on the second-opinion dryRun path, already returned above) is the one-iteration
  // guard that makes this terminate. Best-effort: a sweep failure must never fail the synthesis.
  if (!opts.skipSecondLook && ctx.opts.superTimelineStore) {
    try {
      const outcome = await runSecondLook(ctx, caseId, {
        // The sweep treats anything not in `promptEvents` as a candidate to re-discover; events
        // already covered by a grouped row HAVE been seen, so hand it the expanded set.
        next,
        scopedEvents,
        promptEvents: representedEvents,
        scope,
        evidenceRequests: delta.evidenceRequests,
      });
      if (outcome) {
        if (outcome.meta.promoted > 0) {
          // Promotion changed the in-scope timeline → the synthHash differs → this re-synthesis runs
          // (not skipped) and, with skipSecondLook, does NOT sweep again. Bounded to one extra AI call.
          const resynth = await synthesize(ctx, caseId, {
            force: true,
            skipSecondLook: true,
            ...(opts.signal ? { signal: opts.signal } : {}),
          });
          await ctx.opts.synthMetaStore?.recordSecondLook(caseId, outcome.meta);
          return resynth;
        }
        // Nothing new to promote, but empty requests are still surfaced as collection leads.
        await ctx.opts.synthMetaStore?.recordSecondLook(caseId, outcome.meta);
      }
    } catch (err) {
      console.warn(`[DFIR] second-look sweep failed for case ${caseId}: ${(err as Error).message}`);
    }
  }
  return next;
}

// Second-look sweep (investigation-guidance #11) — the impure orchestration around the pure secondLook
// module. Mines the case's OPEN questions (open hypotheses, unknown/partial key questions with a
// collect target, top connective IOCs) plus the model's own evidenceRequests into concrete searches,
// resolves them against the omitted scoped events AND the super-timeline within the active window,
// promotes the not-yet-analyzed matches (capped, tagged with provenance), and returns a meta summary.
// Returns null when there was nothing to search for. Never re-synthesizes itself — the caller does.
async function runSecondLook(
  ctx: SynthesisContext,
  caseId: string,
  input: {
    next: InvestigationState;
    scopedEvents: ForensicEvent[];
    promptEvents: ForensicEvent[];
    scope: ScopeWindow;
    evidenceRequests?: ModelEvidenceRequest[];
  },
): Promise<{ meta: SecondLookMeta } | null> {
  const superStore = ctx.opts.superTimelineStore;
  if (!superStore) return null;

  // Active window: the explicit scope when set, else the span of the dated in-scope events. Bounds the
  // raw re-query so a huge super-timeline is searched only over the incident window.
  const window = hasScope(input.scope)
    ? { from: input.scope.start ?? undefined, to: input.scope.end ?? undefined }
    : deriveWindow(input.scopedEvents);

  const hypotheses = ctx.opts.hypothesisStore ? await ctx.opts.hypothesisStore.load(caseId) : [];
  const iocValueById = new Map(input.next.iocs.map((i) => [i.id, i.value] as const));
  const connectiveIocs = rankConnectiveIocs(input.next, input.scopedEvents, { max: 5 });

  const requests = buildSecondLookRequests({
    hypotheses,
    iocValueById,
    keyQuestions: input.next.keyQuestions,
    connectiveIocs,
    modelRequests: input.evidenceRequests,
    window,
  });
  if (!requests.length) return null;

  // Candidate pool: the scoped events the sampler OMITTED from the prompt + the super-timeline rows in
  // the window (deduped by id). A super row that is a copy of a forensic event shares its id, so
  // `forensicEventIds` (below) correctly marks it non-promotable — only genuinely-new raw rows promote.
  const shownIds = new Set(input.promptEvents.map((e) => e.id));
  const omitted = input.scopedEvents.filter((e) => !shownIds.has(e.id));
  const superRows = (await superStore.query(caseId, { from: window.from, to: window.to })).events;
  const byId = new Map<string, ForensicEvent>();
  for (const e of [...omitted, ...superRows]) if (!byId.has(e.id)) byId.set(e.id, e);
  const candidates = [...byId.values()];

  const forensicEventIds = new Set(input.next.forensicTimeline.map((e) => e.id));
  const resolutions = resolveSecondLookRequests(requests, candidates, forensicEventIds);
  const plan = buildSecondLookPlan(resolutions);

  if (plan.promotions.length) {
    await ctx.promoteSuperTimeline(caseId, plan.promotions, {
      importedAt: new Date().toISOString(),
      tagById: plan.tagById,
      note: `Second look: promoted ${plan.promotions.length} raw event(s) matching open questions`,
    });
  }

  const matched = resolutions.filter((r) => r.matchedEventIds.length > 0).length;
  return {
    meta: {
      promoted: plan.promotions.length,
      requests: requests.length,
      matched,
      leads: plan.leads.map((l) => l.reason).slice(0, 10),
      summary: summarizeSecondLook(plan),
      at: new Date().toISOString(),
    },
  };
}
