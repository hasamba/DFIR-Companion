import { detectTimelineGaps, gapEnvOptions } from "../gapDetect.js";
import {
  gapHypothesesResponseSchema,
  sanitizeGapHypotheses,
  buildGapHypotheses,
  surroundingEvents,
  renderGapsForPrompt,
  hasGapMaterial,
  GAP_HYPOTHESIS_MAX_DEFAULT,
  SURROUNDING_EVENTS_DEFAULT,
  GAP_HYPOTHESIS_CAVEAT,
  type GapHypothesesResult,
} from "../gapHypothesis.js";
import {
  memoryNextStepResponseSchema,
  sanitizeMemoryNextSteps,
  renderMemoryEvidence,
  memoryPluginsPresent,
  isMemoryEvent,
  hasMemoryMaterial,
  MEMORY_NEXTSTEP_MAX_DEFAULT,
  type MemoryNextStep,
} from "../memoryNextStep.js";
import { estimateTokens, inputTokenBudget, fitItemsToBudget } from "../promptBudget.js";
import { SHADOW_ARTIFACTS } from "../shadowArtifacts.js";
import type { ForensicEvent } from "../stateTypes.js";
import { MATCHABLE_FIELDS } from "../taggerRules.js";
import {
  suggestedRuleResponseSchema,
  sanitizeSuggestedRule,
  type SuggestOutcome,
} from "../taggerRuleSuggest.js";
import { getGapHypothesisPrompt, getMemoryNextStepPrompt, getTaggerRulePrompt } from "./prompts/index.js";
import { loadScopedEvents, retryPolicy, type AiCallContext } from "./aiContext.js";

/**
 * The three AI calls that propose the analyst's NEXT move (#418).
 *
 * Moved from AnalysisPipeline (see ai/caseReports.ts for the pattern). Unlike ai/hunts.ts, which
 * writes a query to run against the fleet, each of these answers "given what this case already has,
 * what should I do about what it does NOT have?" — the next Volatility command, the collection that
 * would fill a silent window, the tagger rule that would stop the noise. All three are EPHEMERAL,
 * and each returns an empty result WITHOUT spending a call when the case has no material for it.
 */

// Memory-forensics "Next-Step" agent (issue #101). The case already has Volatility 3 / Rekall output
// imported as forensic events; read that memory evidence (the process tree, connections, malfind,
// command lines, services), identify the anomalies, and propose the EXACT next Volatility 3 command
// the analyst should run to dig deeper. Single text-only AI call; EPHEMERAL like ask()/suggestHunts()
// — it does NOT mutate state. Returns [] without an AI call when the case has no memory evidence.
export async function suggestMemoryNextSteps(ctx: AiCallContext, caseId: string): Promise<MemoryNextStep[]> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("memory next-step suggestions");
  const loaded = await ctx.opts.stateStore.load(caseId);
  if (!hasMemoryMaterial(loaded)) return []; // no Volatility/Rekall evidence — don't spend a call

  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);
  const memEvents = scoped.filter(isMemoryEvent);
  if (!memEvents.length) return []; // all memory evidence is out-of-scope / legitimate

  const pluginsText = memoryPluginsPresent(memEvents).join(", ") || "(unknown)";

  // Trim the memory evidence so the whole prompt fits the model context (the rest is fixed overhead).
  const renderEvent = (e: ForensicEvent) =>
    `[${e.severity}] ${(e.description ?? "").replace(/\s+/g, " ").trim().slice(0, 300)}`;
  const overhead = estimateTokens(getMemoryNextStepPrompt()) + estimateTokens(pluginsText) + 300;
  const fit = fitItemsToBudget(memEvents, renderEvent, Math.max(0, inputTokenBudget() - overhead));
  const evidenceText = renderMemoryEvidence(memEvents, Math.max(1, fit));

  const userPrompt =
    `ALREADY-IMPORTED MEMORY PLUGINS (prefer suggesting plugins NOT in this list where they advance the case): ${pluginsText}\n\n` +
    `MEMORY EVIDENCE (${memEvents.length} Volatility/Rekall events, worst-severity first):\n${evidenceText}\n\n` +
    `Propose the next Volatility 3 commands as JSON.`;

  const limit = Number(process.env.DFIR_MEMORY_NEXTSTEP_MAX) || MEMORY_NEXTSTEP_MAX_DEFAULT;
  const { retries, backoffMs } = retryPolicy(ctx);
  return ctx.withRetry(
    caseId,
    "memory-next-steps",
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt: getMemoryNextStepPrompt(), userPrompt, images: [] },
        "memory-next-steps",
      );
      const { suggestions } = memoryNextStepResponseSchema.parse(parsed);
      return sanitizeMemoryNextSteps(suggestions, limit);
    },
    retries,
    backoffMs,
  );
}

// Hypothesise what an attacker did during the timeline's SILENT periods (issue #96). Builds on the
// deterministic gap detector: detect the suspicious gaps, then make ONE text-only AI call that reads
// each gap's bounding events (before/after the silence) and infers the attacker activity that fits.
// Each gap is also paired with the DETERMINISTIC shadow-artifact collections (USN journal, SRUM,
// Prefetch, Amcache, …) that reconstruct the missing window — so even a gap the model skips still
// carries deployable Velociraptor collections. EPHEMERAL like ask()/suggestHunts(): no state change.
// Returns an empty result (no AI spend) when the timeline has no flagged gaps.
export async function hypothesizeGaps(ctx: AiCallContext, caseId: string): Promise<GapHypothesesResult> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("gap hypothesis");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);

  // Use the SAME gap detection (and thresholds) the panel/report use, so the analyst hypothesises
  // about exactly the gaps they see flagged.
  const gaps = detectTimelineGaps(scoped, gapEnvOptions());
  if (!hasGapMaterial(gaps)) return { hypotheses: [], caveat: GAP_HYPOTHESIS_CAVEAT };

  const cap = Number(process.env.DFIR_GAP_HYPOTHESIS_MAX) || GAP_HYPOTHESIS_MAX_DEFAULT;
  const focusGaps = gaps.slice(0, Math.max(1, Math.floor(cap))); // worst-first → keep the most suspicious
  const around = Number(process.env.DFIR_GAP_HYPOTHESIS_CONTEXT) || SURROUNDING_EVENTS_DEFAULT;
  const surroundByGapId = new Map(focusGaps.map((g) => [g.id, surroundingEvents(g, scoped, around)]));
  const validGapIds = new Set(focusGaps.map((g) => g.id));

  const gapsText = renderGapsForPrompt(focusGaps, surroundByGapId);
  // The shadow-artifact catalog the model ranks against (id → what it reconstructs). The catalog
  // supplies the actual collection VQL deterministically; the model only picks the relevant ids.
  const artifactsText = SHADOW_ARTIFACTS.map((a) => `- ${a.id}: ${a.name} — ${a.reconstructs}`).join("\n");
  const userPrompt =
    `SHADOW ARTIFACTS (reference recommendedArtifactIds ONLY from these ids):\n${artifactsText}\n\n` +
    `TIMELINE GAPS (${focusGaps.length} of ${gaps.length} flagged; worst-first) with their surrounding events:\n\n` +
    `${gapsText}\n\n` +
    `Hypothesise the attacker activity for each gap as JSON.`;

  const { retries, backoffMs } = retryPolicy(ctx);
  const aiHypotheses = await ctx.withRetry(
    caseId,
    "hypothesize-gaps",
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt: getGapHypothesisPrompt(), userPrompt, images: [] },
        "hypothesize-gaps",
      );
      const { hypotheses } = gapHypothesesResponseSchema.parse(parsed);
      return sanitizeGapHypotheses(hypotheses, validGapIds, focusGaps.length);
    },
    retries,
    backoffMs,
  );

  return buildGapHypotheses(aiHypotheses, focusGaps, surroundByGapId);
}

// Convert a plain-English description into ONE content-tagger rule (PR #112 follow-up), or a
// decline reason when it can't be expressed as a single-event field-match rule. EPHEMERAL — this
// returns a candidate for review; nothing is persisted here (the route's add step saves it). Uses
// the strong synthesisProvider like translateQuery — authoring a schema-constrained rule benefits
// from the general model over the VQL-tuned velociraptorProvider.
export async function suggestTaggerRule(
  ctx: AiCallContext,
  caseId: string,
  description: string,
): Promise<SuggestOutcome> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("tagger rule suggestion");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const userPrompt =
    `MATCHABLE FIELDS (use ONLY these): ${MATCHABLE_FIELDS.join(", ")}\n\n` +
    `ANALYST REQUEST: ${description.trim()}\n\n` +
    `Return the rule as JSON (or a decline).`;
  const { retries, backoffMs } = retryPolicy(ctx);
  return ctx.withRetry(
    caseId,
    "suggest-tagger-rule",
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt: getTaggerRulePrompt(), userPrompt, images: [] },
        "suggest-tagger-rule",
      );
      return sanitizeSuggestedRule(suggestedRuleResponseSchema.parse(parsed));
    },
    retries,
    backoffMs,
  );
}
