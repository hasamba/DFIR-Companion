import type { AIProvider, AnalyzeRequest } from "../../providers/provider.js";
import type { FalsePositiveMarker, FalsePositiveStore } from "../falsePositive.js";
import { filterFalsePositiveEvents } from "../falsePositive.js";
import { filterEventsByScope, NO_SCOPE, type ScopeStore, type ScopeWindow } from "../scope.js";
import { selectSynthesisEvents } from "../synthSelect.js";
import { maxPromptEvents } from "../synthGroup.js";
import { estimateTokens, inputTokenBudget, fitItemsToBudget } from "../promptBudget.js";
import type { StateStore } from "../stateStore.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import type { KevCatalog } from "../kev.js";

/**
 * What an AI-backed pipeline method needs from AnalysisPipeline, and nothing else (#418).
 *
 * This is the seam #384 established for the importers, widened to the shape the AI calls actually
 * need. It is a WIDER interface than `ImportContext` because these methods genuinely reach further:
 * an importer parses a file, but a report has to pick a provider, honour the anonymisation policy,
 * count the tokens against a budget and retry a flaky model. The interface is still narrow where it
 * counts — nothing here can synthesize, write state, or reach a store the method does not name.
 *
 * WHY THE PROVIDER CALL IS ONE METHOD. `analyzeRestored` is not a thin wrapper around
 * `provider.analyze`. It is the gate: per-case anonymisation of the prompt, OCR redaction of the
 * images, the Presidio approval check, cost accounting, usage logging, and restoring the real values
 * into the parsed response before any schema sees it. Every extracted family calls the model through
 * this one member precisely so none of them can accidentally skip a step of that chain.
 */
export interface AiCallContext {
  /**
   * The pipeline options an AI-backed report may read. Enumerated rather than widened to
   * PipelineOptions for the reason ImportContext gives: the type states the real dependency, and a
   * report that has no business touching the hypothesis store or the synthesis knobs cannot reach
   * them because they are not on this type.
   */
  readonly opts: {
    synthesisProvider?: AIProvider;
    stateStore: StateStore;
    falsePositiveStore?: FalsePositiveStore;
    scopeStore?: ScopeStore;
    retries?: number;
    backoffMs?: number;
  };

  /** The vision provider, or a thrown error naming what the analyst was trying to do. */
  requireProvider(purpose: string): AIProvider;

  /** The CISA KEV catalog for `buildSynthesisContext`; undefined when no store is wired. */
  getKevCatalog(): Promise<KevCatalog | undefined>;

  /** The module-level retry, plus the per-attempt WARN and the ai_retry operational metric. */
  withRetry<T>(
    caseId: string,
    label: string,
    fn: () => Promise<T>,
    retries: number,
    backoffMs: number,
  ): Promise<T>;

  /** The anonymise → OCR-redact → Presidio-gate → call → restore chain. See the note above. */
  analyzeRestored(
    caseId: string,
    state: InvestigationState,
    provider: AIProvider,
    req: AnalyzeRequest,
    label?: string,
    skipPresidioGate?: boolean,
  ): Promise<unknown>;
}

/** `opts.retries` / `opts.backoffMs` with the defaults every AI call site repeated inline. */
export function retryPolicy(ctx: AiCallContext): { retries: number; backoffMs: number } {
  return { retries: ctx.opts.retries ?? 3, backoffMs: ctx.opts.backoffMs ?? 500 };
}

/**
 * The tail EVERY read-only AI call in this directory shares (#453): retry the restore-wrapped
 * provider call, then hand the raw JSON to the caller's own schema parse and sanitizer.
 *
 * It lives here rather than being re-derived per family because getting it wrong is silent. The
 * `kind` string must be the SAME value in both places it appears — `withRetry` uses it for the
 * per-attempt log line and `analyzeRestored` for anonymisation telemetry — and a mismatch produces
 * a working call whose telemetry quietly attributes itself to the wrong feature. One parameter now
 * feeds both.
 *
 * Parsing stays the caller's business: every call site has its own zod schema, and most have a
 * sanitizer that needs case state (valid event ids, known hypothesis ids) to reject what the model
 * invented. Those checks are the actual safety property and they do not generalise.
 *
 * Callers that MUTATE state (extraction's batch loop, synthesis) deliberately do not use this —
 * they hold the state lock across the call and need the surrounding structure.
 */
export async function callAiJson<T>(
  ctx: AiCallContext,
  caseId: string,
  loaded: InvestigationState,
  provider: AIProvider,
  kind: string,
  systemPrompt: string | (() => string),
  userPrompt: string,
  parse: (raw: unknown) => T,
): Promise<T> {
  const { retries, backoffMs } = retryPolicy(ctx);
  return ctx.withRetry(
    caseId,
    kind,
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        // Resolved per ATTEMPT when a resolver is passed. DFIR_AI_*_PROMPT_FILE is documented as
        // "re-read on each AI call", so an operator fixing a broken prompt file mid-retry must see
        // it take effect on the next attempt. Callers whose original resolved once pass a string.
        {
          systemPrompt: typeof systemPrompt === "function" ? systemPrompt() : systemPrompt,
          userPrompt,
          images: [],
        },
        kind,
      );
      return parse(parsed);
    },
    retries,
    backoffMs,
  );
}

/**
 * The two-stage event filter every case-wide AI call runs before building its prompt.
 *
 * Kept as one function because the two stages are not interchangeable and the order matters:
 * `inWindow` is after the analyst's investigation scope (out-of-window activity is not part of this
 * case), and `scoped` additionally drops what the analyst confirmed legitimate (so the model never
 * reasons from benign activity). Synthesis needs both counts separately to attribute its coverage
 * audit; every other caller wants only `scoped`.
 *
 * Nothing here mutates state — callers filter a COPY, so un-marking a false positive restores the
 * event everywhere.
 */
export async function loadScopedEvents(
  ctx: AiCallContext,
  caseId: string,
  state: InvestigationState,
): Promise<{
  markers: FalsePositiveMarker[];
  scope: ScopeWindow;
  inWindow: ForensicEvent[];
  scoped: ForensicEvent[];
}> {
  const markers = ctx.opts.falsePositiveStore ? await ctx.opts.falsePositiveStore.load(caseId) : [];
  const scope = ctx.opts.scopeStore ? await ctx.opts.scopeStore.load(caseId) : NO_SCOPE;
  const inWindow = filterEventsByScope(state.forensicTimeline, scope);
  return { markers, scope, inWindow, scoped: filterFalsePositiveEvents(inWindow, markers) };
}

/**
 * Render the timeline into the prompt, trimmed so the WHOLE request fits the model's context.
 *
 * The dance is subtle enough to be worth having in one place: cap to the synthesis event budget,
 * measure what the rendered rows cost against the budget left over after the fixed overhead, and —
 * when they do not fit — RE-SELECT for the smaller count rather than truncating the list. Re-running
 * the selector is what keeps the kept events the most significant ones; slicing would keep whichever
 * happened to sort first.
 */
export function fitTimelineText(
  scopedEvents: ForensicEvent[],
  renderEvent: (e: ForensicEvent) => string,
  overheadTokens: number,
): string {
  let events = selectSynthesisEvents(scopedEvents, maxPromptEvents());
  const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overheadTokens));
  if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
  return events.map(renderEvent).join("\n") || "(no events yet)";
}

/** The fixed overhead of a report prompt: the system prompt plus its non-timeline blocks. */
export function promptOverhead(systemPrompt: string, ...blocks: string[]): number {
  return estimateTokens(systemPrompt) + estimateTokens(blocks.join("")) + 300;
}
