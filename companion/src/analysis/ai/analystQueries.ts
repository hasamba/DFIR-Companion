import { buildGraphContext, DEFAULT_MAX_GRAPH_EDGES } from "../graphContext.js";
import {
  askSchema,
  explainEventSchema,
  fpSimilaritySchema,
  type AskAnswer,
  type ExplainEventResult,
} from "../responseSchema.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import type { SuperTimelineStore } from "../superTimelineStore.js";
import { buildSynthesisContext } from "../synthSelect.js";
import { getAskPrompt, getExplainEventPrompt, getFpSimilarityPrompt } from "./prompts/index.js";
import {
  fitTimelineText,
  loadScopedEvents,
  promptOverhead,
  retryPolicy,
  type AiCallContext,
} from "./aiContext.js";

/**
 * The three "answer this specific question" AI calls (#418).
 *
 * Moved from AnalysisPipeline (see ai/caseReports.ts for the pattern). Unlike the case reports,
 * which write a document about the whole case, each of these is pointed at something the analyst
 * just clicked: a question they typed, an event they want explained, an item they just rejected.
 * All three are single-shot, and only explainEvent can change the case — by promoting the one raw
 * event it was asked about.
 */

/** What explainEvent needs on top of the shared AI-call seam, to reach the raw record. */
export interface AnalystQueryContext extends AiCallContext {
  readonly opts: AiCallContext["opts"] & { superTimelineStore?: SuperTimelineStore };
  promoteSuperTimeline(
    caseId: string,
    events: ForensicEvent[],
    opts: { importedAt: string; tagById?: Record<string, string[]>; note?: string },
  ): Promise<InvestigationState>;
}

// Answer a free-form analyst question from the case's own evidence. Text-only, EPHEMERAL — the
// answer is returned for the analyst to act on, never written into the case.
export async function ask(ctx: AiCallContext, caseId: string, question: string): Promise<AskAnswer> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("case questions");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);

  const renderEvent = (e: ForensicEvent): string =>
    `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${e.description.slice(0, 240)}`;
  const findingsText =
    loaded.findings
      .slice(0, 150)
      .map((f) => `[${f.id}] [${f.severity}] ${f.title}`)
      .join("\n") || "(none)";
  const questionsText =
    loaded.keyQuestions.map((q) => `- ${q.question}${q.answer ? ` → ${q.answer}` : " (open)"}`).join("\n") ||
    "(none)";
  const contextBlock = buildSynthesisContext(loaded, scoped, await ctx.getKevCatalog());
  // GraphRAG (#98): serialize the deterministic evidence-chain graph (causal edges) so the model
  // can trace multi-hop attack paths via the graph's relationships, not just the flat timeline.
  const graphMaxEdges = Number(process.env.DFIR_ASK_GRAPH_MAX_EDGES) || DEFAULT_MAX_GRAPH_EDGES;
  const graphBlock = buildGraphContext({ ...loaded, forensicTimeline: scoped }, { maxEdges: graphMaxEdges });

  // Trim the timeline so the whole prompt fits the model context (the rest is fixed overhead).
  const timelineText = fitTimelineText(
    scoped,
    renderEvent,
    promptOverhead(
      getAskPrompt(),
      contextBlock,
      graphBlock,
      loaded.attackerPath || "",
      findingsText,
      questionsText,
      question,
    ),
  );

  const userPrompt =
    contextBlock +
    graphBlock +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `FINDINGS:\n${findingsText}\n\n` +
    `FORENSIC TIMELINE (${scoped.length} in-scope events):\n${timelineText}\n\n` +
    `CURRENT QUESTIONS:\n${questionsText}\n\n` +
    `ANALYST QUESTION: ${question.trim()}\n\nAnswer it as JSON.`;

  const { retries, backoffMs } = retryPolicy(ctx);
  return ctx.withRetry(
    caseId,
    "ask",
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt: getAskPrompt(), userPrompt, images: [] },
        "ask",
      );
      return askSchema.parse(parsed);
    },
    retries,
    backoffMs,
  );
}

// Explain a single forensic event in context (issue #141). Single text-only AI call.
//
// NO LONGER EPHEMERAL, and that is the point. Asking about a raw super-timeline event PROMOTES it
// into the forensic timeline first, so the model still only ever reads the forensic record — the
// invariant forensicGate.ts states. Promotion is the same seam runSecondLook uses, and it is
// honest: clicking "explain this" is the analyst declaring the event interesting, which is
// precisely what the forensic timeline means. One event, recorded with a note saying why.
export async function explainEvent(
  ctx: AnalystQueryContext,
  caseId: string,
  eventId: string,
): Promise<ExplainEventResult> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("event explanation");
  let loaded = await ctx.opts.stateStore.load(caseId);

  let event = loaded.forensicTimeline.find((e) => e.id === eventId);
  if (!event && ctx.opts.superTimelineStore) {
    // TARGETED lookup, not a paged scan (#406). The previous `query(caseId, {})` returned only the
    // first DEFAULT_SUPER_QUERY_LIMIT (500) rows and searched those, so explaining an event past
    // row 500 threw "event not found" for an event that plainly existed.
    const raw = await ctx.opts.superTimelineStore.get(caseId, eventId);
    if (raw) {
      loaded = await ctx.promoteSuperTimeline(caseId, [raw], {
        importedAt: new Date().toISOString(),
        note: `Promoted 1 raw event for "explain this event"`,
      });
      event = loaded.forensicTimeline.find((e) => e.id === eventId);
    }
  }
  if (!event) throw new Error(`event not found: ${eventId}`);
  // The universe is the forensic timeline, always — including the event just promoted into it.
  const universe = loaded.forensicTimeline;

  // Context: events adjacent in time + events on the same asset (up to 15 total).
  const sorted = [...universe].sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
  const focalIdx = sorted.findIndex((e) => e.id === eventId);
  const nearby = [
    ...sorted.slice(Math.max(0, focalIdx - 7), focalIdx),
    ...sorted.slice(focalIdx + 1, focalIdx + 8),
  ];
  const sameAsset = event.asset
    ? universe.filter((e) => e.id !== eventId && e.asset === event.asset).slice(0, 10)
    : [];
  const contextIds = new Set([...nearby.map((e) => e.id), ...sameAsset.map((e) => e.id)]);
  const contextEvents = [...contextIds]
    .map((id) => universe.find((e) => e.id === id)!)
    .filter(Boolean)
    .slice(0, 15);

  const renderEv = (e: ForensicEvent, focal = false): string =>
    `[${e.id}]${focal ? " *** FOCAL EVENT ***" : ""} ${e.timestamp || "(undated)"} [${e.severity}]` +
    ` ${e.description.slice(0, 300)}` +
    (e.asset ? ` | asset: ${e.asset}` : "") +
    (e.processName ? ` | process: ${e.processName}` : "") +
    (e.parentName ? ` | parent: ${e.parentName}` : "") +
    (e.sha256 ? ` | sha256: ${e.sha256.slice(0, 16)}…` : "") +
    (e.path ? ` | path: ${e.path}` : "") +
    (e.mitreTechniques.length ? ` | MITRE: ${e.mitreTechniques.join(", ")}` : "");

  const findingsText =
    loaded.findings
      .slice(0, 50)
      .map((f) => `[${f.severity}] ${f.title}`)
      .join("\n") || "(none)";
  const contextBlock = buildSynthesisContext(loaded, [event, ...contextEvents], await ctx.getKevCatalog());

  const userPrompt =
    contextBlock +
    `CASE FINDINGS (summary):\n${findingsText}\n\n` +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `FOCAL EVENT TO EXPLAIN:\n${renderEv(event, true)}\n\n` +
    `CONTEXT EVENTS (nearby / same asset):\n` +
    (contextEvents.map((e) => renderEv(e)).join("\n") || "(no context events)") +
    `\n\nExplain the focal event as JSON.`;

  const { retries, backoffMs } = retryPolicy(ctx);
  return ctx.withRetry(
    caseId,
    "explain-event",
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt: getExplainEventPrompt(), userPrompt, images: [] },
        "explain-event",
      );
      return explainEventSchema.parse(parsed);
    },
    retries,
    backoffMs,
  );
}

// Optional AI-assisted extension of deterministic FP suggestions (#227). The caller narrows the
// candidates and returned ids are validated against them, so hallucinated ids cannot be applied.
export async function suggestFalsePositiveSimilarAi(
  ctx: AiCallContext,
  caseId: string,
  anchorId: string,
  anchorLabel: string,
  candidateIds: string[],
  candidateLabels: string[],
): Promise<string[]> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("false positive suggestions");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const list = candidateIds.map((id, i) => `[${id}] ${candidateLabels[i] ?? ""}`).join("\n") || "(none)";
  const userPrompt =
    `ANCHOR ITEM (just marked false positive): [${anchorId}] ${anchorLabel}\n\n` +
    `OTHER ITEMS IN THIS CASE:\n${list}\n\n` +
    "Which of the other items are likely the same false-positive pattern?";
  const { retries, backoffMs } = retryPolicy(ctx);
  return ctx.withRetry(
    caseId,
    "fp-similarity",
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt: getFpSimilarityPrompt(), userPrompt, images: [] },
        "fp-similarity",
      );
      const result = fpSimilaritySchema.parse(parsed);
      const valid = new Set(candidateIds);
      return result.candidateIds.filter((id) => valid.has(id));
    },
    retries,
    backoffMs,
  );
}
