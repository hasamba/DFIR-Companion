import type { AssetOverridesStore } from "../assetOverrides.js";
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
import type { VelociraptorClientStore } from "../velociraptorClientStore.js";
import { getAskPrompt, getExplainEventPrompt, getFpSimilarityPrompt } from "./prompts/index.js";
import type { PromotionIntent } from "../ingest/timelineImports.js";
import {
  callAiJson,
  fitTimelineEvents,
  loadCtxAliasIndex,
  loadScopedEvents,
  promptOverhead,
  type AiCallContext,
} from "./aiContext.js";
import { promptDescription, PROMPT_DESCRIPTION_WIDE_MAX } from "./promptDescription.js";
import type { AiControlStore } from "../aiControl.js";
import type { CommentsStore } from "../comments.js";
import type { DwellWindowStore } from "../dwellWindowStore.js";
import type { HostScopeStore } from "../hostScopeStore.js";
import type { HuntOutcomeStore } from "../huntOutcomeStore.js";
import type { HypothesisStore } from "../hypothesisStore.js";
import type { NotebookStore } from "../notebookStore.js";
import type { TagsStore } from "../tags.js";
import type { AskTurn } from "../askHistory.js";
import { renderPriorHuntsBlock } from "../huntOutcomes.js";
import {
  renderAnalystMarksBlock,
  renderAskHistoryBlock,
  renderAskHypothesesBlock,
  renderAskNotebookBlock,
  renderDwellWindowsBlock,
  renderHostScopeBlock,
} from "./askContext.js";

/**
 * The three "answer this specific question" AI calls (#418).
 *
 * Moved from AnalysisPipeline (see ai/caseReports.ts for the pattern). Unlike the case reports,
 * which write a document about the whole case, each of these is pointed at something the analyst
 * just clicked: a question they typed, an event they want explained, an item they just rejected.
 * All three are single-shot, and only explainEvent can change the case — by promoting the one raw
 * event it was asked about.
 */

/**
 * What explainEvent needs on top of the shared AI-call seam, to reach the raw record — plus the two
 * stores ask()/explainEvent() resolve canonical host identity from (see `loadCtxAliasIndex` in
 * aiContext.ts), so a question or an event explanation reads a merged near-duplicate as one machine.
 */
export interface AnalystQueryContext extends AiCallContext {
  readonly opts: AiCallContext["opts"] &
    AnalystDecisionStores & {
      superTimelineStore?: SuperTimelineStore;
      assetOverridesStore?: AssetOverridesStore;
      velociraptorClientStore?: VelociraptorClientStore;
      hypothesisStore?: HypothesisStore;
      huntOutcomeStore?: HuntOutcomeStore;
      notebookStore?: NotebookStore;
      aiControlStore?: AiControlStore;
    };
  promoteSuperTimeline(
    caseId: string,
    events: ForensicEvent[],
    opts: { importedAt: string; intent: PromotionIntent; tagById?: Record<string, string[]>; note?: string },
  ): Promise<InvestigationState>;
}

/**
 * The four analyst-decision stores ask() reads that the pipeline's AI context did not already carry
 * (#1411). Getters, not a snapshot, like the rest of the pipeline's `aiCtx.opts` literal: a store
 * wired after construction is still seen. Spread into that literal so pipeline.ts grows by one line.
 */
export interface AnalystDecisionStores {
  tagsStore?: TagsStore;
  commentsStore?: CommentsStore;
  hostScopeStore?: HostScopeStore;
  dwellWindowStore?: DwellWindowStore;
}

export function analystDecisionOpts(opts: AnalystDecisionStores): AnalystDecisionStores {
  return {
    get tagsStore() {
      return opts.tagsStore;
    },
    get commentsStore() {
      return opts.commentsStore;
    },
    get hostScopeStore() {
      return opts.hostScopeStore;
    },
    get dwellWindowStore() {
      return opts.dwellWindowStore;
    },
  };
}

export interface AskOptions {
  /** The panel's last few Q&A pairs, already bounded by parseAskHistory. */
  history?: AskTurn[];
}

/** The model's answer plus what it was answered FROM, so the panel can disclose a trimmed timeline. */
export type AskResult = AskAnswer & {
  usedEvents: number; // in-scope events the prompt actually carried
  eventCount: number; // in-scope events the case has (scope window + false-positive markers applied)
};

/**
 * The analyst's own work on the case, rendered for the prompt (#1411). Every store is optional and
 * every block is "" when empty; the notebook honours the same opt-in synthesis does
 * (ai-control.json `includeNotebook`), so a private note never reaches a model the analyst did not
 * point at it. Reads side files only — never the super-timeline.
 */
async function analystDecisionBlocks(
  ctx: AnalystQueryContext,
  caseId: string,
  history: readonly AskTurn[],
): Promise<string> {
  const o = ctx.opts;
  const [hypotheses, decisions, windows, outcomes, tags, comments, notebook] = await Promise.all([
    o.hypothesisStore?.load(caseId) ?? [],
    o.hostScopeStore?.load(caseId) ?? [],
    o.dwellWindowStore?.list(caseId) ?? [],
    o.huntOutcomeStore?.load(caseId) ?? [],
    o.tagsStore?.load(caseId) ?? [],
    o.commentsStore?.load(caseId) ?? [],
    loadNotebookIfOptedIn(ctx, caseId),
  ]);
  return (
    renderAskHypothesesBlock(hypotheses) +
    renderHostScopeBlock(decisions) +
    renderDwellWindowsBlock(windows) +
    renderPriorHuntsBlock(outcomes) +
    renderAnalystMarksBlock(tags, comments) +
    renderAskNotebookBlock(notebook) +
    renderAskHistoryBlock(history)
  );
}

async function loadNotebookIfOptedIn(ctx: AnalystQueryContext, caseId: string) {
  if (!ctx.opts.notebookStore || !ctx.opts.aiControlStore) return [];
  const control = await ctx.opts.aiControlStore.load(caseId);
  return control.includeNotebook ? ctx.opts.notebookStore.load(caseId) : [];
}

// Answer a free-form analyst question from the case's own evidence. Text-only, EPHEMERAL — the
// answer is returned for the analyst to act on, never written into the case.
export async function ask(
  ctx: AnalystQueryContext,
  caseId: string,
  question: string,
  options: AskOptions = {},
): Promise<AskResult> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("case questions");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);
  const decisionBlocks = await analystDecisionBlocks(ctx, caseId, options.history ?? []);

  const renderEvent = (e: ForensicEvent): string =>
    `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${promptDescription(e.description)}`;
  const findingsText =
    loaded.findings
      .slice(0, 150)
      .map((f) => `[${f.id}] [${f.severity}] ${f.title}`)
      .join("\n") || "(none)";
  const questionsText =
    loaded.keyQuestions.map((q) => `- ${q.question}${q.answer ? ` → ${q.answer}` : " (open)"}`).join("\n") ||
    "(none)";
  const aliasIndex = await loadCtxAliasIndex(ctx.opts, caseId);
  const contextBlock = buildSynthesisContext(loaded, scoped, await ctx.getKevCatalog(), aliasIndex);
  // GraphRAG (#98): serialize the deterministic evidence-chain graph (causal edges) so the model
  // can trace multi-hop attack paths via the graph's relationships, not just the flat timeline.
  const graphMaxEdges = Number(process.env.DFIR_ASK_GRAPH_MAX_EDGES) || DEFAULT_MAX_GRAPH_EDGES;
  const graphBlock = buildGraphContext({ ...loaded, forensicTimeline: scoped }, { maxEdges: graphMaxEdges });

  // Trim the timeline so the whole prompt fits the model context (the rest is fixed overhead).
  const shown = fitTimelineEvents(
    scoped,
    renderEvent,
    promptOverhead(
      getAskPrompt(),
      contextBlock,
      graphBlock,
      loaded.attackerPath || "",
      findingsText,
      questionsText,
      decisionBlocks,
      question,
    ),
  );
  const timelineText = shown.map(renderEvent).join("\n") || "(no events yet)";

  const userPrompt =
    contextBlock +
    graphBlock +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `FINDINGS:\n${findingsText}\n\n` +
    `FORENSIC TIMELINE (${scoped.length} in-scope events):\n${timelineText}\n\n` +
    `CURRENT QUESTIONS:\n${questionsText}\n\n` +
    decisionBlocks +
    `ANALYST QUESTION: ${question.trim()}\n\nAnswer it as JSON.`;

  const answer = await callAiJson(ctx, caseId, loaded, provider, "ask", getAskPrompt, userPrompt, (raw) =>
    askSchema.parse(raw),
  );
  return { ...answer, usedEvents: shown.length, eventCount: scoped.length };
}

/**
 * Resolve the event to explain, promoting it out of the raw record first if that is where it lives.
 *
 * TARGETED lookup, not a paged scan (#406): the previous `query(caseId, {})` returned only the first
 * DEFAULT_SUPER_QUERY_LIMIT (500) rows and searched those, so explaining an event past row 500 threw
 * "event not found" for an event that plainly existed.
 *
 * Promotion happens BEFORE the model sees anything, so the universe stays the forensic timeline —
 * the invariant that the model reads only the forensic record holds literally here.
 */
async function resolveFocalEvent(
  ctx: AnalystQueryContext,
  caseId: string,
  loaded: InvestigationState,
  eventId: string,
): Promise<{ loaded: InvestigationState; event: ForensicEvent }> {
  let state = loaded;
  let event = state.forensicTimeline.find((e) => e.id === eventId);
  if (!event && ctx.opts.superTimelineStore) {
    const raw = await ctx.opts.superTimelineStore.get(caseId, eventId);
    if (raw) {
      state = await ctx.promoteSuperTimeline(caseId, [raw], {
        importedAt: new Date().toISOString(),
        intent: "explain",
        note: `Promoted 1 raw event for "explain this event"`,
      });
      event = state.forensicTimeline.find((e) => e.id === eventId);
    }
  }
  if (!event) throw new Error(`event not found: ${eventId}`);
  return { loaded: state, event };
}

/** Events adjacent in time plus events on the same asset, capped at 15 total. */
function selectContextEvents(universe: ForensicEvent[], focal: ForensicEvent): ForensicEvent[] {
  const sorted = [...universe].sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
  const focalIdx = sorted.findIndex((e) => e.id === focal.id);
  const nearby = [
    ...sorted.slice(Math.max(0, focalIdx - 7), focalIdx),
    ...sorted.slice(focalIdx + 1, focalIdx + 8),
  ];
  const sameAsset = focal.asset
    ? universe.filter((e) => e.id !== focal.id && e.asset === focal.asset).slice(0, 10)
    : [];
  const contextIds = new Set([...nearby.map((e) => e.id), ...sameAsset.map((e) => e.id)]);
  return [...contextIds]
    .map((id) => universe.find((e) => e.id === id)!)
    .filter(Boolean)
    .slice(0, 15);
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

  const resolved = await resolveFocalEvent(ctx, caseId, loaded, eventId);
  loaded = resolved.loaded;
  const event = resolved.event;
  const contextEvents = selectContextEvents(loaded.forensicTimeline, event);

  const renderEv = (e: ForensicEvent, focal = false): string =>
    `[${e.id}]${focal ? " *** FOCAL EVENT ***" : ""} ${e.timestamp || "(undated)"} [${e.severity}]` +
    ` ${promptDescription(e.description, PROMPT_DESCRIPTION_WIDE_MAX)}` +
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
  const aliasIndex = await loadCtxAliasIndex(ctx.opts, caseId);
  const contextBlock = buildSynthesisContext(
    loaded,
    [event, ...contextEvents],
    await ctx.getKevCatalog(),
    aliasIndex,
  );

  const userPrompt =
    contextBlock +
    `CASE FINDINGS (summary):\n${findingsText}\n\n` +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `FOCAL EVENT TO EXPLAIN:\n${renderEv(event, true)}\n\n` +
    `CONTEXT EVENTS (nearby / same asset):\n` +
    (contextEvents.map((e) => renderEv(e)).join("\n") || "(no context events)") +
    `\n\nExplain the focal event as JSON.`;

  return callAiJson(
    ctx,
    caseId,
    loaded,
    provider,
    "explain-event",
    getExplainEventPrompt,
    userPrompt,
    (raw) => explainEventSchema.parse(raw),
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
  const valid = new Set(candidateIds);
  return callAiJson(
    ctx,
    caseId,
    loaded,
    provider,
    "fp-similarity",
    getFpSimilarityPrompt,
    userPrompt,
    (raw) => fpSimilaritySchema.parse(raw).candidateIds.filter((id) => valid.has(id)),
  );
}
