import type { AIProvider } from "../../providers/provider.js";
import { z } from "zod";
import { sortByEventTime } from "../forensicSort.js";
import { estimateTokens, inputTokenBudget, fitItemsToBudget } from "../promptBudget.js";
import { segmentSessions, sessionEnvOptions } from "../sessionSegmentation.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import type { SuperQuery, SuperLabelMap } from "../superTimeline.js";
import type { SuperTimelineStore } from "../superTimelineStore.js";
import { maxPromptEvents } from "../synthGroup.js";
import { selectSynthesisEvents } from "../synthSelect.js";
import { getSessionSummaryPrompt, getStarredReportPrompt, getViewSummaryPrompt } from "./prompts/index.js";
import { retryPolicy, type AiCallContext } from "./aiContext.js";

/**
 * The three view-scoped AI summaries (#418).
 *
 * Moved from AnalysisPipeline (see ai/caseReports.ts for the pattern). These differ from the case
 * reports in what defines their input: not the case, but a SLICE the analyst chose — the events they
 * starred, the session they clicked, the filter they typed. So they share an event fitter rather
 * than the case-wide scope/false-positive filter, and none of them applies that filter at all: the
 * analyst hand-picked these rows and hiding some would misreport what the summary covered.
 *
 * Two of the three reach the raw super-timeline; starredReport PROMOTES what it reads and
 * viewSummary is the codebase's one sanctioned exception to that rule (see its own note).
 */

// Result of the two view-scoped AI summaries (starred report / view summary). `eventCount` is the
// full deduplicated match; `usedEvents` what actually fit the AI input budget.
export interface StarredSummaryResult {
  markdown: string;
  eventCount: number;
  usedEvents: number;
  truncated: boolean;
}

/** One session's AI account (#342). Carries the session identity so a stale card can't mislabel it. */
export interface SessionSummaryResult extends StarredSummaryResult {
  sessionId: string;
  label: string;
}

/**
 * How many raw super-timeline rows viewSummary may read in one call (#384).
 *
 * Was 10,000. That is more than a model can usefully summarise and far more than the analyst can
 * check, and it made the one sanctioned exception to the forensic/super-timeline rule the widest
 * path into the raw record in the codebase. A few hundred rows is enough for "what am I looking
 * at?" and small enough that the answer stays reviewable.
 */
export const VIEW_SUMMARY_MAX_ROWS = 500;

/** What the two raw-record summaries need on top of the shared AI-call seam. */
export interface ViewReportContext extends AiCallContext {
  readonly opts: AiCallContext["opts"] & { superTimelineStore?: SuperTimelineStore };
  promoteSuperTimeline(
    caseId: string,
    events: ForensicEvent[],
    opts: { importedAt: string; tagById?: Record<string, string[]>; note?: string },
  ): Promise<InvestigationState>;
}

const markdownSchema = z.object({ markdown: z.string().min(1) });

// Shared event-selection for the view-scoped summaries: cap to the synthesis event budget
// (DFIR_AI_SYNTH_MAX_EVENTS, default 600), token-fit against the prompt overhead, keep the most
// signal-bearing subset (selectSynthesisEvents) and re-sort it chronologically for the report.
function fitViewEvents(
  all: ForensicEvent[],
  overheadTokens: number,
): { events: ForensicEvent[]; render: (e: ForensicEvent) => string } {
  const render = (e: ForensicEvent): string =>
    `[${e.timestamp || "(undated)"}] [${e.severity}]` +
    (e.asset ? ` [${e.asset}]` : "") +
    ` ${e.description.slice(0, 240)}` +
    (e.processName ? ` | process: ${e.processName}` : "") +
    (e.srcIp || e.dstIp ? ` | net: ${[e.srcIp, e.dstIp].filter(Boolean).join(" → ")}` : "");
  const max = maxPromptEvents();
  let events = selectSynthesisEvents(all, max);
  const fit = fitItemsToBudget(events, render, Math.max(0, inputTokenBudget() - overheadTokens));
  if (fit < events.length) events = selectSynthesisEvents(all, fit);
  return { events: sortByEventTime(events), render };
}

/**
 * The tail all three view reports share (#453): one retried, restore-wrapped model call returning
 * the markdown envelope. Every one of them is EPHEMERAL — the result is returned, never persisted.
 */
async function callViewReport(
  ctx: AiCallContext,
  caseId: string,
  loaded: InvestigationState,
  provider: AIProvider,
  kind: "starred-report" | "session-summary" | "view-summary",
  systemPrompt: string,
  userPrompt: string,
): Promise<string> {
  const { retries, backoffMs } = retryPolicy(ctx);
  const result = await ctx.withRetry(
    caseId,
    kind,
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt, userPrompt, images: [] },
        kind,
      );
      return markdownSchema.parse(parsed);
    },
    retries,
    backoffMs,
  );
  return result.markdown;
}

/**
 * Resolve the starred ids to forensic events, promoting any that live only in the raw record.
 *
 * FORENSIC copies win: imports dual-write the same event ids to both stores, but all later
 * severity/MITRE re-grades (content tagger, synthesis mergeDelta) land on the forensic copy only —
 * the super copy is frozen at import time, so it must not shadow the re-graded one.
 *
 * Anything starred that lives ONLY in the raw record is PROMOTED before the model sees it, so the
 * report is still built from the forensic timeline alone. Starring an event is the analyst saying it
 * matters; promotion is that judgement written down. Fetched by id rather than with `.all(caseId)`,
 * which materialised the ENTIRE super-timeline — tens of thousands of rows — to resolve a handful.
 */
async function resolveStarredEvents(
  ctx: ViewReportContext,
  caseId: string,
  loaded: InvestigationState,
  starredIds: string[],
): Promise<{ loaded: InvestigationState; all: ForensicEvent[] }> {
  const wanted = new Set(starredIds);
  const byId = new Map<string, ForensicEvent>();
  for (const e of loaded.forensicTimeline) if (wanted.has(e.id)) byId.set(e.id, e);

  let state = loaded;
  if (ctx.opts.superTimelineStore) {
    const promotable: ForensicEvent[] = [];
    for (const id of starredIds.filter((id) => !byId.has(id))) {
      const raw = await ctx.opts.superTimelineStore.get(caseId, id);
      if (raw) promotable.push(raw);
    }
    if (promotable.length) {
      state = await ctx.promoteSuperTimeline(caseId, promotable, {
        importedAt: new Date().toISOString(),
        note: `Promoted ${promotable.length} starred raw event(s) for the starred report`,
      });
      for (const e of state.forensicTimeline) if (wanted.has(e.id)) byId.set(e.id, e);
    }
  }
  return { loaded: state, all: sortByEventTime([...byId.values()]) };
}

// TimeSketch-style Starred Events Report: ONE text-only AI call over ONLY the analyst-starred
// events (ids resolved by the route from the reserved "starred" tags — the pipeline has no tags
// store). Events resolve from the super-timeline store UNIONed with the forensic timeline
// (manual/pushed events may exist only there), deduped by id. Deliberately NO scope / false-
// positive filtering: the analyst hand-picked these events. EPHEMERAL — no state change.
export async function starredReport(
  ctx: ViewReportContext,
  caseId: string,
  starredIds: string[],
): Promise<StarredSummaryResult> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("starred report");
  const { loaded, all } = await resolveStarredEvents(
    ctx,
    caseId,
    await ctx.opts.stateStore.load(caseId),
    starredIds,
  );
  if (!all.length) throw new Error("no starred events");

  // The provenance line is computed HERE (the model copies it verbatim, it never counts events
  // itself) so the report's stated coverage is always accurate — including when the budget cap
  // reduced the set.
  const provenance = (used: number): string =>
    used < all.length
      ? `[*This report was generated based on the ${used} most significant of ${all.length} (deduplicated) starred events.*]`
      : `[*This report was generated based on ${all.length} (deduplicated) starred events.*]`;

  const prompt = getStarredReportPrompt();
  const { events, render } = fitViewEvents(
    all,
    estimateTokens(prompt) + estimateTokens(provenance(all.length)) + 300,
  );

  const userPrompt =
    `PROVENANCE LINE (copy verbatim directly under the title): ${provenance(events.length)}\n\n` +
    `STARRED EVENTS (${events.length} of ${all.length}, chronological):\n` +
    events.map(render).join("\n") +
    `\n\nWrite the starred events report as JSON.`;

  const markdown = await callViewReport(ctx, caseId, loaded, provider, "starred-report", prompt, userPrompt);

  return {
    markdown,
    eventCount: all.length,
    usedEvents: events.length,
    truncated: events.length < all.length,
  };
}

// Per-session summary (#342): ONE text-only AI call over just the events of a single attacker
// session. Cheaper and more coherent than full synthesis — the events already share a host and a
// tight window, so the model gets a focused slice instead of a 600-event wall.
//
// The session is re-derived HERE from the case's own timeline rather than trusting a caller-passed
// event list: a session id is only meaningful relative to a segmentation run, and re-segmenting
// with sessionEnvOptions() guarantees the summary covers exactly the session the dashboard and the
// report call by that id. EPHEMERAL — no state change.
export async function sessionSummary(
  ctx: AiCallContext,
  caseId: string,
  sessionId: string,
): Promise<SessionSummaryResult> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("session summary");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const sessions = segmentSessions(loaded.forensicTimeline, sessionEnvOptions());
  const session = sessions.find((s) => s.id === sessionId);
  if (!session) throw new Error(`session not found: ${sessionId}`);

  const wanted = new Set(session.eventIds);
  const all = sortByEventTime(loaded.forensicTimeline.filter((e) => wanted.has(e.id)));
  if (!all.length) throw new Error(`session not found: ${sessionId}`);

  const prompt = getSessionSummaryPrompt();
  const { events, render } = fitViewEvents(all, estimateTokens(prompt) + 300);

  const userPrompt =
    `SESSION: ${session.label}\n` +
    `HOST: ${session.host}\n` +
    (session.account ? `ACCOUNT: ${session.account}\n` : "") +
    `WINDOW: ${session.startTime} → ${session.endTime}\n\n` +
    `EVENTS (${events.length} of ${all.length}, chronological):\n` +
    events.map(render).join("\n") +
    `\n\nWrite the session account as JSON.`;

  const markdown = await callViewReport(ctx, caseId, loaded, provider, "session-summary", prompt, userPrompt);

  return {
    markdown,
    sessionId: session.id,
    label: session.label,
    eventCount: all.length,
    usedEvents: events.length,
    truncated: events.length < all.length,
  };
}

/**
 * Summarize the analyst's CURRENT super-timeline view.
 *
 * THIS IS THE ONE SANCTIONED EXCEPTION to the rule that the model reads only the forensic
 * timeline, and it is written down here so nobody has to infer it from the code.
 *
 * The other two raw-record paths — explainEvent and starredReport — promote before asking, so the
 * invariant holds literally for them. This one cannot: it summarises whatever the analyst has
 * filtered to, which can be thousands of rows. Promoting them would write thousands of Info-graded
 * events into the forensic timeline permanently, drowning the record the rule exists to protect.
 * Obeying the rule that way would cause exactly the harm the rule prevents.
 *
 * So it reads the raw record directly, under three constraints that keep it safe:
 *   1. It only ever runs when the analyst presses the button. Nothing automatic reaches this.
 *   2. It is EPHEMERAL — no promotion, no state change. Nothing it reads enters the case.
 *   3. It is capped at VIEW_SUMMARY_MAX_ROWS, far below the old 10,000, and it tells the analyst
 *      when the cap truncated their view rather than silently summarising a slice.
 */
export async function viewSummary(
  ctx: ViewReportContext,
  caseId: string,
  filters: SuperQuery,
  labelMap?: SuperLabelMap,
): Promise<StarredSummaryResult> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("view summary");
  if (!ctx.opts.superTimelineStore) throw new Error("super-timeline not configured");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const { events: matched, total } = await ctx.opts.superTimelineStore.query(
    caseId,
    { ...filters, offset: 0, limit: VIEW_SUMMARY_MAX_ROWS },
    labelMap,
  );
  if (!matched.length) throw new Error("no events match the current filters");

  const prompt = getViewSummaryPrompt();
  const { events, render } = fitViewEvents(matched, estimateTokens(prompt) + 300);

  // `total` is what MATCHED the filters; `matched.length` is what the cap let through. Reporting
  // both means an analyst looking at a 40,000-row filter is told the summary covers a slice,
  // rather than being left to assume it covered everything.
  const capped = total > matched.length;
  const userPrompt =
    `EVENTS (${events.length} of ${matched.length}${capped ? ` read from ${total} matching (capped at ${VIEW_SUMMARY_MAX_ROWS})` : " matching the analyst's current filters"}, chronological):\n` +
    events.map(render).join("\n") +
    `\n\nWrite the overview as JSON.`;

  const markdown = await callViewReport(ctx, caseId, loaded, provider, "view-summary", prompt, userPrompt);

  // `eventCount` is what MATCHED the filters, NOT what the row cap let through — the analyst is
  // told the true denominator or the disclosure is worthless. Reporting `matched.length` here made
  // a 750-row filter render as "500 matching events" with `truncated: false` whenever those 500
  // happened to fit the AI budget: the 250 the cap excluded vanished from the panel and from the
  // Activity Log line, which is exactly the silent-slice failure the cap exists to prevent.
  //
  // `truncated` therefore compares against `total` as well, so it covers BOTH reasons rows went
  // unread: the VIEW_SUMMARY_MAX_ROWS cap and the AI input budget. Because the flag can no longer
  // tell those two apart, the dashboard caption states the fact ("N of M matching events
  // summarized") instead of naming a cause it cannot know — it used to say "(AI input budget)",
  // which is the wrong reason whenever the row cap was what dropped them.
  return {
    markdown,
    eventCount: total,
    usedEvents: events.length,
    truncated: events.length < total,
  };
}
