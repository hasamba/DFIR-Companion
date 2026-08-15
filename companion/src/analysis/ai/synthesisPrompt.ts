import type { FalsePositiveMarker } from "../falsePositive.js";
import type { HostAliasIndex } from "../hostAlias.js";
import { estimateTokens, inputTokenBudget, fitItemsToBudget } from "../promptBudget.js";
import type { ScopeWindow } from "../scope.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import type { CollapsedPrompt } from "../synthGroup.js";
import { buildSynthesisCoverage, type SynthesisCoverage } from "../synthMeta.js";
import type { selectSynthesisEventsAnnotated } from "../synthSelect.js";
import { getSynthesisPrompt } from "./prompts/index.js";
import type { AiCallContext } from "./aiContext.js";
import {
  assembleUserPrompt,
  buildSynthesisBlocks,
  overheadSourceText,
  type SynthesisBlocks,
  type SynthesisPromptContext,
} from "./synthesisPromptBlocks.js";
import { createTimelineSelection, type TimelineSelection } from "./synthesisPromptEvents.js";

/**
 * Synthesis prompt construction and the coverage audit that describes it (#418, split further #453).
 *
 * Split out of `synthesize` because it is a different KIND of work from the rest of that function:
 * everything here is a pure-ish transformation of an already-loaded case into one string, whereas
 * the orchestration around it loads stores, calls a model and writes state. Keeping them together is
 * what made the 695-line version impossible to review — a change to how an event row renders sat 400
 * lines away from the lock that protects the write.
 *
 * #453 then split this file's own 309-line function three ways along the same reasoning: which
 * events get a seat (`synthesisPromptEvents.ts`), what prose surrounds them
 * (`synthesisPromptBlocks.ts`), and — here — the order those two are combined in, which is the only
 * part that needs to know both.
 *
 * The coverage audit (#62) is computed HERE and not by the caller, and that is deliberate: it must
 * describe the prompt that was actually sent. Every omission it reports — out of scope, confirmed
 * legitimate, Info-severity, over the size budget — is a decision made in this file or its two
 * siblings, and a denominator computed anywhere else would eventually stop matching them.
 */

/** Everything the prompt builder consumes. The blocks are loaded by the caller BEFORE the skip-hash. */
export interface SynthesisPromptInput {
  caseId: string;
  /** The correlated state this run is reasoning over (not the raw snapshot). */
  state: InvestigationState;
  scope: ScopeWindow;
  markers: FalsePositiveMarker[];
  /** After the scope filter only — the coverage audit needs it separately from `scopedEvents`. */
  inWindowEvents: ForensicEvent[];
  scopedEvents: ForensicEvent[];
  /** The blocks that are also hashed for skip-if-unchanged, so they are loaded before this runs. */
  observationsBlock: string;
  notebookBlock: string;
  analystHypothesesBlock: string;
  refutedHypothesesBlock: string;
  priorHuntsBlock: string;
  playbookProgressBlock: string;
  incidentTypeBlock: string;
  /** Canonical host identity for this run (#host-near-duplicate-merge-gate) — resolved once by the
   *  caller and threaded through every render/ranking site so a merged host shows as one machine. */
  aliasIndex?: HostAliasIndex;
}

/** The prompt, plus what the run record and the second-look sweep need to describe it. */
export interface SynthesisPromptResult {
  userPrompt: string;
  /** The rows the model was shown. A grouped row stands for its whole burst. */
  promptEvents: ForensicEvent[];
  /** Every scoped event the model saw, INCLUDING the members a grouped row represents. */
  representedEvents: ForensicEvent[];
  shownIds: Set<string>;
  selection: ReturnType<typeof selectSynthesisEventsAnnotated>;
  coverage: SynthesisCoverage;
  maxEvents: number;
  omittedInfo: number;
}

/** Slack covering the JSON scaffolding around the blocks the overhead estimate counts. */
const OVERHEAD_SLACK_TOKENS = 400;

/**
 * Legend for the "~" context prefix (investigation-guidance #4). Emitted only when at least one
 * context row is present, so it costs nothing on a small case.
 */
const CONTEXT_LEGEND =
  ' Rows prefixed "~" are SUPPORTING CONTEXT (pulled in to explain a nearby anchor), not primary findings — weight them as background.';

/**
 * Trim the timeline so the WHOLE prompt fits the model context, and return the fixed overhead it was
 * measured against — the blocks, the findings echo and the system prompt.
 *
 * Re-selecting (rather than truncating) for the smaller count keeps the events that survive the most
 * important ones; the deterministic high-severity backfill downstream still creates findings for any
 * Critical/High event dropped here, so trimming never loses a severe detection.
 */
function trimTimelineToBudget(
  timeline: TimelineSelection,
  blocks: SynthesisBlocks,
  lastSummary: string,
): number {
  const overhead =
    estimateTokens(getSynthesisPrompt()) +
    estimateTokens(overheadSourceText(blocks, lastSummary)) +
    OVERHEAD_SLACK_TOKENS;
  const budget = Math.max(0, inputTokenBudget() - overhead);
  timeline.fitTo(fitItemsToBudget(timeline.promptEvents, (e) => timeline.renderEvent(e), budget));
  return overhead;
}

export async function buildSynthesisPrompt(
  ctx: SynthesisPromptContext,
  input: SynthesisPromptInput,
): Promise<SynthesisPromptResult> {
  const { caseId, state, scope, markers, inWindowEvents, scopedEvents, aliasIndex, ...preloaded } = input;
  const timeline = createTimelineSelection(state, scopedEvents, aliasIndex);
  const blocks = await buildSynthesisBlocks(ctx, {
    caseId,
    state,
    scope,
    markers,
    scopedEvents,
    preloaded,
    aliasIndex,
  });

  const overhead = trimTimelineToBudget(timeline, blocks, state.lastSummary || "");
  const timelineText = timeline.promptEvents.map((e) => timeline.renderEvent(e)).join("\n");
  const audit = auditCoverage({
    state,
    inWindowEvents,
    scopedEvents,
    promptEvents: timeline.promptEvents,
    grouping: timeline.grouping,
    omittedInfo: timeline.omittedInfo,
    promptTokensEstimate: overhead + estimateTokens(timelineText),
  });

  const userPrompt = assembleUserPrompt(blocks, {
    timelineText,
    scopedCount: scopedEvents.length,
    truncatedNote: audit.truncatedNote,
    contextLegend: timeline.hasContextRows() ? CONTEXT_LEGEND : "",
    lastSummary: state.lastSummary || "",
  });

  return {
    userPrompt,
    promptEvents: timeline.promptEvents,
    representedEvents: audit.representedEvents,
    shownIds: audit.shownIds,
    selection: timeline.selection,
    coverage: audit.coverage,
    maxEvents: timeline.maxEvents,
    omittedInfo: timeline.omittedInfo,
  };
}

interface CoverageInput {
  state: InvestigationState;
  inWindowEvents: ForensicEvent[];
  scopedEvents: ForensicEvent[];
  promptEvents: ForensicEvent[];
  grouping: CollapsedPrompt;
  omittedInfo: number;
  promptTokensEstimate: number;
}

interface CoverageAudit {
  shownIds: Set<string>;
  representedEvents: ForensicEvent[];
  coverage: SynthesisCoverage;
  truncatedNote: string;
}

/**
 * Coverage audit (#62): what the model actually saw this run vs what was left out and why. Computed
 * once `promptEvents` and the token overhead are final. Of the budget-omitted events, the safety-net
 * backfill downstream still guarantees a finding for any Critical/High, so surface that count too.
 *
 * A grouped row stands for every member of its burst, so all of those events were SEEN by the model —
 * counting only the representative would report the rest as "omitted for the size limit", the
 * opposite of the truth.
 */
function auditCoverage(i: CoverageInput): CoverageAudit {
  const shownIds = new Set<string>();
  let groupEntries = 0;
  let groupedEvents = 0;
  for (const e of i.promptEvents) {
    shownIds.add(e.id);
    const members = i.grouping.memberIdsByRepresentative.get(e.id);
    if (!members) continue;
    groupEntries += 1;
    groupedEvents += members.length;
    for (const id of members) shownIds.add(id);
  }
  const omittedHighSeverity = i.scopedEvents.filter(
    (e) => !shownIds.has(e.id) && (e.severity === "Critical" || e.severity === "High"),
  ).length;
  const omitted = i.scopedEvents.length - shownIds.size;
  return {
    shownIds,
    representedEvents: i.scopedEvents.filter((e) => shownIds.has(e.id)),
    coverage: buildSynthesisCoverage({
      totalEvents: i.state.forensicTimeline.length,
      inWindow: i.inWindowEvents.length,
      scoped: i.scopedEvents.length,
      considered: shownIds.size,
      groupEntries,
      groupedEvents,
      omittedInfo: i.omittedInfo,
      omittedHighSeverity,
      promptTokensEstimate: i.promptTokensEstimate,
    }),
    truncatedNote:
      omitted > 0
        ? ` — showing ${shownIds.size} of ${i.scopedEvents.length}; ${omitted} event(s) omitted from this prompt but still in the case`
        : "",
  };
}

// Satisfies the AiCallContext constraint without widening it here — the context this module
// declares is a superset, and TypeScript checks the assignment at every call site.
export type { AiCallContext, SynthesisPromptContext };
