import { eventPrevalence, buildPrevalenceIndex, prevalenceTag, rarityScore } from "../prevalence.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import { renderStructuredTags } from "../synthEvidence.js";
import {
  collapseForPrompt,
  renderGroupSuffix,
  groupEnvOptions,
  groupingEnabled,
  maxPromptEvents,
  promptCandidates,
  type CollapsedPrompt,
} from "../synthGroup.js";
import { selectSynthesisEventsAnnotated, type SelectionClass } from "../synthSelect.js";

/**
 * Which events reach the synthesis prompt, and how each one renders (#453, split from
 * `buildSynthesisPrompt`).
 *
 * This is the half of prompt construction that decides WHO gets a seat: burst collapsing, the
 * stratified selection, the prevalence/rarity bias, and the re-selection that happens when the
 * rendered timeline overflows the token budget. The other half — the narrative blocks around the
 * timeline — is `synthesisPromptBlocks.ts`. They were one 309-line function; the seam is real
 * because nothing here reads a block and nothing there reads an event.
 *
 * WHY THIS HOLDS MUTABLE STATE. `renderEvent` prefixes context-only rows with "~", and which rows
 * those are comes from `selection.classOf` — which is REPLACED when `fitTo` re-selects for a smaller
 * count. The original relied on `renderEvent` closing over a `let selection`, so the measuring pass
 * and the final render legitimately disagree by exactly that prefix. Freezing the selection here
 * would change the rendered timeline, so the mutation is preserved deliberately, not tidied away.
 */

/** Everything that is NOT a primary verdict-bearing anchor / initial-access event. */
const CONTEXT_CLASSES = new Set<SelectionClass>([
  "anchor_context",
  "corroborated",
  "technique",
  "rare",
  "spread",
]);

export interface TimelineSelection {
  /** Burst collapsing, so the coverage audit can expand a representative back to its members. */
  readonly grouping: CollapsedPrompt;
  /** Info-severity events denied a prompt seat. Still in the case and the coverage denominators. */
  readonly omittedInfo: number;
  /** The event cap this run used, for the run record. */
  readonly maxEvents: number;
  /** The current selection — replaced when `fitTo` re-selects. */
  readonly selection: ReturnType<typeof selectSynthesisEventsAnnotated>;
  /** The rows the model will be shown. A grouped row stands for its whole burst. */
  readonly promptEvents: ForensicEvent[];
  renderEvent(event: ForensicEvent): string;
  /** Re-select for a smaller count when the rendered timeline overflows the budget. No-op if larger. */
  fitTo(count: number): void;
  /** Whether any shown row is supporting context, which is what earns the legend its tokens. */
  hasContextRows(): boolean;
}

/**
 * Collapse detection bursts, select the events that fit the cap, and build their renderer.
 *
 * Prompt-only and derived on read: `scopedEvents` — and therefore the case, the coverage
 * denominators and the high-severity backfill — is untouched by anything here.
 */
export function createTimelineSelection(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
): TimelineSelection {
  const { grouping, omittedInfo } = collapseBursts(scopedEvents);
  const collapsedEvents = grouping.events;

  // Per-case prevalence/baseline (investigation-guidance #15): how common each activity PATTERN is
  // across the WHOLE case timeline (not just the scoped subset — the baseline is a property of the
  // corpus). Feeds a rarity bias into the selection fill (a 1-off wins a seat over 500× noise) and a
  // common/rare tag into each rendered event so the model gets explicit baseline context.
  const prevalenceIndex = buildPrevalenceIndex(state.forensicTimeline);
  const rarityOf = (e: ForensicEvent): number => rarityScore(e, prevalenceIndex);

  // Bound the prompt for large imports (e.g. THOR: hundreds of events + auto-findings). Stratified
  // selection: all Critical/High + the earliest (initial-access) + an even time-spread sample,
  // chronologically — better kill-chain coverage than severity-only. The ANNOTATED form
  // (investigation-guidance #4) exposes which CLASS claimed each event. The deterministic
  // high-severity backfill still creates findings for any Critical/High event NOT shown here, so
  // capping the prompt never loses a severe detection.
  const maxEvents = maxPromptEvents();
  let selection = selectSynthesisEventsAnnotated(collapsedEvents, maxEvents, rarityOf);
  let promptEvents = selection.events;
  const isContext = (id: string): boolean => CONTEXT_CLASSES.has(selection.classOf.get(id) as SelectionClass);

  return {
    grouping,
    omittedInfo,
    maxEvents,
    get selection() {
      return selection;
    },
    get promptEvents() {
      return promptEvents;
    },
    renderEvent: (event) => renderPromptEvent(event, { grouping, prevalenceIndex, isContext }),
    fitTo(count) {
      if (count >= promptEvents.length) return;
      selection = selectSynthesisEventsAnnotated(collapsedEvents, count, rarityOf);
      promptEvents = selection.events;
    },
    hasContextRows: () => promptEvents.some((e) => isContext(e.id)),
  };
}

/**
 * Detection-burst collapsing (spec 2026-07-21). The same Sigma/YARA detection firing hundreds of
 * times used to consume hundreds of prompt seats; collapse each burst to ONE representative row so
 * every DISTINCT detection reaches the model.
 *
 * Info-severity events don't get prompt seats either (DFIR_SYNTH_INCLUDE_INFO=1 restores them): on a
 * real case 213 Info rows pushed the prompt from 546 to 759 entries, past the cap, costing 26 GRADED
 * detections their place. They remain in the case, the timeline and the coverage denominators — this
 * only decides who gets budget.
 */
function collapseBursts(scopedEvents: ForensicEvent[]): {
  grouping: CollapsedPrompt;
  omittedInfo: number;
} {
  const eligible = promptCandidates(scopedEvents);
  // The explicit CollapsedPrompt annotation matters: without it the disabled branch's bare
  // `new Map()` infers Map<unknown, unknown> and every later `groupById.get(...)` fails to typecheck.
  const grouping: CollapsedPrompt = groupingEnabled()
    ? collapseForPrompt(eligible, groupEnvOptions())
    : { events: [...eligible], groupById: new Map(), memberIdsByRepresentative: new Map() };
  return { grouping, omittedInfo: scopedEvents.length - eligible.length };
}

interface RenderContext {
  grouping: CollapsedPrompt;
  prevalenceIndex: ReturnType<typeof buildPrevalenceIndex>;
  isContext: (id: string) => boolean;
}

/**
 * One timeline row. Each event carries its structured tags (host / process lineage / src→dst /
 * corroborating-source count) after the prose (investigation-guidance #5) — only when set, so a bare
 * event costs no extra tokens. This is what lets the model connect cross-host activity instead of
 * guessing from prose.
 */
function renderPromptEvent(e: ForensicEvent, ctx: RenderContext): string {
  // Grouped rows carry their own count/host-spread/span suffix, which supersedes the prevalence
  // tag — showing both would state the same repetition twice in different words.
  const group = ctx.grouping.groupById.get(e.id);
  const groupTag = group ? renderGroupSuffix(group) : "";
  // Prevalence baseline tag (#15): only the informative extremes (clearly common / clearly rare) are
  // tagged, so the model knows a 500× pattern is routine and a 1-off is anomalous.
  const p = group ? null : eventPrevalence(e, ctx.prevalenceIndex);
  const prevTag = p ? prevalenceTag(p) : "";
  // "~" prefix (investigation-guidance #4): this row is supporting CONTEXT (pulled in to explain an
  // anchor), not itself a primary verdict-bearing event — so the model weights it as background.
  const prefix = ctx.isContext(e.id) ? "~" : "";
  const description = e.description.slice(0, 240);
  return `${prefix}[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${description}${renderStructuredTags(e)}${groupTag}${prevTag ? ` ⟨${prevTag}⟩` : ""}`;
}
