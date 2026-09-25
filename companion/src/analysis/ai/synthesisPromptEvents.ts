import { eventPrevalence, buildPrevalenceIndex, prevalenceTag, rarityScore } from "../prevalence.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import { resolveHost, type HostAliasIndex } from "../hostAlias.js";
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
import {
  selectSynthesisEventsAnnotated,
  type CommandSeatOptions,
  type SelectionClass,
} from "../synthSelect.js";
import { promptDescription } from "./promptDescription.js";
import { byEventTime } from "../forensicSort.js";
import { pinCap, promotedTag, rankPins } from "./promotedEvidence.js";
import {
  commandSeatCap,
  findingSessionRowIds,
  sessionCommandSeats,
  type CommandSeat,
} from "./synthCommandSeats.js";

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
  /** New promoted rows in the prompt right now (#1586), how many are not, and how many were pinned. */
  shownNew(): ForensicEvent[];
  newLeftOut(): number;
  pinnedCount(): number;
}

const NO_IDS: ReadonlySet<string> = new Set();

/**
 * Collapse detection bursts, select the events that fit the cap, and build their renderer.
 *
 * Prompt-only and derived on read: `scopedEvents` — and therefore the case, the coverage
 * denominators and the high-severity backfill — is untouched by anything here.
 */
export function createTimelineSelection(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
  aliasIndex?: HostAliasIndex,
  newPromotedIds: ReadonlySet<string> = NO_IDS,
): TimelineSelection {
  // New promoted rows (#1586) skip the three prompt-only filters that would hide them: the Info
  // filter, burst collapsing and the stratified fill. They are the rows the model most needs to see,
  // and the reason the missed-evidence review exists. Their seats still count against the cap, and
  // at most pinCap of them are pinned — the rest stay in the ordinary pool and compete for the seats
  // left, so a big second-look promotion is not cut to the pin cap when the prompt has room.
  const maxEvents = maxPromptEvents();
  const pinned = rankPins(scopedEvents.filter((e) => newPromotedIds.has(e.id))).slice(0, pinCap(maxEvents));
  const pinnedIds = new Set(pinned.map((e) => e.id));
  const rest = pinned.length ? scopedEvents.filter((e) => !pinnedIds.has(e.id)) : scopedEvents;
  const { grouping, omittedInfo } = collapseBursts(rest, aliasIndex);
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
  const commandSeats = commandSeatRows(state, scopedEvents, grouping, pinnedIds, aliasIndex);
  const choose = (count: number) => {
    const pins = pinned.slice(0, count);
    // The reserve is sized from the whole prompt count, not what the pins leave, and a pinned
    // Critical/High row already satisfies the one-anchor guarantee (#1622).
    const chosen = selectOrNone(collapsedEvents, count - pins.length, rarityOf, commandSeats, {
      cap: commandSeatCap(count),
      anchorShown: pins.some((e) => e.severity === "Critical" || e.severity === "High"),
    });
    return { chosen, pins, events: [...chosen.events, ...pins].sort(byEventTime) };
  };
  let current = choose(maxEvents);
  let selection = current.chosen;
  let promptEvents = current.events;
  const isContext = (id: string): boolean => CONTEXT_CLASSES.has(selection.classOf.get(id) as SelectionClass);
  const isNew = (id: string): boolean => newPromotedIds.has(id);

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
    renderEvent: (event) =>
      renderPromptEvent(event, { grouping, prevalenceIndex, isContext, isNew, aliasIndex }),
    fitTo(count) {
      if (count >= promptEvents.length) return;
      current = choose(count);
      selection = current.chosen;
      promptEvents = current.events;
    },
    hasContextRows: () => promptEvents.some((e) => isContext(e.id)),
    // Every new promoted row the prompt shows on its own line — pinned or seated by the stratifier.
    shownNew: () => promptEvents.filter((e) => newPromotedIds.has(e.id)),
    newLeftOut: () => newPromotedIds.size - promptEvents.filter((e) => newPromotedIds.has(e.id)).length,
    pinnedCount: () => current.pins.length,
  };
}

/**
 * The stratified selection for `max` seats. `selectSynthesisEventsAnnotated` reads max <= 0 as "no
 * cap" and returns everything — right for its other callers, wrong here, where 0 seats left over
 * after the pinned rows means none.
 */
function selectOrNone(
  events: ForensicEvent[],
  max: number,
  rarityOf: (e: ForensicEvent) => number,
  commandSeats: readonly CommandSeat[],
  seatOptions: CommandSeatOptions,
): ReturnType<typeof selectSynthesisEventsAnnotated> {
  if (max > 0) return selectSynthesisEventsAnnotated(events, max, rarityOf, commandSeats, seatOptions);
  const empty = selectSynthesisEventsAnnotated([], 1, rarityOf);
  return { ...empty, omitted: events.length };
}

/**
 * The rows that get reserved command seats (#1622), as rows of the collapsed prompt pool. Sessions and
 * candidates come from the UNCOLLAPSED scoped timeline, so a pinned or grouped Critical/High row still
 * opens a session and a grouped command is not lost. A pinned candidate is already on the prompt and
 * takes no reserve; a grouped one reserves the seat of the row that represents its burst.
 */
function commandSeatRows(
  state: InvestigationState,
  scopedEvents: readonly ForensicEvent[],
  grouping: CollapsedPrompt,
  pinnedIds: ReadonlySet<string>,
  aliasIndex?: HostAliasIndex,
): CommandSeat[] {
  const hostOf = (raw: string): string =>
    aliasIndex ? resolveHost(aliasIndex, raw) : raw.trim().toLowerCase();
  const seats = sessionCommandSeats({
    events: scopedEvents,
    hostOf,
    findingRowIds: findingSessionRowIds(state),
  });
  if (!seats.length) return [];
  const pool = new Map(grouping.events.map((e) => [e.id, e] as const));
  const representativeOf = new Map<string, string>();
  for (const [rep, members] of grouping.memberIdsByRepresentative)
    for (const id of members) representativeOf.set(id, rep);
  const rowOf = (id: string): string => representativeOf.get(id) ?? id;
  const out: CommandSeat[] = [];
  const seen = new Set<string>();
  for (const { event, shadowedBy } of seats) {
    // Pinned: already on the prompt. Shadowed by a pinned anchor: its command already is.
    if (pinnedIds.has(event.id) || shadowedBy.some((id) => pinnedIds.has(id))) continue;
    const row = pool.get(rowOf(event.id));
    if (!row || seen.has(row.id)) continue;
    seen.add(row.id);
    out.push({ event: row, shadowedBy: shadowedBy.map(rowOf) });
  }
  return out;
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
function collapseBursts(
  scopedEvents: ForensicEvent[],
  aliasIndex?: HostAliasIndex,
): {
  grouping: CollapsedPrompt;
  omittedInfo: number;
} {
  const eligible = promptCandidates(scopedEvents);
  // The explicit CollapsedPrompt annotation matters: without it the disabled branch's bare
  // `new Map()` infers Map<unknown, unknown> and every later `groupById.get(...)` fails to typecheck.
  const grouping: CollapsedPrompt = groupingEnabled()
    ? collapseForPrompt(eligible, { ...groupEnvOptions(), aliasIndex })
    : { events: [...eligible], groupById: new Map(), memberIdsByRepresentative: new Map() };
  return { grouping, omittedInfo: scopedEvents.length - eligible.length };
}

interface RenderContext {
  grouping: CollapsedPrompt;
  prevalenceIndex: ReturnType<typeof buildPrevalenceIndex>;
  isContext: (id: string) => boolean;
  isNew: (id: string) => boolean;
  aliasIndex?: HostAliasIndex;
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
  const description = promptDescription(e.description);
  return `${prefix}[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${description}${renderStructuredTags(e, ctx.aliasIndex)}${groupTag}${prevTag ? ` ⟨${prevTag}⟩` : ""}${promotedTag(e, ctx.isNew(e.id))}`;
}
