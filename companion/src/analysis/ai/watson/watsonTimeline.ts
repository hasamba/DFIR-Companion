import type { HostAliasIndex } from "../../hostAlias.js";
import type { ForensicEvent, InvestigationState } from "../../stateTypes.js";
import { renderGroupSuffix } from "../../synthGroup.js";
import { createTimelineSelection, type TimelineSelection } from "../synthesisPromptEvents.js";
import { timelineRow } from "./timelineLookup.js";

// Watson's forensic-timeline rows (#2656). The seats come from synthesis's own selection
// (createTimelineSelection: burst grouping, the Info policy, Critical/High anchors, rarity, command,
// account and PowerShell-session seats), so Watson and synthesis see the case the same way. When the
// rows do not all fit, the selection is re-run for a smaller count and measured again: the earlier
// code walked a time-ordered list and stopped at the budget, so the EARLIEST rows won and a late
// Critical event was the one cut. Rows are still listed in time order.

export interface WatsonTimelineBlock {
  text: string;
  /** In-scope events the shown rows cover: a grouped row covers every event of its burst. */
  used: number;
}

/** Said under the rows when the packet could not carry every in-scope event (Task 11). */
export const partialNote = (shown: number, total: number): string =>
  `\n(showing ${shown} of ${total} in-scope events — ask for a 'lookup' to read others)`;

const NO_ROWS = "(no events shown)";
const CLIP_MARK = "…";

const titleOf = (total: number): string =>
  `FORENSIC TIMELINE (${total} in-scope events; the most significant are kept when they do not all fit, listed in time order):\n`;

function rowOf(t: TimelineSelection, e: ForensicEvent, withGroup = true): string {
  const g = withGroup ? t.grouping.groupById.get(e.id) : undefined;
  return timelineRow(e) + (g ? renderGroupSuffix(g) : "");
}

/** How many leading rows fit the budget, each followed by a newline. May be 0. */
function fitCount(rows: readonly string[], budget: number): number {
  let used = 0;
  for (let i = 0; i < rows.length; i++) {
    used += rows[i].length + 1;
    if (used > budget) return i;
  }
  return rows.length;
}

interface Fitted {
  rows: string[];
  /** The one row was cut down: its burst members are not shown, so they are not covered. */
  clipped: boolean;
}

/** Re-select by priority until the rendered rows fit. Each pass shows strictly fewer rows. */
function fitSelection(t: TimelineSelection, budget: number): Fitted {
  let rows = t.promptEvents.map((e) => rowOf(t, e));
  for (;;) {
    const fits = fitCount(rows, budget);
    if (fits >= rows.length) return { rows, clipped: false };
    // Zero fit: keep the single most significant row rather than an empty timeline.
    t.fitTo(Math.max(1, fits));
    const next = t.promptEvents.map((e) => rowOf(t, e));
    if (next.length >= rows.length) return clipOne(t, budget); // one row left, and it is too long
    rows = next;
  }
}

/**
 * The one remaining row, cut down to the budget. A burst keeps a short note of its size in place of
 * its member detail, so Watson still knows the row stands for more events than it shows.
 */
function clipOne(t: TimelineSelection, budget: number): Fitted {
  const e = t.promptEvents[0];
  if (!e) return { rows: [], clipped: false };
  const g = t.grouping.groupById.get(e.id);
  const tail = g ? ` ⟨grouped: ${g.count}× — member detail left out to fit⟩` : "";
  const room = Math.max(0, budget - 1);
  const head = rowOf(t, e, false);
  if (head.length + tail.length <= room) return { rows: [head + tail], clipped: true };
  const keep = Math.max(0, room - tail.length - CLIP_MARK.length);
  const row =
    keep > 0 ? head.slice(0, keep) + CLIP_MARK + tail : head.slice(0, Math.max(0, room - 1)) + CLIP_MARK;
  return { rows: [row], clipped: true };
}

/** In-scope events the shown rows cover; a cut-down burst covers only the row itself. */
const covered = (t: TimelineSelection, clipped: boolean): number =>
  clipped
    ? 1
    : t.promptEvents.reduce((n, e) => n + (t.grouping.memberIdsByRepresentative.get(e.id)?.length ?? 1), 0);

/**
 * The FORENSIC TIMELINE block of Watson's case context, at most `budget` characters (title and the
 * partial note included). `scoped` is the in-scope forensic timeline (scope and false-positive marks
 * applied); nothing here reads the super-timeline.
 */
export function watsonTimelineBlock(
  state: InvestigationState,
  scoped: ForensicEvent[],
  budget: number,
  aliasIndex?: HostAliasIndex,
): WatsonTimelineBlock {
  const title = titleOf(scoped.length);
  const reserve = partialNote(scoped.length, scoped.length).length + NO_ROWS.length;
  const room = Math.max(0, budget - title.length - reserve);
  const t = createTimelineSelection(state, scoped, aliasIndex);
  const { rows, clipped } = t.promptEvents.length ? fitSelection(t, room) : { rows: [], clipped: false };
  const used = rows.length ? covered(t, clipped) : 0;
  const note = used < scoped.length ? partialNote(used, scoped.length) : "";
  return { text: title + (rows.join("\n") || NO_ROWS) + note, used };
}
