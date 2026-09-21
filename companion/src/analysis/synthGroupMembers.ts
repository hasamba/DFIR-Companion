// The members of a grouped prompt row, when their command lines differ (#1501).
//
// synthGroup.ts collapses a detection burst into ONE prompt row keyed on severity + hash (or rule
// head). For process creations the hash identifies the BINARY, not the activity: six launches of one
// renamed cmd.exe — `/c whoami`, `/c net user`, `/c tasklist`… — grouped as "6× identical detection"
// and the model read only the representative's command. The other five discovery commands never
// reached it as attributable rows, and the linker (synthesisMerge.ts) attaches only the ids the model
// cites, so those rows stayed linked to nothing while the synthesis wrote "no initial-access vector".
//
// One seat still stands for the burst — that is what grouping is for — but the row now names each
// member whose command differs, with its id, time and host, so the model can cite `14e80` directly.
// Pure and prompt-only: derived on read, nothing in the case is touched.

import type { ForensicEvent } from "./stateTypes.js";
import { eventCommandLine } from "./chainSignature.js";
import { stripImagePrefix, ARGS_MARKER, COMMAND_FIELD_CAP } from "./renderCommandLine.js";

/** How many member lines one grouped row spells out; the rest are counted. */
export const DEFAULT_MAX_MEMBER_LINES = 12;
/** Per-line cap on the rendered arguments — the command-field cap, so a target at the tail survives. */
export const MEMBER_LINE_CAP = COMMAND_FIELD_CAP;
// Kept from the end of a capped command: URLs, remotes and the last `/c <command>` sit there.
const LINE_TAIL = 96;
const ELLIPSIS = " … ";

export interface GroupMemberLines {
  /** `[<id> <HH:MM:SS> <host>] <args>` per member whose command differs, member order, capped. */
  lines: string[];
  /** Distinct command lines across the whole burst, the representative's included. */
  distinct: number;
  /** Distinct member commands beyond the cap, counted rather than shown. */
  more: number;
}

// The arguments of a member's command line as the analyst would read them: the structured field
// first (its image dropped the way the description renders it, `… /c whoami`), else the command the
// description carries. Empty when the member has no command line at all.
function memberArgs(e: ForensicEvent): string {
  const structured = (e.commandLine ?? "").replace(/\s+/g, " ").trim();
  if (structured) {
    const stripped = stripImagePrefix(structured, e.path ?? "");
    if (stripped !== structured) return stripped;
    // A path that is not the image (or none): drop the leading token, quoted or bare.
    const m = /^(?:"[^"]*"|\S+)\s+(.+)$/.exec(structured);
    return m ? `${ARGS_MARKER} ${m[1]}` : structured;
  }
  return eventCommandLine(e);
}

function capLine(text: string): string {
  if (text.length <= MEMBER_LINE_CAP) return text;
  const head = MEMBER_LINE_CAP - LINE_TAIL - ELLIPSIS.length;
  return `${text.slice(0, head).trimEnd()}${ELLIPSIS}${text.slice(text.length - LINE_TAIL).trimStart()}`;
}

// The asset as the row carries it. Not cut at the first dot: importers use IP literals as assets,
// and `10.1.1.5` / `10.2.2.6` must not both read as `10` on a burst that crosses hosts.
function memberTag(e: ForensicEvent): string {
  const ms = Date.parse(e.timestamp);
  const clock = Number.isNaN(ms) ? "" : new Date(ms).toISOString().slice(11, 19);
  const host = (e.asset ?? "").trim();
  return `[${[e.id, clock, host].filter(Boolean).join(" ")}]`;
}

/**
 * One line per member whose command differs from the representative's and from every earlier
 * member's. `members` is the burst in chronological order, representative first. Two commands are
 * the same when their ARGUMENTS read the same: the image spelling and runs of whitespace do not
 * split them, but case does — `-enc AAAA` and `-enc aaaa` are two payloads, and folding them would
 * drop the second without a line or a count. (chainSignature's lowercased identity is for
 * cross-tool correlation, where that trade goes the other way; it is deliberately not reused.)
 */
export function groupMemberLines(
  members: readonly ForensicEvent[],
  max = DEFAULT_MAX_MEMBER_LINES,
): GroupMemberLines {
  const seen = new Set<string>();
  const lines: string[] = [];
  let more = 0;
  members.forEach((e, index) => {
    const identity = memberArgs(e);
    if (!identity || seen.has(identity)) return;
    seen.add(identity);
    if (index === 0) return; // the representative's own command is already on its row
    if (lines.length >= max) {
      more += 1;
      return;
    }
    lines.push(`${memberTag(e)} ${capLine(memberArgs(e))}`);
  });
  return { lines, distinct: seen.size, more };
}

/** The suffix fragment a grouped row appends when its members differ; empty when they do not. */
export function renderGroupMembers({ lines, distinct, more }: GroupMemberLines): string {
  if (!lines.length) return "";
  const rest = more > 0 ? `; +${more} more` : "";
  return `; ${distinct} distinct command lines — ${lines.join("; ")}${rest}`;
}
