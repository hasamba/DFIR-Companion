// What a message cap removed, said out loud.
//
// An importer that stores a long event message has to bound it, or one quoted 100 KB ScriptBlockText
// lands in case state on every row that matched it. So the text is cut. The cut itself is right.
// What was wrong is that it was SILENT.
//
// On a real case (INC-2026-001, a Lunar Spider simulation) 181 events each stored exactly 4,001
// characters of PowerShell — the cap plus its ellipsis. The script kept its C2 table 7,626
// characters in, past the cut, so every stored event showed four thousand characters of setup code
// and not one attacker host, and the synthesis over those events reported no confirmed C2
// infrastructure. Seventeen C2 domains, ten C2 addresses, an RC4 key and an exfil endpoint were in
// the collected file the whole time; nothing in the case said a table had been dropped.
//
// This module builds the one line that says it: how much text the cut removed, and which indicators
// were in it. The line is appended AFTER the cap, so it is small, bounded, and always survives —
// raising the cap would have grown every long row instead of the few that hide something.
//
// It reads the DROPPED text only. Indicators before the cut are already in the stored message, and
// repeating them would spend the budget on what the analyst can already see.

import { textIocs, type SiemIoc } from "./siemImport.js";

/**
 * Characters of indicator VALUES the note may print. A cap on the list, not on the scan: everything
 * the remainder holds is counted, and whatever does not fit is reported as "+N more" rather than
 * quietly dropped. 600 is 15% of velociraptorImport's 4,000-character message cap — enough for the
 * real case's 29 values (10 addresses, 19 domains, ~500 characters), small enough that a note can
 * never rival the evidence it annotates.
 */
export const REMAINDER_VALUE_BUDGET = 600;

/**
 * How far back into the KEPT text the scan starts. A cap cuts on a character count, not on a token
 * boundary, so it lands mid-value as readily as between two: the kept text ends with a dangling
 * "c2-strad" and the dropped text opens with "dler.example.net". Scanning the dropped side alone
 * then reports a suffix that never existed — a wrong indicator an analyst can pivot on and find
 * nothing, with no sign the value was cut in half. Starting the scan a little BEFORE the cut hands
 * the extractor the whole value again; whatever the kept text already shows in full is filtered out
 * afterwards, so the look-back costs no budget.
 *
 * 512 characters covers every value the extractor can produce: a domain stops at 253, a SHA256 at
 * 64, an IPv4 at 15. A URL can exceed it, but a mid-URL start cannot masquerade as a URL — the
 * pattern is anchored on `https?://` — so the overflow case degrades to "not listed", never to
 * "listed wrong".
 */
export const REMAINDER_OVERLAP = 512;

/**
 * Type order for the list. Network infrastructure first, because "which host did it talk to" is the
 * question the silent cut made unanswerable.
 *
 * URLs come LAST despite being infrastructure, and that is the point: one is up to 300 characters
 * and half the budget, while the host inside it is 17 and `textIocs` already extracts that host
 * separately as a domain (or an ip). Listing URLs first spent the whole budget naming four servers
 * in full and pushed every remaining C2 domain into "+N more" — the long form crowding out the very
 * answer it contains. Ordered this way the note names every host it found, then spends what is left
 * on the paths.
 */
const TYPE_ORDER: readonly SiemIoc["type"][] = ["domain", "ip", "sid", "hash", "url"];

function rank(type: SiemIoc["type"]): number {
  const i = TYPE_ORDER.indexOf(type);
  return i < 0 ? TYPE_ORDER.length : i;
}

/**
 * One line describing what a cap removed, ready to append to the text that survived it.
 *
 * `kept` is the text the cap left in place and `dropped` is what it took. Both are needed: the size
 * of the cut is `dropped`'s, but the SCAN starts inside `kept` so a value the cut split in half is
 * read whole (see REMAINDER_OVERLAP), and anything `kept` already shows in full is then left out.
 *
 * Returns "" only for an empty remainder — nothing was cut, so there is nothing to disclose. A
 * remainder that holds no indicators still gets a note: an analyst has to be able to tell "the cut
 * text was checked and held none" apart from "nobody looked". Pure; neither input is mutated.
 */
export function remainderNote(kept: string, dropped: string): string {
  if (!dropped) return "";
  const sink = new Map<string, SiemIoc>();
  // Linear in the scanned text — see textIocs' own note on why it has no input cap.
  textIocs(kept.slice(-REMAINDER_OVERLAP) + dropped, sink);
  const keptLower = kept.toLowerCase();
  const found = [...sink.values()]
    // Already readable above the cut ⇒ not something the cut removed. Budget spent on it is budget
    // stolen from a value the analyst genuinely cannot see. textIocs lowercases what it normalizes,
    // so the containment test is done on one case.
    .filter((i) => !keptLower.includes(i.value.toLowerCase()))
    .sort((a, b) => rank(a.type) - rank(b.type));
  const head = `[cut here: ${dropped.length} more characters`;
  if (found.length === 0) return `\n\n${head} — no indicators in the cut text]`;

  // Group runs of the same type under one label ("domain: a, b, c"), so the budget buys values
  // rather than repeated type names.
  const parts: string[] = [];
  let printed = 0;
  let used = 0;
  let lastType = "";
  for (const ioc of found) {
    const seg =
      ioc.type === lastType ? `, ${ioc.value}` : `${parts.length ? "; " : ""}${ioc.type}: ${ioc.value}`;
    // SKIP the value that does not fit, do not stop at it. One 300-character URL would otherwise
    // silence every short domain and address behind it, leaving the note reporting the least useful
    // thing it found — the opposite of listing infrastructure first. A skipped value still counts
    // toward "+N more", so the tally stays honest about everything the note did not print.
    if (used + seg.length > REMAINDER_VALUE_BUDGET) continue;
    parts.push(seg);
    lastType = ioc.type;
    used += seg.length;
    printed++;
  }
  const more = found.length - printed;
  const tail = more > 0 ? ` (+${more} more)` : "";
  return `\n\n${head} — indicators in the cut text: ${parts.join("")}${tail}]`;
}

/**
 * The cap on a stored event message. It is what keeps one 100 KB ScriptBlockText out of case state
 * on every row that quotes it, and it is not the lever to reach for when a long message hides
 * something — see this module's header for what is.
 */
export const MESSAGE_CAP = 4000;

/**
 * The full event detail (raw EVTX rendered Message / ScriptBlock text, etc.) an analyst may want to
 * read beyond the one-line `description`, capped, and — when the cap bit — carrying the note that
 * says what the cap removed.
 *
 * Returns "" when there is no message, or when it adds nothing beyond `description`, so a redundant
 * expandable block is never stamped onto an event.
 *
 * Where the result is read: the analyst expands it on the super-timeline row, and the local text
 * consumers (second-look keyword search, CVE/KEV grounding) match on it. The synthesis prompt
 * renders `description`, not `message`, so the note costs the model no tokens — see
 * renderPromptEvent in ai/synthesisPromptEvents.ts.
 */
export function cappedMessage(message: string, description: string): string {
  const raw = message.trim();
  if (!raw) return "";
  // If the description already contains (nearly) the whole message there's no extra detail to reveal.
  if (description.includes(raw) || raw.length <= 80) return "";
  if (raw.length <= MESSAGE_CAP) return raw;
  const kept = raw.slice(0, MESSAGE_CAP);
  return `${kept}…${remainderNote(kept, raw.slice(MESSAGE_CAP))}`;
}
