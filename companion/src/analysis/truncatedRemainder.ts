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
 * Type order for the list. Network infrastructure first, because "which host did it talk to" is the
 * question the silent cut made unanswerable — and because when the budget runs out, the type that
 * gets cut should be the one an analyst can most easily recover from elsewhere in the case.
 */
const TYPE_ORDER: readonly SiemIoc["type"][] = ["url", "domain", "ip", "sid", "hash"];

function rank(type: SiemIoc["type"]): number {
  const i = TYPE_ORDER.indexOf(type);
  return i < 0 ? TYPE_ORDER.length : i;
}

/**
 * One line describing what a cap removed, ready to append to the text that survived it.
 *
 * Returns "" only for an empty remainder — nothing was cut, so there is nothing to disclose. A
 * remainder that holds no indicators still gets a note: an analyst has to be able to tell "the cut
 * text was checked and held none" apart from "nobody looked". Pure; `dropped` is never mutated.
 */
export function remainderNote(dropped: string): string {
  if (!dropped) return "";
  const sink = new Map<string, SiemIoc>();
  textIocs(dropped, sink); // linear in `dropped` — see textIocs' own note on why it has no input cap
  const found = [...sink.values()].sort((a, b) => rank(a.type) - rank(b.type));
  const head = `[cut here: ${dropped.length} more characters`;
  if (found.length === 0) return `\n\n${head} — no indicators in the cut text]`;

  // Group runs of the same type under one label ("domain: a, b, c"), so the budget buys values
  // rather than repeated type names.
  const parts: string[] = [];
  let printed = 0;
  let used = 0;
  let lastType = "";
  for (const ioc of found) {
    const cost = ioc.value.length + 2;
    if (used + cost > REMAINDER_VALUE_BUDGET) break;
    parts.push(
      ioc.type === lastType ? `, ${ioc.value}` : `${parts.length ? "; " : ""}${ioc.type}: ${ioc.value}`,
    );
    lastType = ioc.type;
    used += cost;
    printed++;
  }
  const more = found.length - printed;
  const tail = more > 0 ? ` (+${more} more)` : "";
  return `\n\n${head} — indicators in the cut text: ${parts.join("")}${tail}]`;
}
