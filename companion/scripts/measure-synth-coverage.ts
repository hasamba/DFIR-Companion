// Measure how much of a real case's forensic timeline fits the synthesis prompt once detection bursts
// are grouped.
//
// Why it exists: full AI coverage of the timeline was scoped as three tiers — (1) group bursts so a
// repetitive detection costs one prompt row, (2) select what remains by severity and rarity, and
// (3) a batched deep pass that runs synthesis over the timeline in chunks so nothing is unseen.
// Tier 3 is much the most expensive, in tokens and in complexity. This script is the evidence for
// whether it is needed at all: run it against real cases, and if the grouped timeline already fits
// the prompt cap, tier 3 buys nothing and should be dropped rather than built.
//
// Usage (from companion/):  npx tsx scripts/measure-synth-coverage.ts <path-to-investigation.json>

// IMPORTANT: this must mirror pipeline.synthesize() exactly — same eligibility filter, same grouping
// options, same cap — or it reports a number the pipeline cannot deliver. It previously applied its own
// non-Info filter that the pipeline did not, and overstated coverage as a result.

import { readFile } from "node:fs/promises";
import type { ForensicEvent } from "../src/analysis/stateTypes.js";
import { collapseForPrompt, groupEnvOptions, maxPromptEvents, promptCandidates } from "../src/analysis/synthGroup.js";
import { selectSynthesisEventsAnnotated } from "../src/analysis/synthSelect.js";

const file = process.argv[2];
if (!file) {
  console.error("usage: npx tsx scripts/measure-synth-coverage.ts <path-to-investigation.json>");
  process.exit(1);
}

const raw = JSON.parse(await readFile(file, "utf8")) as { forensicTimeline?: ForensicEvent[] };
const all = raw.forensicTimeline ?? [];
const nonInfo = all.filter((e) => e.severity !== "Info");
const cap = maxPromptEvents();

// Same eligibility rule the pipeline applies (drops Info unless DFIR_SYNTH_INCLUDE_INFO=1).
const eligible = promptCandidates(all);
const { events: collapsed, memberIdsByRepresentative } = collapseForPrompt(eligible, groupEnvOptions());
const selection = selectSynthesisEventsAnnotated(collapsed, cap);

const represented = new Set<string>();
for (const e of selection.events) {
  represented.add(e.id);
  for (const id of memberIdsByRepresentative.get(e.id) ?? []) represented.add(id);
}

// The number that matters: how many GRADED (non-Info) events actually reach the model.
const nonInfoRepresented = nonInfo.filter((e) => represented.has(e.id)).length;
const missing = nonInfo.length - nonInfoRepresented;
const pct = nonInfo.length ? Math.round((nonInfoRepresented / nonInfo.length) * 1000) / 10 : 100;

console.log(`forensic timeline events ....... ${all.length}`);
console.log(`non-Info events ................ ${nonInfo.length}`);
console.log(`eligible for the prompt ........ ${eligible.length}${eligible.length < all.length ? `  (${all.length - eligible.length} Info excluded)` : ""}`);
console.log(`distinct rows after grouping ... ${collapsed.length}`);
console.log(`prompt cap ..................... ${cap}`);
console.log(`rows selected .................. ${selection.events.length}`);
console.log(`NON-INFO represented ........... ${nonInfoRepresented} / ${nonInfo.length} (${pct}%)`);
console.log(missing === 0
  ? "\nVERDICT: every graded event reaches the model — tier 3 (batched deep pass) is NOT needed for this case."
  : `\nVERDICT: ${missing} graded event(s) never reach the model — raise DFIR_AI_SYNTH_MAX_EVENTS (needs ${collapsed.length}) or consider tier 3.`);
