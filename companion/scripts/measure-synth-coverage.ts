// Measure how much of a real case's forensic timeline fits the synthesis prompt once detection bursts
// are grouped. This is the decision input for tier 3 (the batched deep pass) in
// docs/superpowers/specs/2026-07-21-forensic-timeline-ai-coverage-design.md: if the collapsed set fits
// the cap on real imports, tier 3 is unnecessary and should be dropped.
//
// Usage (from companion/):  npx tsx scripts/measure-synth-coverage.ts <path-to-investigation.json>

import { readFile } from "node:fs/promises";
import type { ForensicEvent } from "../src/analysis/stateTypes.js";
import { collapseForPrompt, groupEnvOptions } from "../src/analysis/synthGroup.js";
import { selectSynthesisEventsAnnotated } from "../src/analysis/synthSelect.js";

const file = process.argv[2];
if (!file) {
  console.error("usage: npx tsx scripts/measure-synth-coverage.ts <path-to-investigation.json>");
  process.exit(1);
}

const raw = JSON.parse(await readFile(file, "utf8")) as { forensicTimeline?: ForensicEvent[] };
const all = raw.forensicTimeline ?? [];
const nonInfo = all.filter((e) => e.severity !== "Info");
const cap = Number(process.env.DFIR_AI_SYNTH_MAX_EVENTS) || 300;

const { events: collapsed, memberIdsByRepresentative } = collapseForPrompt(nonInfo, groupEnvOptions());
const selection = selectSynthesisEventsAnnotated(collapsed, cap);

const represented = new Set<string>();
for (const e of selection.events) {
  represented.add(e.id);
  for (const id of memberIdsByRepresentative.get(e.id) ?? []) represented.add(id);
}

const pct = nonInfo.length ? Math.round((represented.size / nonInfo.length) * 1000) / 10 : 100;
console.log(`forensic timeline events ....... ${all.length}`);
console.log(`non-Info events ................ ${nonInfo.length}`);
console.log(`distinct rows after grouping ... ${collapsed.length}`);
console.log(`prompt cap ..................... ${cap}`);
console.log(`rows selected .................. ${selection.events.length}`);
console.log(`non-Info events represented .... ${represented.size} (${pct}%)`);
console.log(represented.size >= nonInfo.length
  ? "\nVERDICT: full coverage — tier 3 (batched deep pass) is NOT needed for this case."
  : `\nVERDICT: ${nonInfo.length - represented.size} event(s) unrepresented — tier 3 may be justified.`);
