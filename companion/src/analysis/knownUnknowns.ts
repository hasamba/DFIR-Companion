// Known unknowns (#165): the evidence we'd EXPECT in an intrusion but don't yet have — the gaps in
// the story. Synthesis and hunt suggestions report what the evidence shows; this surfaces what it
// DOESN'T, so the model treats the holes as open questions to investigate/hunt instead of glossing
// over them ("ransomware deployed but no initial-access vector identified", "lateral movement seen
// but no persistence", "a 3h window where every source went silent").
//
// PURE and OFFLINE — no AI, no network, no I/O. It consolidates signals the codebase already
// derives, so it adds no new detection: timeline coverage gaps (gapDetect), uncovered ATT&CK phases
// (tacticForTechniques over the findings), and the matched actors' likely-next techniques the case
// hasn't shown (adversaryEmulation, supplied by the caller). Like a gap, every line is a LEAD, not
// proof — the wording says so.

import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import { detectTimelineGaps, type GapOptions } from "./gapDetect.js";
import { tacticForTechniques, type IrisTactic } from "../integrations/iris/mitreTactics.js";
import type { NextTechnique } from "./adversaryEmulation.js";

// The kill-chain phases an intrusion usually touches. A case with real (Critical/High) findings that
// has NO finding covering one of these is a conspicuous gap worth calling out ("how did they get
// in?", "where's the persistence?"). Defense Evasion / Discovery / Collection are intentionally
// omitted — their absence is rarely a meaningful lead on its own.
const CORE_TACTICS: readonly IrisTactic[] = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Lateral Movement",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export interface KnownUnknownsOptions {
  gapOptions?: GapOptions;                      // forwarded to detectTimelineGaps
  nextTechniques?: readonly NextTechnique[];    // from adversaryEmulation — caller supplies (needs the offline dataset)
  maxGaps?: number;                             // cap on coverage-gap lines (default 3)
  maxNextTechniques?: number;                   // cap on likely-next-technique lines (default 5)
  max?: number;                                 // hard cap on TOTAL bullets in the block (default 10)
}

const DEFAULT_MAX_GAPS = 3;
const DEFAULT_MAX_NEXT = 5;
const DEFAULT_MAX_TOTAL = 10;

// Build the "known unknowns" preamble block, or "" when the case has no gaps worth surfacing.
export function buildKnownUnknowns(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
  opts: KnownUnknownsOptions = {},
): string {
  const bullets: string[] = [];

  // 1. Uncovered ATT&CK phases — only once the case has a real (Critical/High) finding, so a
  //    low-signal case doesn't spuriously claim "missing initial access". One compact line.
  const serious = state.findings.some((f) => f.severity === "Critical" || f.severity === "High");
  if (serious) {
    const covered = new Set<IrisTactic>();
    for (const f of state.findings) {
      const tac = tacticForTechniques(f.mitreTechniques ?? [], `${f.title} ${f.description}`);
      if (tac) covered.add(tac);
    }
    const missing = CORE_TACTICS.filter((t) => !covered.has(t));
    if (missing.length) {
      bullets.push(`No finding yet explains these ATT&CK phases: ${missing.join(", ")}.`);
    }
  }

  // 2. Coverage gaps — silent windows in the timeline (complete = every source dark, the strongest
  //    log-tampering lead). Complete gaps first, then partial, capped.
  const gaps = detectTimelineGaps(scopedEvents, opts.gapOptions);
  const maxGaps = Math.max(0, opts.maxGaps ?? DEFAULT_MAX_GAPS);
  const orderedGaps = [...gaps.filter((g) => g.complete), ...gaps.filter((g) => !g.complete)].slice(0, maxGaps);
  for (const g of orderedGaps) {
    const who = g.complete ? "ALL sources silent" : `silent: ${g.silentSources.join(", ") || "some sources"}`;
    bullets.push(
      `No telemetry from ${g.startTimestamp} to ${g.endTimestamp} (${g.durationLabel}; ${who}) — collection gap or cleared logs?`,
    );
  }

  // 3. Likely-next techniques — what lookalike actors use that this case hasn't shown (predictive
  //    hunt priorities; statistical similarity, NOT attribution). Caller supplies them.
  const maxNext = Math.max(0, opts.maxNextTechniques ?? DEFAULT_MAX_NEXT);
  for (const nt of (opts.nextTechniques ?? []).slice(0, maxNext)) {
    bullets.push(
      `Not yet observed: ${nt.id}${nt.name ? ` (${nt.name})` : ""} [${nt.tactic}] — used by ${nt.groupCount} lookalike group(s).`,
    );
  }

  if (!bullets.length) return "";
  const capped = bullets.slice(0, Math.max(0, opts.max ?? DEFAULT_MAX_TOTAL));
  return (
    "KNOWN UNKNOWNS / OPEN GAPS (evidence we'd expect in an intrusion but don't yet have — treat each " +
    "as an open question to investigate or hunt; an absence is a lead, not proof):\n" +
    capped.map((b) => `- ${b}`).join("\n") +
    "\n\n"
  );
}
