// Batched deep pass (spec 2026-07-21-batched-deep-pass-design.md) — PURE core.
//
// Normal synthesis shows the model one prompt's worth of events. Row count scales with hosts, so a
// real multi-host engagement leaves most graded detections unread: measured after grouping, a 12-host
// case needs 5 prompts and a 14-host case 13. This module supports an analyst-triggered pass that
// reads them ALL, in as many batches as required.
//
// The contract that makes batching safe: a batch returns OBSERVATIONS — factual pointers at specific
// event ids — never findings, severities or narrative. Handed a slice of mostly-benign activity and
// asked for "the attack story", the model fabricates one (halcyon and fairhaven both did); running
// that prompt 13 times would produce 13 confident, conflicting stories. Observations cannot conflict
// that way, and exactly one final synthesis call draws conclusions.
//
// Everything here is pure and deterministic: no I/O, no AI, no state mutation.

import type { ForensicEvent, Severity } from "./stateTypes.js";
import { SEVERITY_RANK, applySeverityFloor } from "./severityFloor.js";
import { collapseForPrompt, groupEnvOptions, promptCandidates } from "./synthGroup.js";
import { estimateTokens } from "./promptBudget.js";
import { byEventTime } from "./forensicSort.js";

// Refuse rather than silently start a very expensive job. The analyst is told which floor would fit.
export const DEFAULT_MAX_BATCHES = 30;

// Floors the preview offers, most severe first. Info is never a floor: Info events are excluded from
// AI prompts entirely (see synthGroup.promptCandidates), so offering it would promise events that
// would then be dropped.
export const FLOOR_CHOICES: readonly Severity[] = ["Critical", "High", "Medium", "Low"];

export interface FloorOption {
  floor: Severity;
  events: number;                 // graded events at or above this floor
  rows: number;                   // prompt rows after detection-burst grouping
  batches: number;                // how many AI calls the batching stage would make
  estimatedInputTokens: number;   // rendered timeline cost across all batches
}

export interface PreviewOptions {
  cap?: number;                   // rows per batch; defaults to the synthesis event cap
  env?: NodeJS.ProcessEnv;
}

// One prompt line's worth of text, for estimation only — mirrors the shape pipeline.renderEvent
// produces (id + timestamp + severity + description + tags) without importing it.
function estimateRow(e: ForensicEvent): number {
  return estimateTokens(`[${e.id}] ${e.timestamp} [${e.severity}] ${e.description.slice(0, 240)}`) + 30;
}

/**
 * Volume at every floor, so the analyst chooses against real numbers instead of guessing. Info events
 * are excluded first (they never reach a prompt), then the shared severityFloor gate is applied, then
 * grouping — the same sequence the run itself uses, so the preview cannot promise what the run will
 * not deliver.
 */
export function previewFloors(
  events: readonly ForensicEvent[],
  opts: PreviewOptions = {},
): FloorOption[] {
  const env = opts.env ?? process.env;
  const cap = Math.max(1, Math.floor(opts.cap ?? 0)) || 1;
  const graded = promptCandidates(events, env);          // drops Info unless explicitly re-enabled
  return FLOOR_CHOICES.map((floor) => {
    const kept = applySeverityFloor([...graded], floor);
    const { events: rows } = collapseForPrompt(kept, groupEnvOptions(env));
    return {
      floor,
      events: kept.length,
      rows: rows.length,
      batches: Math.ceil(rows.length / cap),
      estimatedInputTokens: rows.reduce((sum, e) => sum + estimateRow(e), 0),
    };
  });
}

/**
 * Split prompt rows into chronological batches of at most `cap`. Chronological on purpose: a batch is
 * then a contiguous window of the case, which reads coherently, rather than an arbitrary scatter.
 * A batch boundary can still cut an attack chain in half — accepted, because batches only report
 * observations and the final synthesis reassembles them.
 */
export function planBatches(rows: readonly ForensicEvent[], cap: number): ForensicEvent[][] {
  if (!rows.length) return [];
  const size = Math.max(1, Math.floor(cap) || 1);
  const sorted = [...rows].sort(byEventTime);
  const out: ForensicEvent[][] = [];
  for (let i = 0; i < sorted.length; i += size) out.push(sorted.slice(i, i + size));
  return out;
}

/** Floors that would keep the run at or under `maxBatches`, most severe first. */
export function floorsWithinBudget(options: readonly FloorOption[], maxBatches: number): Severity[] {
  return options.filter((o) => o.batches > 0 && o.batches <= maxBatches).map((o) => o.floor);
}

export { SEVERITY_RANK };
