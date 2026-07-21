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

// How many observations one batch may contribute. Bounds the final digest by construction:
// maxBatches × this is the worst case the reduce step ever has to read.
export const OBSERVATION_CAP_PER_BATCH = 15;

const SUMMARY_MAX = 300;
const WHY_MAX = 300;
const HOSTS_MAX = 8;
const EVENT_IDS_MAX = 12;

/**
 * One factual pointer at specific events. Deliberately carries NO severity, title, confidence or
 * MITRE field: a batch sees a slice of the case and must not be able to render a verdict on it.
 * The final synthesis is the only place conclusions are drawn.
 */
export interface Observation {
  summary: string;
  whyItMatters: string;
  eventIds: string[];
  hosts?: string[];
  firstSeen?: string;
  lastSeen?: string;
}

function str(v: unknown, max: number): string {
  return String(v ?? "").trim().slice(0, max);
}

function strList(v: unknown, max: number): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of v) {
    const s = String(item ?? "").trim();
    if (!s || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= max) break;
  }
  return out;
}

/**
 * Validate a batch's raw JSON into observations. Unknown fields (a smuggled `severity`, `title`, …)
 * are dropped by construction because only the known fields are read. An observation whose event ids
 * are all unknown to the case is discarded entirely — an observation with no real evidence behind it
 * is exactly the fabrication this design exists to prevent.
 */
export function sanitizeObservations(raw: unknown, validEventIds: ReadonlySet<string>): Observation[] {
  const list = (raw as { observations?: unknown })?.observations;
  if (!Array.isArray(list)) return [];
  const out: Observation[] = [];
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    const eventIds = strList(o.eventIds, EVENT_IDS_MAX).filter((id) => validEventIds.has(id));
    if (!eventIds.length) continue;
    const summary = str(o.summary, SUMMARY_MAX);
    if (!summary) continue;
    const hosts = strList(o.hosts, HOSTS_MAX);
    const firstSeen = str(o.firstSeen, 40);
    const lastSeen = str(o.lastSeen, 40);
    out.push({
      summary,
      whyItMatters: str(o.whyItMatters, WHY_MAX),
      eventIds,
      ...(hosts.length ? { hosts } : {}),
      ...(firstSeen ? { firstSeen } : {}),
      ...(lastSeen ? { lastSeen } : {}),
    });
    if (out.length >= OBSERVATION_CAP_PER_BATCH) break;
  }
  return out;
}

/**
 * The prompt block the FINAL synthesis receives. Labelled explicitly as evidence from parts of the
 * timeline the model is not being shown row-by-row, so it weighs them as reported evidence rather
 * than assuming it saw them itself.
 */
export function renderObservationDigest(observations: readonly Observation[]): string {
  if (!observations.length) return "";
  const lines = observations.map((o) => {
    const where = o.hosts?.length ? ` on ${o.hosts.join(", ")}` : "";
    const when = o.firstSeen
      ? ` (${o.firstSeen}${o.lastSeen && o.lastSeen !== o.firstSeen ? ` → ${o.lastSeen}` : ""})`
      : "";
    const why = o.whyItMatters ? ` — ${o.whyItMatters}` : "";
    return `- ${o.summary}${where}${when}${why} [events: ${o.eventIds.join(", ")}]`;
  });
  return (
    "DEEP-PASS OBSERVATIONS (a batched read of the REST of the timeline — these events are NOT shown " +
    "to you row-by-row below, so treat each line as reported evidence you may cite by its event ids; " +
    "they carry no severity verdict of their own):\n" +
    lines.join("\n") +
    "\n\n"
  );
}

export { SEVERITY_RANK };
