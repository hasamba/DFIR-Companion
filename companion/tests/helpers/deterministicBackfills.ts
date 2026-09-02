// The deterministic backfill passes, each one runnable, in the single place both guards read.
//
// A pass mints findings the AI did not: an uncovered Critical/High artifact row, a window where
// every source went dark, the intrusion's wave cadence. `carryOutOfWindowFindings` re-attaches such
// a finding across a narrowed scope window (#751) only if TWO things hold — the id shape is
// registered in responseSchema.ts, and the finding is back-linked to an event, since
// `supportingEventIds` drops an unlinked finding as "nothing proves it is outside the window".
//
// This table is what lets both be checked against the real pass rather than a hand-written
// imitation of it. It lives in a helper rather than in either test because both read it:
// tests/analysis/deterministicFindingIds.test.ts runs each entry, and
// tests/architecture/deterministicFindingMint.test.ts parses src/analysis and fails when an
// `export function backfill*` is missing from it. Importing one test file from another would work
// and would also run every test in it twice.
import { backfillActivityWaveFinding, detectGapsWithWaves } from "../../src/analysis/activityWaves.js";
import { backfillSilenceGapFindings, detectTimelineGaps } from "../../src/analysis/gapDetect.js";
import { backfillHighSeverityFindings } from "../../src/analysis/highSeverityFindings.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

const event = (id: string, timestamp: string): ForensicEvent => ({
  id,
  timestamp,
  description: `event ${id}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

// Two bursts three weeks apart: enough silence between them for a complete gap AND the wave
// cadence, so one timeline drives all three passes.
export const burstEvents: ForensicEvent[] = [
  ...[0, 1, 2].map((i) => event(`a${i}`, `2026-01-01T00:0${i}:00.000Z`)),
  ...[0, 1, 2].map((i) => event(`b${i}`, `2026-01-20T00:0${i}:00.000Z`)),
];

const stamp = "2026-01-21T00:00:00.000Z";
const seed = (): InvestigationState => ({ ...emptyState("c1"), forensicTimeline: burstEvents });

/**
 * Each entry RUNS the real pass and hands back the state it produced.
 *
 * ADD A NEW BACKFILL HERE. `name` is the EXPORTED function's name, not a label — the architecture
 * gate parses src/analysis for every `export function backfill*` and fails when one is missing from
 * this list, so this is a checked obligation rather than a comment hoping to be remembered.
 */
export const BACKFILLS: { name: string; run: () => InvestigationState }[] = [
  {
    name: "backfillHighSeverityFindings",
    run: () => backfillHighSeverityFindings(seed(), new Set(burstEvents.map((e) => e.id)), stamp),
  },
  {
    name: "backfillSilenceGapFindings",
    run: () => backfillSilenceGapFindings(seed(), detectTimelineGaps(burstEvents), stamp),
  },
  {
    name: "backfillActivityWaveFinding",
    run: () => backfillActivityWaveFinding(seed(), detectGapsWithWaves(burstEvents).pattern, stamp),
  },
];
