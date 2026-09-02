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
// backfill export is not run by it. Importing one test file from another would work
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
 * One entry: the pass itself, plus the arguments to call it with.
 *
 * `name` is DERIVED from the function rather than written beside it, and `run` calls that same
 * reference. This is the whole point of the shape. When the two were independent fields, a new
 * entry copied from an old one could carry a new `name` while its `run` still invoked the pass it
 * was copied from: the completeness gate below saw the new name and passed, both behaviour tests
 * ran the OLD pass a second time, and the new pass shipped with neither its id shape nor its event
 * linkage ever checked — the silence this file exists to break, wearing a green tick. Now the name
 * and the callee are one reference, so they cannot disagree.
 *
 * The arguments are a thunk, not a value: each entry seeds its own state, and sharing one would let
 * whichever pass ran first hand its findings to the next.
 */
// Curried, so the pass's parameter tuple is fixed by the FIRST call and the argument list in the
// second is then checked against it. Taking both at once, TypeScript infers the tuple from the
// thunk as well, the two candidates disagree, and the arguments widen to a plain union array that
// no longer has to match the pass's signature — the type stops checking the one thing it is for.
export interface BackfillEntry {
  // The pass itself, for the architecture gate to compare against the modules' own exports. Typed
  // `object` rather than a call signature because it is only ever compared by identity: a function
  // IS an object, every pass's parameters differ, and a shared signature here would either lie
  // about them or need a cast at each entry.
  fn: object;
  name: string;
  run: () => InvestigationState;
}

const pass =
  <A extends unknown[]>(fn: (...args: A) => InvestigationState) =>
  (args: () => A): BackfillEntry => ({
    fn,
    name: fn.name,
    run: () => fn(...args()),
  });

/**
 * Each entry RUNS the real pass and hands back the state it produced.
 *
 * ADD A NEW BACKFILL HERE. The architecture gate loads every module under src/ that exports a
 * backfill and compares those functions with `fn` BY REFERENCE, so this is a checked obligation
 * rather than a comment hoping to be remembered — and a stub named after a real pass fails it.
 */
export const BACKFILLS = [
  pass(backfillHighSeverityFindings)(() => [seed(), new Set(burstEvents.map((e) => e.id)), stamp]),
  pass(backfillSilenceGapFindings)(() => [seed(), detectTimelineGaps(burstEvents), stamp]),
  pass(backfillActivityWaveFinding)(() => [seed(), detectGapsWithWaves(burstEvents).pattern, stamp]),
];
