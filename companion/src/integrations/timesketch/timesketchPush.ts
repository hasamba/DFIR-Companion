// Orchestrates a Companion → Timesketch push: log in, find-or-create the sketch by name (= the
// Companion case id), then upload an event list as a Timesketch timeline. Idempotent — the managed
// timeline is replaced, never duplicated, mirroring how the IRIS push clean-replaces its notes.
// The replace is UPLOAD-FIRST (#2414, timesketchSwap.ts): the new events go up under a staging name,
// and only once every upload request was accepted are the old copies deleted and the staging
// timeline renamed. A failed upload leaves the old timeline in place.
//
// Two public entry points: pushCaseToTimesketch (the forensic timeline, from InvestigationState,
// one upload) and pushSuperTimelineToTimesketch (the super-timeline, streamed from
// SuperTimelineStore.eventBatches() as CHUNKED uploads — #1444: a capped super-timeline is 900k
// events, which is neither one array nor one JSONL string this process can hold). Both push into
// the SAME sketch (named after the case id) but write to two DIFFERENTLY-NAMED timelines inside
// it, so pushing one never replaces the other.
//
// The client is injected as a structural interface so this is unit-testable with a mock (no
// network), matching the IRIS-push / enrichment-service pattern.

import type { ForensicEvent, InvestigationState } from "../../analysis/stateTypes.js";
import { mapForensicEvent, splitTimesketchEvents, timesketchOmittedWarning } from "./timesketchMap.js";
import type { TimesketchSketchRef, TimesketchTimelineRef } from "./timesketchClient.js";
import {
  abortSwap,
  beginSwap,
  commitSwap,
  type StagedTimeline,
  type TimelineSwap,
} from "./timesketchSwap.js";

// Structural subset of TimesketchClient used here — lets tests pass a lightweight mock.
export interface TimesketchClientLike {
  login(): Promise<void>;
  findSketchByName(name: string): Promise<TimesketchSketchRef | null>;
  createSketch(name: string, description: string): Promise<TimesketchSketchRef>;
  listTimelines(sketchId: number): Promise<TimesketchTimelineRef[]>;
  deleteTimeline(sketchId: number, timelineId: number): Promise<void>;
  /** Rename a timeline in place, keeping its colour (#2414 — the last step of the swap). */
  renameTimeline(
    sketchId: number,
    timelineId: number,
    name: string,
    opts?: { color?: string },
  ): Promise<void>;
  uploadEvents(
    sketchId: number,
    timelineName: string,
    jsonl: string,
    opts?: { dataLabel?: string },
  ): Promise<StagedTimeline>;
  /**
   * One chunk of a streamed upload (#1444). The first chunk opens the index and returns its name;
   * later chunks pass that `indexName` back so Timesketch appends to the same timeline, and
   * `last: true` closes the stream so the timeline is indexed.
   */
  uploadEventsChunk(
    sketchId: number,
    timelineName: string,
    jsonl: string,
    chunk: { indexName?: string; last: boolean; dataLabel?: string },
  ): Promise<StagedTimeline & { indexName: string }>;
}

export interface TimesketchPushInput {
  sketchName: string; // = the Companion case id (used as the Timesketch sketch name)
  state: InvestigationState;
  timelineName?: string; // overrides the default managed-timeline name
}

export interface TimesketchSuperPushInput {
  sketchName: string; // = the Companion case id (used as the Timesketch sketch name)
  events: AsyncIterable<readonly ForensicEvent[]>; // the super-timeline, one store batch at a time
  timelineName?: string; // overrides the default managed-timeline name
}

export interface TimesketchPushOptions {
  baseUrl?: string; // to build a clickable sketch URL in the result
  timelineName?: string; // managed FORENSIC timeline name (default "DFIR-Companion Forensic Timeline")
  chunkEvents?: number; // super push: events per chunked upload (default SUPER_PUSH_CHUNK_EVENTS)
}

export interface TimesketchPushResult {
  sketchId: number;
  sketchName: string;
  created: boolean; // true = the sketch was newly created
  timelineName: string; // the name in place at the end — the staging name when the swap stopped short
  events: number; // events uploaded (with a parseable timestamp)
  omitted: number; // events left out for lack of one — also named in `warnings` (#957)
  replacedTimeline: boolean; // true = an older copy was removed AND the new one took its name
  sketchUrl?: string;
  warnings: string[];
}

const DEFAULT_TIMELINE = "DFIR-Companion Forensic Timeline";
const DEFAULT_SUPER_TIMELINE = "DFIR-Companion Super Timeline";
// Events per chunked super-timeline upload: ~5–15 MB of JSONL per request, well under both V8's
// string ceiling and Timesketch's upload limits, and few enough requests for a capped case.
const SUPER_PUSH_CHUNK_EVENTS = 5000;
const NOTHING_TO_UPLOAD = "no events with a parseable timestamp to upload; existing timeline left untouched";

interface PushOutcome {
  timelineName: string;
  replacedTimeline: boolean;
}

function pushResult(
  opened: { sketch: TimesketchSketchRef; created: boolean },
  counts: { events: number; omitted: number },
  outcome: PushOutcome,
  options: TimesketchPushOptions,
  warnings: string[],
): TimesketchPushResult {
  const { sketch, created } = opened;
  return {
    sketchId: sketch.id,
    sketchName: sketch.name,
    created,
    timelineName: outcome.timelineName,
    events: counts.events,
    omitted: counts.omitted,
    replacedTimeline: outcome.replacedTimeline,
    sketchUrl: options.baseUrl
      ? `${options.baseUrl.replace(/\/+$/, "")}/sketch/${sketch.id}/explore`
      : undefined,
    warnings,
  };
}

/** Log in and find-or-create the sketch (fatal — we need a sketch id to upload into). */
async function openSketch(
  client: TimesketchClientLike,
  sketchName: string,
): Promise<{ sketch: TimesketchSketchRef; created: boolean }> {
  await client.login();
  const found = await client.findSketchByName(sketchName);
  if (found) return { sketch: found, created: false };
  return { sketch: await client.createSketch(sketchName, "Imported from DFIR Companion."), created: true };
}

async function pushEventsToTimesketch(
  client: TimesketchClientLike,
  input: { sketchName: string; events: ForensicEvent[]; timelineName: string },
  options: TimesketchPushOptions,
): Promise<TimesketchPushResult> {
  const warnings: string[] = [];
  const { timelineName } = input;
  const opened = await openSketch(client, input.sketchName);
  const sketchId = opened.sketch.id;

  // Rows with no parseable time cannot be Timesketch events; they are counted and named in the
  // warnings so a partial push is not mistaken for a whole one.
  const { events, omitted } = splitTimesketchEvents(input.events);
  if (omitted > 0) warnings.push(timesketchOmittedWarning(omitted));
  const counts = { events: events.length, omitted };

  // A zero-event push (all timestamps unparseable, or an empty timeline) must NOT touch the existing
  // timeline — no list, no delete, no upload — or a no-op re-push would erase prior data.
  if (!events.length) {
    warnings.push(NOTHING_TO_UPLOAD);
    return pushResult(opened, counts, { timelineName, replacedTimeline: false }, options, warnings);
  }

  const jsonl = events.map((e) => JSON.stringify(e)).join("\n") + "\n";
  const swap = await beginSwap(client, sketchId, timelineName, warnings);
  let staged: StagedTimeline;
  try {
    staged = await client.uploadEvents(sketchId, swap.stagingName, jsonl, { dataLabel: swap.dataLabel });
  } catch (err) {
    return abortSwap(client, swap, err);
  }
  const outcome = await commitSwap(client, swap, staged, warnings);
  return pushResult(opened, counts, outcome, options, warnings);
}

export async function pushCaseToTimesketch(
  client: TimesketchClientLike,
  input: TimesketchPushInput,
  options: TimesketchPushOptions = {},
): Promise<TimesketchPushResult> {
  const timelineName = input.timelineName ?? options.timelineName ?? DEFAULT_TIMELINE;
  return pushEventsToTimesketch(
    client,
    { sketchName: input.sketchName, events: input.state.forensicTimeline, timelineName },
    options,
  );
}

/** Streaming state of one super push (local to it). The swap opens at the first chunk with rows. */
interface SuperStream {
  client: TimesketchClientLike;
  sketchId: number;
  timelineName: string;
  warnings: string[];
  swap?: TimelineSwap;
  staged: StagedTimeline;
  indexName?: string;
  pending: string[];
  uploaded: number;
  omitted: number;
}

async function flushChunk(s: SuperStream, last: boolean): Promise<void> {
  // Nothing to send and nothing open: no request. Nothing to send but a stream still open (the
  // rows ended exactly on a chunk boundary): an empty closing chunk, so the index is finalized.
  if (!s.pending.length && (!last || s.uploaded === 0)) return;
  s.swap ??= await beginSwap(s.client, s.sketchId, s.timelineName, s.warnings);
  const jsonl = s.pending.length ? s.pending.join("\n") + "\n" : "";
  const count = s.pending.length;
  s.pending = [];
  const res = await s.client.uploadEventsChunk(s.sketchId, s.swap.stagingName, jsonl, {
    indexName: s.indexName,
    last,
    dataLabel: s.swap.dataLabel,
  });
  s.indexName = res.indexName;
  s.staged = { timelineId: s.staged.timelineId ?? res.timelineId, color: s.staged.color ?? res.color };
  s.uploaded += count;
}

async function streamSuperEvents(
  s: SuperStream,
  events: AsyncIterable<readonly ForensicEvent[]>,
  chunkEvents: number,
): Promise<void> {
  for await (const batch of events) {
    for (const event of batch) {
      const mapped = mapForensicEvent(event);
      if (!mapped) {
        s.omitted += 1;
        continue;
      }
      s.pending.push(JSON.stringify(mapped));
      // A full chunk goes out as "more to come"; only the tail (after the loop) can close the stream.
      if (s.pending.length >= chunkEvents) await flushChunk(s, false);
    }
  }
  await flushChunk(s, true);
}

/**
 * The super-timeline push, streamed (#1444). Batches arrive in the store's scan order (dated
 * ascending, then undated — which Timesketch omits anyway), are mapped row by row, and go out as
 * chunked uploads into ONE staging timeline: the first chunk opens the index, the rest append to
 * it, the last closes it. Rows are never held past their chunk. The old managed timeline is noted
 * right before the first chunk and deleted only after the LAST chunk was accepted (#2414); a failed
 * chunk — or a failed store read mid-stream — removes the partial staging timeline instead. A push
 * with nothing uploadable makes no request at all, exactly as the one-shot push does.
 */
export async function pushSuperTimelineToTimesketch(
  client: TimesketchClientLike,
  input: TimesketchSuperPushInput,
  options: TimesketchPushOptions = {},
): Promise<TimesketchPushResult> {
  const timelineName = input.timelineName ?? DEFAULT_SUPER_TIMELINE;
  const chunkEvents = Math.max(1, Math.floor(options.chunkEvents ?? SUPER_PUSH_CHUNK_EVENTS));
  const warnings: string[] = [];
  const opened = await openSketch(client, input.sketchName);

  const s: SuperStream = {
    client,
    sketchId: opened.sketch.id,
    timelineName,
    warnings,
    staged: {},
    pending: [],
    uploaded: 0,
    omitted: 0,
  };
  try {
    await streamSuperEvents(s, input.events, chunkEvents);
  } catch (err) {
    if (s.swap) return abortSwap(client, s.swap, err);
    throw err;
  }
  if (s.omitted > 0) warnings.push(timesketchOmittedWarning(s.omitted));
  const outcome: PushOutcome = s.swap
    ? await commitSwap(client, s.swap, s.staged, warnings)
    : { timelineName, replacedTimeline: false };
  if (s.uploaded === 0) warnings.push(NOTHING_TO_UPLOAD);
  return pushResult(opened, { events: s.uploaded, omitted: s.omitted }, outcome, options, warnings);
}
