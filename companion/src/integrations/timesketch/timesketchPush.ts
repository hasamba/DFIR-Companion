// Orchestrates a Companion → Timesketch push: log in, find-or-create the sketch by name (= the
// Companion case id), then upload an event list as a Timesketch timeline. Idempotent — the managed
// timeline is clean-replaced (deleted then re-uploaded) so re-pushing never duplicates events,
// mirroring how the IRIS push clean-replaces its notes and synthesis replaces conclusions.
//
// Two public entry points: pushCaseToTimesketch (the forensic timeline, from InvestigationState,
// one upload) and pushSuperTimelineToTimesketch (the super-timeline, streamed from
// SuperTimelineStore.eventBatches() as CHUNKED uploads — #1444: a capped super-timeline is 900k
// events, which is neither one array nor one JSONL string this process can hold). Both push into
// the SAME sketch (named after the case id) but write to two DIFFERENTLY-NAMED timelines inside
// it, so pushing one never clean-replaces the other.
//
// The client is injected as a structural interface so this is unit-testable with a mock (no
// network), matching the IRIS-push / enrichment-service pattern.

import type { ForensicEvent, InvestigationState } from "../../analysis/stateTypes.js";
import { mapForensicEvent, splitTimesketchEvents, timesketchOmittedWarning } from "./timesketchMap.js";
import type { TimesketchSketchRef, TimesketchTimelineRef } from "./timesketchClient.js";

// Structural subset of TimesketchClient used here — lets tests pass a lightweight mock.
export interface TimesketchClientLike {
  login(): Promise<void>;
  findSketchByName(name: string): Promise<TimesketchSketchRef | null>;
  createSketch(name: string, description: string): Promise<TimesketchSketchRef>;
  listTimelines(sketchId: number): Promise<TimesketchTimelineRef[]>;
  deleteTimeline(sketchId: number, timelineId: number): Promise<void>;
  uploadEvents(sketchId: number, timelineName: string, jsonl: string): Promise<void>;
  /**
   * One chunk of a streamed upload (#1444). The first chunk opens the index and returns its name;
   * later chunks pass that `indexName` back so Timesketch appends to the same timeline, and
   * `last: true` closes the stream so the timeline is indexed.
   */
  uploadEventsChunk(
    sketchId: number,
    timelineName: string,
    jsonl: string,
    chunk: { indexName?: string; last: boolean },
  ): Promise<{ indexName: string }>;
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
  timelineName: string;
  events: number; // events uploaded (with a parseable timestamp)
  omitted: number; // events left out for lack of one — also named in `warnings` (#957)
  replacedTimeline: boolean; // true = an existing same-named timeline was deleted first
  sketchUrl?: string;
  warnings: string[];
}

const DEFAULT_TIMELINE = "DFIR-Companion Forensic Timeline";
const DEFAULT_SUPER_TIMELINE = "DFIR-Companion Super Timeline";
// Events per chunked super-timeline upload: ~5–15 MB of JSONL per request, well under both V8's
// string ceiling and Timesketch's upload limits, and few enough requests for a capped case.
const SUPER_PUSH_CHUNK_EVENTS = 5000;

async function pushEventsToTimesketch(
  client: TimesketchClientLike,
  input: { sketchName: string; events: ForensicEvent[]; timelineName: string },
  options: TimesketchPushOptions,
): Promise<TimesketchPushResult> {
  const warnings: string[] = [];
  const { sketchName, timelineName } = input;

  // 1. Connectivity / auth (fatal).
  await client.login();

  // 2. Find-or-create the sketch by name (fatal — we need a sketch id to upload into).
  const found = await client.findSketchByName(sketchName);
  let sketch: TimesketchSketchRef;
  let created = false;
  if (found) {
    sketch = found;
  } else {
    sketch = await client.createSketch(sketchName, "Imported from DFIR Companion.");
    created = true;
  }

  // 3. Build the JSONL from the event list. Rows with no parseable time cannot be Timesketch events;
  // they are counted and named in the warnings so a partial push is not mistaken for a whole one.
  const { events, omitted } = splitTimesketchEvents(input.events);
  if (omitted > 0) warnings.push(timesketchOmittedWarning(omitted));
  const jsonl = events.length ? events.map((e) => JSON.stringify(e)).join("\n") + "\n" : "";

  // 4. Clean-replace: delete any existing SAME-NAMED timeline so re-pushes don't duplicate events
  // (non-fatal — if listing/deleting fails we still upload, but flag the possible duplication).
  // Matching by name is also what keeps the forensic and super-timeline pushes from clobbering
  // each other — they use different timelineName defaults within the same sketch.
  // ONLY delete when we have events to replace it with — a zero-event push (all timestamps
  // unparseable, or the source timeline is empty) must NOT destroy the existing timeline,
  // otherwise a no-op re-push silently erases prior data with nothing to show for it.
  let replacedTimeline = false;
  if (events.length) {
    try {
      for (const t of await client.listTimelines(sketch.id)) {
        if (t.name === timelineName) {
          await client.deleteTimeline(sketch.id, t.id);
          replacedTimeline = true;
        }
      }
    } catch (err) {
      warnings.push(`timeline cleanup: ${(err as Error).message} — a re-push may duplicate events`);
    }
  }

  // 5. Upload (fatal on failure — the push has nothing else to do).
  if (events.length) {
    await client.uploadEvents(sketch.id, timelineName, jsonl);
  } else {
    warnings.push("no events with a parseable timestamp to upload; existing timeline left untouched");
  }

  return {
    sketchId: sketch.id,
    sketchName: sketch.name,
    created,
    timelineName,
    events: events.length,
    omitted,
    replacedTimeline,
    sketchUrl: options.baseUrl
      ? `${options.baseUrl.replace(/\/+$/, "")}/sketch/${sketch.id}/explore`
      : undefined,
    warnings,
  };
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

/** Log in, find-or-create the sketch, and clean-replace the managed timeline (steps 1, 2 and 4 of
 * pushEventsToTimesketch) — shared by the streamed super push below. */
async function openSketch(
  client: TimesketchClientLike,
  sketchName: string,
): Promise<{ sketch: TimesketchSketchRef; created: boolean }> {
  await client.login();
  const found = await client.findSketchByName(sketchName);
  if (found) return { sketch: found, created: false };
  return { sketch: await client.createSketch(sketchName, "Imported from DFIR Companion."), created: true };
}

async function replaceTimeline(
  client: TimesketchClientLike,
  sketchId: number,
  timelineName: string,
  warnings: string[],
): Promise<boolean> {
  let replaced = false;
  try {
    for (const t of await client.listTimelines(sketchId)) {
      if (t.name === timelineName) {
        await client.deleteTimeline(sketchId, t.id);
        replaced = true;
      }
    }
  } catch (err) {
    warnings.push(`timeline cleanup: ${(err as Error).message} — a re-push may duplicate events`);
  }
  return replaced;
}

/**
 * The super-timeline push, streamed (#1444). Batches arrive in the store's scan order (dated
 * ascending, then undated — which Timesketch omits anyway), are mapped row by row, and go out as
 * chunked uploads into ONE timeline: the first chunk opens the index, the rest append to it, the
 * last closes it. Rows are never held past their chunk. The same-named timeline is clean-replaced
 * right before the FIRST chunk — only once there is something to replace it with, so a push with
 * nothing uploadable leaves the existing timeline untouched, exactly as the one-shot push does.
 */
export async function pushSuperTimelineToTimesketch(
  client: TimesketchClientLike,
  input: TimesketchSuperPushInput,
  options: TimesketchPushOptions = {},
): Promise<TimesketchPushResult> {
  const timelineName = input.timelineName ?? DEFAULT_SUPER_TIMELINE;
  const chunkEvents = Math.max(1, Math.floor(options.chunkEvents ?? SUPER_PUSH_CHUNK_EVENTS));
  const warnings: string[] = [];
  const { sketch, created } = await openSketch(client, input.sketchName);

  let uploaded = 0;
  let omitted = 0;
  let replacedTimeline = false;
  let indexName: string | undefined;
  let pending: string[] = [];
  const flush = async (last: boolean): Promise<void> => {
    // Nothing to send and nothing open: no request. Nothing to send but a stream still open (the
    // rows ended exactly on a chunk boundary): an empty closing chunk, so the index is finalized.
    if (!pending.length && (!last || uploaded === 0)) return;
    if (uploaded === 0) replacedTimeline = await replaceTimeline(client, sketch.id, timelineName, warnings);
    const jsonl = pending.length ? pending.join("\n") + "\n" : "";
    const count = pending.length;
    pending = [];
    ({ indexName } = await client.uploadEventsChunk(sketch.id, timelineName, jsonl, { indexName, last }));
    uploaded += count;
  };
  for await (const batch of input.events) {
    for (const event of batch) {
      const mapped = mapForensicEvent(event);
      if (!mapped) {
        omitted += 1;
        continue;
      }
      pending.push(JSON.stringify(mapped));
      // A full chunk goes out as "more to come"; only the tail (after the loop) can close the stream.
      if (pending.length >= chunkEvents) await flush(false);
    }
  }
  await flush(true);
  if (omitted > 0) warnings.push(timesketchOmittedWarning(omitted));
  if (uploaded === 0)
    warnings.push("no events with a parseable timestamp to upload; existing timeline left untouched");

  return {
    sketchId: sketch.id,
    sketchName: sketch.name,
    created,
    timelineName,
    events: uploaded,
    omitted,
    replacedTimeline,
    sketchUrl: options.baseUrl
      ? `${options.baseUrl.replace(/\/+$/, "")}/sketch/${sketch.id}/explore`
      : undefined,
    warnings,
  };
}
