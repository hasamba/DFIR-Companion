// Orchestrates a Companion → Timesketch push: log in, find-or-create the sketch by name (= the
// Companion case id), then upload an event list as a Timesketch timeline. Idempotent — the managed
// timeline is clean-replaced (deleted then re-uploaded) so re-pushing never duplicates events,
// mirroring how the IRIS push clean-replaces its notes and synthesis replaces conclusions.
//
// Two public entry points share one internal helper: pushCaseToTimesketch (the forensic timeline,
// from InvestigationState) and pushSuperTimelineToTimesketch (the super-timeline, a plain
// ForensicEvent[] the caller already queried from SuperTimelineStore). Both push into the SAME
// sketch (named after the case id) but write to two DIFFERENTLY-NAMED timelines inside it, so
// pushing one never clean-replaces the other.
//
// The client is injected as a structural interface so this is unit-testable with a mock (no
// network), matching the IRIS-push / enrichment-service pattern.

import type { ForensicEvent, InvestigationState } from "../../analysis/stateTypes.js";
import { toTimesketchEventsFromList } from "./timesketchMap.js";
import type { TimesketchSketchRef, TimesketchTimelineRef } from "./timesketchClient.js";

// Structural subset of TimesketchClient used here — lets tests pass a lightweight mock.
export interface TimesketchClientLike {
  login(): Promise<void>;
  findSketchByName(name: string): Promise<TimesketchSketchRef | null>;
  createSketch(name: string, description: string): Promise<TimesketchSketchRef>;
  listTimelines(sketchId: number): Promise<TimesketchTimelineRef[]>;
  deleteTimeline(sketchId: number, timelineId: number): Promise<void>;
  uploadEvents(sketchId: number, timelineName: string, jsonl: string): Promise<void>;
}

export interface TimesketchPushInput {
  sketchName: string;          // = the Companion case id (used as the Timesketch sketch name)
  state: InvestigationState;
  timelineName?: string;       // overrides the default managed-timeline name
}

export interface TimesketchSuperPushInput {
  sketchName: string;          // = the Companion case id (used as the Timesketch sketch name)
  events: ForensicEvent[];     // the super-timeline's event list (caller already queried it)
  timelineName?: string;       // overrides the default managed-timeline name
}

export interface TimesketchPushOptions {
  baseUrl?: string;            // to build a clickable sketch URL in the result
  timelineName?: string;       // managed FORENSIC timeline name (default "DFIR Companion timeline")
}

export interface TimesketchPushResult {
  sketchId: number;
  sketchName: string;
  created: boolean;            // true = the sketch was newly created
  timelineName: string;
  events: number;              // events uploaded (with a parseable timestamp)
  replacedTimeline: boolean;   // true = an existing same-named timeline was deleted first
  sketchUrl?: string;
  warnings: string[];
}

const DEFAULT_TIMELINE = "DFIR Companion timeline";
const DEFAULT_SUPER_TIMELINE = "DFIR Companion super timeline";

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

  // 3. Build the JSONL from the event list.
  const events = toTimesketchEventsFromList(input.events);
  const jsonl = events.length ? events.map((e) => JSON.stringify(e)).join("\n") + "\n" : "";

  // 4. Clean-replace: delete any existing SAME-NAMED timeline so re-pushes don't duplicate events
  // (non-fatal — if listing/deleting fails we still upload, but flag the possible duplication).
  // Matching by name is also what keeps the forensic and super-timeline pushes from clobbering
  // each other — they use different timelineName defaults within the same sketch.
  let replacedTimeline = false;
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

  // 5. Upload (fatal on failure — the push has nothing else to do).
  if (events.length) {
    await client.uploadEvents(sketch.id, timelineName, jsonl);
  } else {
    warnings.push("no events with a parseable timestamp to upload");
  }

  return {
    sketchId: sketch.id,
    sketchName: sketch.name,
    created,
    timelineName,
    events: events.length,
    replacedTimeline,
    sketchUrl: options.baseUrl ? `${options.baseUrl.replace(/\/+$/, "")}/sketch/${sketch.id}/explore` : undefined,
    warnings,
  };
}

export async function pushCaseToTimesketch(
  client: TimesketchClientLike,
  input: TimesketchPushInput,
  options: TimesketchPushOptions = {},
): Promise<TimesketchPushResult> {
  const timelineName = input.timelineName ?? options.timelineName ?? DEFAULT_TIMELINE;
  return pushEventsToTimesketch(client, { sketchName: input.sketchName, events: input.state.forensicTimeline, timelineName }, options);
}

export async function pushSuperTimelineToTimesketch(
  client: TimesketchClientLike,
  input: TimesketchSuperPushInput,
  options: TimesketchPushOptions = {},
): Promise<TimesketchPushResult> {
  const timelineName = input.timelineName ?? DEFAULT_SUPER_TIMELINE;
  return pushEventsToTimesketch(client, { sketchName: input.sketchName, events: input.events, timelineName }, options);
}
