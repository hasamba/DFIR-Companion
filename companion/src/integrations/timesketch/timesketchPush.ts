// Orchestrates a Companion → Timesketch push: log in, find-or-create the sketch by name (= the
// Companion case id), then upload the forensic timeline as a Timesketch timeline. Idempotent —
// the managed timeline is clean-replaced (deleted then re-uploaded) so re-pushing never duplicates
// events, mirroring how the IRIS push clean-replaces its notes and synthesis replaces conclusions.
//
// The client is injected as a structural interface so this is unit-testable with a mock (no
// network), matching the IRIS-push / enrichment-service pattern.

import type { InvestigationState } from "../../analysis/stateTypes.js";
import { toTimesketchEvents } from "./timesketchMap.js";
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

export interface TimesketchPushOptions {
  baseUrl?: string;            // to build a clickable sketch URL in the result
  timelineName?: string;       // managed timeline name (default "DFIR Companion timeline")
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

export async function pushCaseToTimesketch(
  client: TimesketchClientLike,
  input: TimesketchPushInput,
  options: TimesketchPushOptions = {},
): Promise<TimesketchPushResult> {
  const warnings: string[] = [];
  const timelineName = input.timelineName ?? options.timelineName ?? DEFAULT_TIMELINE;

  // 1. Connectivity / auth (fatal).
  await client.login();

  // 2. Find-or-create the sketch by name (fatal — we need a sketch id to upload into).
  const found = await client.findSketchByName(input.sketchName);
  let sketch: TimesketchSketchRef;
  let created = false;
  if (found) {
    sketch = found;
  } else {
    sketch = await client.createSketch(input.sketchName, "Imported from DFIR Companion.");
    created = true;
  }

  // 3. Build the JSONL from the forensic timeline.
  const events = toTimesketchEvents(input.state);
  const jsonl = events.length ? events.map((e) => JSON.stringify(e)).join("\n") + "\n" : "";

  // 4. Clean-replace: delete any existing same-named timeline so re-pushes don't duplicate events
  // (non-fatal — if listing/deleting fails we still upload, but flag the possible duplication).
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
    warnings.push("no forensic events with a parseable timestamp to upload");
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
