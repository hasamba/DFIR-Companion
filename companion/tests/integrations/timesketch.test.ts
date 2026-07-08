import { describe, it, expect } from "vitest";
import {
  timesketchDate, mapForensicEvent, toTimesketchEvents, toTimesketchJsonl,
  toTimesketchEventsFromList, toTimesketchJsonlFromList,
} from "../../src/integrations/timesketch/timesketchMap.js";
import { scrapeCsrfToken } from "../../src/integrations/timesketch/timesketchClient.js";
import {
  pushCaseToTimesketch, pushSuperTimelineToTimesketch, type TimesketchClientLike,
} from "../../src/integrations/timesketch/timesketchPush.js";
import { emptyState, type InvestigationState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { TimesketchSketchRef, TimesketchTimelineRef } from "../../src/integrations/timesketch/timesketchClient.js";

function event(over: Partial<ForensicEvent> & { timestamp: string; description: string }): ForensicEvent {
  return { id: over.timestamp, severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...over };
}

// ---- mappers ---------------------------------------------------------------

describe("timesketchMap", () => {
  it("formats datetime as ISO8601 with microseconds + explicit UTC offset", () => {
    expect(timesketchDate("2026-06-04T13:45:09.123Z")).toBe("2026-06-04T13:45:09.123000+00:00");
    expect(timesketchDate("2026-06-04T13:45:09+02:00")).toBe("2026-06-04T11:45:09.000000+00:00"); // normalized to UTC
    expect(timesketchDate("not a date")).toBeNull();
  });

  it("maps a forensic event to the three required fields plus searchable extras and a tag list", () => {
    const e = mapForensicEvent(event({
      timestamp: "2026-06-04T13:00:00Z", description: "C2 beacon to 8.8.8.8", severity: "High",
      asset: "DC01", mitreTechniques: ["T1071"], sources: ["THOR", "Velociraptor"],
      sha256: "a".repeat(64), path: "c:\\\\temp\\\\evil.exe", processName: "evil.exe", count: 5,
      endTimestamp: "2026-06-04T14:00:00Z", relatedFindingIds: ["f1"],
    }))!;
    expect(e.message).toBe("C2 beacon to 8.8.8.8");
    expect(e.datetime).toBe("2026-06-04T13:00:00.000000+00:00");
    expect(e.timestamp_desc).toBe("THOR, Velociraptor");          // derived from the reporting tools
    expect(e.data_type).toBe("dfir:companion:event");
    expect(e.severity).toBe("High");
    expect(e.tag).toEqual(["dfir-companion", "high", "T1071"]);
    expect(e.asset).toBe("DC01");
    expect(e.mitre).toBe("T1071");
    expect(e.sha256).toBe("a".repeat(64));
    expect(e.process_name).toBe("evil.exe");
    expect(e.occurrence_count).toBe(5);
    expect(e.end_datetime).toBe("2026-06-04T14:00:00.000000+00:00");
    expect(e.related_findings).toBe("f1");
    expect(e.companion_event_id).toBe("2026-06-04T13:00:00Z");
  });

  it("falls back to a generic timestamp_desc and drops a no-timestamp event", () => {
    const e = mapForensicEvent(event({ timestamp: "2026-06-04T13:00:00Z", description: "logon" }))!;
    expect(e.timestamp_desc).toBe("Forensic event");
    expect(mapForensicEvent(event({ timestamp: "bad", description: "x" }))).toBeNull();
  });

  it("renders the timeline as sorted JSONL, one valid JSON event per line, skipping bad timestamps", () => {
    const state: InvestigationState = {
      ...emptyState("c1"),
      forensicTimeline: [
        event({ timestamp: "2026-06-04T15:00:00Z", description: "later" }),
        event({ timestamp: "bad-date", description: "dropped" }),
        event({ timestamp: "2026-06-04T09:00:00Z", description: "earlier" }),
      ],
    };
    expect(toTimesketchEvents(state)).toHaveLength(2);             // bad-date dropped
    const lines = toTimesketchJsonl(state).trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    const parsed = lines.map((l) => JSON.parse(l));
    expect(parsed.map((p) => p.message)).toEqual(["earlier", "later"]); // chronological
    expect(parsed[0]).toHaveProperty("datetime");
    expect(toTimesketchJsonl(emptyState("c1"))).toBe("");          // no events → empty string
  });

  it("maps and renders a plain event list the same way as toTimesketchEvents/toTimesketchJsonl", () => {
    const events: ForensicEvent[] = [
      event({ timestamp: "2026-06-04T15:00:00Z", description: "later" }),
      event({ timestamp: "bad-date", description: "dropped" }),
      event({ timestamp: "2026-06-04T09:00:00Z", description: "earlier" }),
    ];
    const mapped = toTimesketchEventsFromList(events);
    expect(mapped).toHaveLength(2);
    expect(mapped.map((e) => e.message)).toEqual(["earlier", "later"]); // chronological, bad-date dropped

    const jsonl = toTimesketchJsonlFromList(events).trimEnd().split("\n");
    expect(jsonl).toHaveLength(2);
    expect(jsonl.map((l) => JSON.parse(l).message)).toEqual(["earlier", "later"]);
    expect(toTimesketchJsonlFromList([])).toBe(""); // no events → empty string
  });
});

describe("scrapeCsrfToken", () => {
  it("extracts the token from a hidden input or a meta tag", () => {
    expect(scrapeCsrfToken('<input id="csrf_token" name="csrf_token" type="hidden" value="abc123">')).toBe("abc123");
    expect(scrapeCsrfToken('<meta name="csrf-token" content="meta-tok">')).toBe("meta-tok");
    expect(scrapeCsrfToken("<html>no token here</html>")).toBeUndefined();
  });
});

// ---- orchestrator with a recording mock client -----------------------------

class MockTimesketch implements TimesketchClientLike {
  sketches: TimesketchSketchRef[] = [];
  timelines: TimesketchTimelineRef[] = [];
  uploads: { sketchId: number; timelineName: string; jsonl: string }[] = [];
  deletedTimelines: number[] = [];
  loggedIn = false;
  private seq = 10;

  async login() { this.loggedIn = true; }
  async findSketchByName(name: string) { return this.sketches.find((s) => s.name === name) ?? null; }
  async createSketch(name: string) { const ref = { id: 1, name }; this.sketches.push(ref); return ref; }
  async listTimelines() { return this.timelines; }
  async deleteTimeline(_sketchId: number, timelineId: number) {
    this.deletedTimelines.push(timelineId);
    this.timelines = this.timelines.filter((t) => t.id !== timelineId);
  }
  async uploadEvents(sketchId: number, timelineName: string, jsonl: string) {
    this.uploads.push({ sketchId, timelineName, jsonl });
  }
}

function sampleState(): InvestigationState {
  return {
    ...emptyState("Case Alpha"),
    forensicTimeline: [
      event({ timestamp: "2026-06-04T10:00:00Z", description: "logon to DC01", asset: "DC01", severity: "High" }),
      event({ timestamp: "2026-06-04T11:00:00Z", description: "mimikatz run", severity: "Critical" }),
    ],
  };
}

describe("pushCaseToTimesketch", () => {
  it("logs in, creates the sketch when missing, and uploads the timeline", async () => {
    const m = new MockTimesketch();
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() }, { baseUrl: "https://ts.example.org/" });
    expect(m.loggedIn).toBe(true);
    expect(res.created).toBe(true);
    expect(res.sketchId).toBe(1);
    expect(res.events).toBe(2);
    expect(res.timelineName).toBe("DFIR-Companion Forensic Timeline");
    expect(res.replacedTimeline).toBe(false);
    expect(m.uploads).toHaveLength(1);
    expect(m.uploads[0].jsonl.trimEnd().split("\n")).toHaveLength(2);
    expect(res.sketchUrl).toBe("https://ts.example.org/sketch/1/explore");
  });

  it("uses an existing sketch (matched by name) and clean-replaces the managed timeline", async () => {
    const m = new MockTimesketch();
    m.sketches.push({ id: 42, name: "Case Alpha" });
    m.timelines.push({ id: 7, name: "DFIR-Companion Forensic Timeline" });  // from a prior push
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() });
    expect(res.created).toBe(false);
    expect(res.sketchId).toBe(42);
    expect(res.replacedTimeline).toBe(true);
    expect(m.deletedTimelines).toContain(7);                       // old timeline deleted before upload
    expect(m.uploads).toHaveLength(1);
  });

  it("warns and skips the upload when there are no events with a parseable timestamp", async () => {
    const m = new MockTimesketch();
    const state = { ...emptyState("Case Beta"), forensicTimeline: [event({ timestamp: "bad", description: "x" })] };
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Beta", state });
    expect(res.events).toBe(0);
    expect(m.uploads).toHaveLength(0);
    expect(res.warnings.some((w) => w.includes("no events with a parseable timestamp"))).toBe(true);
  });
});

describe("pushSuperTimelineToTimesketch", () => {
  function superEvents(): ForensicEvent[] {
    return [
      event({ timestamp: "2026-06-04T08:00:00Z", description: "raw MFT entry", asset: "DC01" }),
      event({ timestamp: "2026-06-04T08:05:00Z", description: "raw USN entry", asset: "DC01" }),
    ];
  }

  it("pushes to a DIFFERENT default timeline name than the forensic push, in the same sketch", async () => {
    const m = new MockTimesketch();
    const res = await pushSuperTimelineToTimesketch(m, { sketchName: "Case Alpha", events: superEvents() });
    expect(res.created).toBe(true);
    expect(res.sketchId).toBe(1);
    expect(res.events).toBe(2);
    expect(res.timelineName).toBe("DFIR-Companion Super Timeline");
    expect(res.timelineName).not.toBe("DFIR-Companion Forensic Timeline");
  });

  it("reuses the same sketch as a prior forensic-timeline push without touching that timeline", async () => {
    const m = new MockTimesketch();
    // Simulate a prior forensic push: same sketch, forensic timeline already present.
    m.sketches.push({ id: 42, name: "Case Alpha" });
    m.timelines.push({ id: 7, name: "DFIR-Companion Forensic Timeline" });
    const res = await pushSuperTimelineToTimesketch(m, { sketchName: "Case Alpha", events: superEvents() });
    expect(res.sketchId).toBe(42);       // same sketch
    expect(res.created).toBe(false);
    expect(res.replacedTimeline).toBe(false);      // no super timeline existed yet, nothing replaced
    expect(m.deletedTimelines).not.toContain(7);    // the forensic timeline was left alone
    expect(m.timelines.some((t) => t.name === "DFIR-Companion Forensic Timeline")).toBe(true); // still there
  });

  it("clean-replaces its OWN super timeline on re-push, leaving a same-sketch forensic timeline alone", async () => {
    const m = new MockTimesketch();
    m.sketches.push({ id: 42, name: "Case Alpha" });
    m.timelines.push({ id: 7, name: "DFIR-Companion Forensic Timeline" });
    m.timelines.push({ id: 8, name: "DFIR-Companion Super Timeline" });
    const res = await pushSuperTimelineToTimesketch(m, { sketchName: "Case Alpha", events: superEvents() });
    expect(res.replacedTimeline).toBe(true);
    expect(m.deletedTimelines).toEqual([8]);
    expect(m.deletedTimelines).not.toContain(7);
  });

  it("warns and skips the upload when there are no events with a parseable timestamp", async () => {
    const m = new MockTimesketch();
    const res = await pushSuperTimelineToTimesketch(m, { sketchName: "Case Beta", events: [event({ timestamp: "bad", description: "x" })] });
    expect(res.events).toBe(0);
    expect(m.uploads).toHaveLength(0);
    expect(res.warnings.some((w) => w.includes("no events with a parseable timestamp"))).toBe(true);
  });
});
