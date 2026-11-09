import { describe, it, expect } from "vitest";
import {
  timesketchDate,
  mapForensicEvent,
  toTimesketchEvents,
  toTimesketchJsonl,
  toTimesketchEventsFromList,
  toTimesketchJsonlFromList,
  splitTimesketchEvents,
} from "../../src/integrations/timesketch/timesketchMap.js";
import {
  scrapeCsrfToken,
  describeFetchError,
  TimesketchClient,
} from "../../src/integrations/timesketch/timesketchClient.js";
import { ResponseTooLargeError, RESPONSE_SIZE_LIMITS } from "../../src/providers/boundedResponse.js";
import {
  pushCaseToTimesketch,
  pushSuperTimelineToTimesketch,
  type TimesketchClientLike,
} from "../../src/integrations/timesketch/timesketchPush.js";
import { emptyState, type InvestigationState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type {
  TimesketchSketchRef,
  TimesketchTimelineRef,
} from "../../src/integrations/timesketch/timesketchClient.js";

function event(over: Partial<ForensicEvent> & { timestamp: string; description: string }): ForensicEvent {
  return {
    id: over.timestamp,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

// ---- mappers ---------------------------------------------------------------

describe("timesketchMap", () => {
  it("formats datetime as ISO8601 with microseconds + explicit UTC offset", () => {
    expect(timesketchDate("2026-06-04T13:45:09.123Z")).toBe("2026-06-04T13:45:09.123000+00:00");
    expect(timesketchDate("2026-06-04T13:45:09+02:00")).toBe("2026-06-04T11:45:09.000000+00:00"); // normalized to UTC
    expect(timesketchDate("not a date")).toBeNull();
  });

  it("maps a forensic event to the three required fields plus searchable extras and a tag list", () => {
    const e = mapForensicEvent(
      event({
        timestamp: "2026-06-04T13:00:00Z",
        description: "C2 beacon to 8.8.8.8",
        severity: "High",
        asset: "DC01",
        mitreTechniques: ["T1071"],
        sources: ["THOR", "Velociraptor"],
        sha256: "a".repeat(64),
        path: "c:\\\\temp\\\\evil.exe",
        processName: "evil.exe",
        count: 5,
        endTimestamp: "2026-06-04T14:00:00Z",
        relatedFindingIds: ["f1"],
      }),
    )!;
    expect(e.message).toBe("C2 beacon to 8.8.8.8");
    expect(e.datetime).toBe("2026-06-04T13:00:00.000000+00:00");
    expect(e.timestamp_desc).toBe("THOR, Velociraptor"); // derived from the reporting tools
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
    expect(toTimesketchEvents(state)).toHaveLength(2); // bad-date dropped
    const lines = toTimesketchJsonl(state).trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    const parsed = lines.map((l) => JSON.parse(l));
    expect(parsed.map((p) => p.message)).toEqual(["earlier", "later"]); // chronological
    expect(parsed[0]).toHaveProperty("datetime");
    expect(toTimesketchJsonl(emptyState("c1"))).toBe(""); // no events → empty string
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

// An undated row cannot be a Timesketch event (the format requires a datetime), so it is omitted —
// and the omission is counted, so the export can say so instead of shrinking in silence (#957).
describe("splitTimesketchEvents", () => {
  it("counts the rows it omits for lack of a parseable time", () => {
    const { events, omitted } = splitTimesketchEvents([
      event({ timestamp: "2026-05-26T12:00:00Z", description: "dated" }),
      event({ timestamp: "", description: "undated" }),
      event({ timestamp: "not a time", description: "junk" }),
    ]);
    expect(events.map((e) => e.message)).toEqual(["dated"]);
    expect(omitted).toBe(2);
  });
  it("reports zero omitted when every row has a time", () => {
    expect(
      splitTimesketchEvents([event({ timestamp: "2026-05-26T12:00:00Z", description: "d" })]).omitted,
    ).toBe(0);
  });
});

describe("scrapeCsrfToken", () => {
  it("extracts the token from a hidden input or a meta tag", () => {
    expect(scrapeCsrfToken('<input id="csrf_token" name="csrf_token" type="hidden" value="abc123">')).toBe(
      "abc123",
    );
    expect(scrapeCsrfToken('<meta name="csrf-token" content="meta-tok">')).toBe("meta-tok");
    expect(scrapeCsrfToken("<html>no token here</html>")).toBeUndefined();
  });
});

describe("describeFetchError", () => {
  it("walks the cause chain so an errno code isn't lost behind Node's generic 'fetch failed'", () => {
    const errno = Object.assign(new Error("connect ECONNREFUSED 10.0.0.2:5000"), { code: "ECONNREFUSED" });
    const fetchFailed = new TypeError("fetch failed", { cause: errno });
    expect(describeFetchError(fetchFailed)).toBe(
      "fetch failed -> connect ECONNREFUSED 10.0.0.2:5000 (ECONNREFUSED)",
    );
  });

  it("passes through a plain error message when there is no cause", () => {
    expect(describeFetchError(new Error("boom"))).toBe("boom");
  });

  it("stringifies non-Error throws", () => {
    expect(describeFetchError("not an error")).toBe("not an error");
  });
});

describe("TimesketchClient network failure", () => {
  it("surfaces the underlying cause instead of a bare 'fetch failed'", async () => {
    const errno = Object.assign(new Error("connect ECONNREFUSED 10.0.0.2:5000"), { code: "ECONNREFUSED" });
    const client = new TimesketchClient({
      baseUrl: "https://10.0.0.2:5000",
      username: "u",
      password: "p",
      fetchFn: async () => {
        throw new TypeError("fetch failed", { cause: errno });
      },
    });
    await expect(client.login()).rejects.toThrow(
      "Timesketch request failed: fetch failed -> connect ECONNREFUSED 10.0.0.2:5000 (ECONNREFUSED)",
    );
  });

  it("adds no TLS advice to a connection failure", async () => {
    // Guards the pairing, not the helper (that is tests/integrations/tlsTrustHint.test.ts):
    // answering "nothing is listening" with "skip certificate verification" would send an
    // operator disabling a security control over a wrong port.
    const errno = Object.assign(new Error("connect ECONNREFUSED 10.0.0.2:5000"), { code: "ECONNREFUSED" });
    const client = new TimesketchClient({
      baseUrl: "https://10.0.0.2:5000",
      username: "u",
      password: "p",
      fetchFn: async () => {
        throw new TypeError("fetch failed", { cause: errno });
      },
    });
    await expect(client.login()).rejects.toThrow(/^(?!.*DFIR_TIMESKETCH_INSECURE)/s);
  });

  it("points a rejected certificate at the set's CA bundle, not Node's --use-system-ca", async () => {
    // The reported failure verbatim: a self-hosted Timesketch behind its own cert. Node's message
    // ends in --use-system-ca, which is not a setting this app has — the analyst needs the two it
    // does have, and the global opt-in a non-loopback host additionally requires.
    const errno = Object.assign(
      new Error(
        "self-signed certificate; if the root CA is installed locally, try running Node.js with --use-system-ca",
      ),
      { code: "DEPTH_ZERO_SELF_SIGNED_CERT" },
    );
    const client = new TimesketchClient({
      baseUrl: "https://timesketch.example.org",
      username: "u",
      password: "p",
      fetchFn: async () => {
        throw new TypeError("fetch failed", { cause: errno });
      },
    });
    const err = await client.login().then(
      () => null,
      (e: Error) => e,
    );
    expect(err?.message).toContain("DEPTH_ZERO_SELF_SIGNED_CERT"); // Node's own words are kept
    // The client is built from a server set, so the fix is in the set, not in .env.
    expect(err?.message).toContain(
      "Set the CA bundle for Timesketch in this server set (Settings → Server sets)",
    );
    expect(err?.message).not.toContain("DFIR_TIMESKETCH_CA");
  });
});

describe("TimesketchClient bounded response (issue #686)", () => {
  // Regression: readBoundedJson().catch(() => ({})) originally caught EVERY rejection, including
  // ResponseTooLargeError — so an oversized-but-VALID sketches list silently looked like "no
  // sketches on this page", findSketchByName returned null, and the push flow went on to create a
  // duplicate sketch instead of reusing the existing one. It must now propagate.
  it("findSketchByName propagates ResponseTooLargeError instead of treating an oversized page as empty", async () => {
    const client = new TimesketchClient({
      baseUrl: "https://timesketch.example.org",
      username: "u",
      password: "p",
      fetchFn: async () =>
        new Response("irrelevant — rejected on the declared Content-Length before this is read", {
          status: 200,
          headers: { "content-length": String(RESPONSE_SIZE_LIMITS.json + 1) },
        }),
    });
    await expect(client.findSketchByName("existing-case-sketch")).rejects.toThrow(ResponseTooLargeError);
  });
});

// ---- orchestrator with a recording mock client -----------------------------

class MockTimesketch implements TimesketchClientLike {
  sketches: TimesketchSketchRef[] = [];
  timelines: TimesketchTimelineRef[] = [];
  uploads: { sketchId: number; timelineName: string; jsonl: string; dataLabel?: string }[] = [];
  deletedTimelines: number[] = [];
  renames: { timelineId: number; name: string; color?: string }[] = [];
  calls: string[] = []; // call order: "list", "delete:<id>", "upload", "chunk", "rename:<id>"
  loggedIn = false;
  // Failure switches (#2414).
  failUpload = false;
  failChunkAt = 0; // 1-based chunk number that throws (0 = never)
  failRename = false;
  failDeleteIds: number[] = [];
  private seq = 100;

  async login() {
    this.loggedIn = true;
  }
  async findSketchByName(name: string) {
    return this.sketches.find((s) => s.name === name) ?? null;
  }
  async createSketch(name: string) {
    const ref = { id: 1, name };
    this.sketches.push(ref);
    return ref;
  }
  async listTimelines() {
    this.calls.push("list");
    return [...this.timelines];
  }
  async deleteTimeline(_sketchId: number, timelineId: number) {
    this.calls.push(`delete:${timelineId}`);
    if (this.failDeleteIds.includes(timelineId)) throw new Error(`delete ${timelineId} refused`);
    this.deletedTimelines.push(timelineId);
    this.timelines = this.timelines.filter((t) => t.id !== timelineId);
  }
  // Like Timesketch: an upload creates (or reuses, by name) the timeline before it can fail later.
  private ensureTimeline(name: string): number {
    const hit = this.timelines.find((t) => t.name === name);
    if (hit) return hit.id;
    const id = this.seq++;
    this.timelines.push({ id, name });
    return id;
  }
  async uploadEvents(
    sketchId: number,
    timelineName: string,
    jsonl: string,
    opts: { dataLabel?: string } = {},
  ) {
    this.calls.push("upload");
    const timelineId = this.ensureTimeline(timelineName);
    if (this.failUpload) throw new Error("upload refused");
    this.uploads.push({ sketchId, timelineName, jsonl, dataLabel: opts.dataLabel });
    return { timelineId, color: "A1B2C3" };
  }
  chunks: {
    sketchId: number;
    timelineName: string;
    jsonl: string;
    indexName?: string;
    last: boolean;
    dataLabel?: string;
  }[] = [];
  async uploadEventsChunk(
    sketchId: number,
    timelineName: string,
    jsonl: string,
    chunk: { indexName?: string; last: boolean; dataLabel?: string },
  ) {
    this.calls.push("chunk");
    const timelineId = this.ensureTimeline(timelineName);
    this.chunks.push({ sketchId, timelineName, jsonl, ...chunk });
    if (this.failChunkAt === this.chunks.length) throw new Error(`chunk ${this.chunks.length} refused`);
    return { indexName: chunk.indexName ?? `idx-${this.chunks.length}`, timelineId, color: "A1B2C3" };
  }
  async renameTimeline(_sketchId: number, timelineId: number, name: string, opts: { color?: string } = {}) {
    this.calls.push(`rename:${timelineId}`);
    if (this.failRename) throw new Error("rename refused");
    this.renames.push({ timelineId, name, color: opts.color });
    this.timelines = this.timelines.map((t) => (t.id === timelineId ? { ...t, name } : t));
  }
}

const STAGING = / \(staging [0-9a-f]{6}\)$/;

function sampleState(): InvestigationState {
  return {
    ...emptyState("Case Alpha"),
    forensicTimeline: [
      event({
        timestamp: "2026-06-04T10:00:00Z",
        description: "logon to DC01",
        asset: "DC01",
        severity: "High",
      }),
      event({ timestamp: "2026-06-04T11:00:00Z", description: "mimikatz run", severity: "Critical" }),
    ],
  };
}

describe("pushCaseToTimesketch", () => {
  it("logs in, creates the sketch when missing, and uploads the timeline", async () => {
    const m = new MockTimesketch();
    const res = await pushCaseToTimesketch(
      m,
      { sketchName: "Case Alpha", state: sampleState() },
      { baseUrl: "https://ts.example.org/" },
    );
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
    m.timelines.push({ id: 7, name: "DFIR-Companion Forensic Timeline" }); // from a prior push
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() });
    expect(res.created).toBe(false);
    expect(res.sketchId).toBe(42);
    expect(res.replacedTimeline).toBe(true);
    expect(m.deletedTimelines).toContain(7); // old timeline deleted before upload
    expect(m.uploads).toHaveLength(1);
  });

  it("warns and skips the upload when there are no events with a parseable timestamp", async () => {
    const m = new MockTimesketch();
    const state = {
      ...emptyState("Case Beta"),
      forensicTimeline: [event({ timestamp: "bad", description: "x" })],
    };
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Beta", state });
    expect(res.events).toBe(0);
    expect(m.uploads).toHaveLength(0);
    expect(res.warnings.some((w) => w.includes("no events with a parseable timestamp"))).toBe(true);
  });

  it("counts and warns about the undated rows a partial push leaves behind (#957)", async () => {
    const m = new MockTimesketch();
    const state = {
      ...emptyState("Case Gamma"),
      forensicTimeline: [
        event({ timestamp: "2026-05-26T12:00:00Z", description: "dated" }),
        event({ timestamp: "", description: "undated one" }),
        event({ timestamp: "", description: "undated two" }),
      ],
    };
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Gamma", state });
    expect(res.events).toBe(1);
    expect(res.omitted).toBe(2);
    expect(res.warnings).toEqual([
      "2 event(s) omitted: no parseable timestamp (Timesketch requires one) — they remain in the Companion timeline",
    ]);
  });

  it("does NOT delete an existing same-named timeline when there are no events to upload (data-loss guard)", async () => {
    // A zero-event push (all timestamps unparseable, or the source timeline is empty) must be
    // a no-op on the existing timeline, not a delete-without-replace. Previously the delete ran
    // unconditionally before the upload guard, destroying prior data on a no-op re-push.
    const m = new MockTimesketch();
    m.sketches.push({ id: 42, name: "Case Beta" });
    m.timelines.push({ id: 7, name: "DFIR-Companion Forensic Timeline" }); // prior data
    const state = {
      ...emptyState("Case Beta"),
      forensicTimeline: [event({ timestamp: "bad", description: "x" })],
    };
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Beta", state });
    expect(res.events).toBe(0);
    expect(m.uploads).toHaveLength(0);
    expect(m.deletedTimelines).not.toContain(7); // prior timeline NOT deleted
    expect(m.timelines.some((t) => t.id === 7)).toBe(true); // still present
    expect(res.replacedTimeline).toBe(false);
  });
});

describe("pushSuperTimelineToTimesketch", () => {
  function superEvents(): ForensicEvent[] {
    return [
      event({ timestamp: "2026-06-04T08:00:00Z", description: "raw MFT entry", asset: "DC01" }),
      event({ timestamp: "2026-06-04T08:05:00Z", description: "raw USN entry", asset: "DC01" }),
    ];
  }

  async function* batches(events: ForensicEvent[], size = 1): AsyncGenerator<ForensicEvent[]> {
    for (let i = 0; i < events.length; i += size) yield events.slice(i, i + size);
  }

  it("pushes to a DIFFERENT default timeline name than the forensic push, in the same sketch", async () => {
    const m = new MockTimesketch();
    const res = await pushSuperTimelineToTimesketch(m, {
      sketchName: "Case Alpha",
      events: batches(superEvents()),
    });
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
    const res = await pushSuperTimelineToTimesketch(m, {
      sketchName: "Case Alpha",
      events: batches(superEvents()),
    });
    expect(res.sketchId).toBe(42); // same sketch
    expect(res.created).toBe(false);
    expect(res.replacedTimeline).toBe(false); // no super timeline existed yet, nothing replaced
    expect(m.deletedTimelines).not.toContain(7); // the forensic timeline was left alone
    expect(m.timelines.some((t) => t.name === "DFIR-Companion Forensic Timeline")).toBe(true); // still there
  });

  it("clean-replaces its OWN super timeline on re-push, leaving a same-sketch forensic timeline alone", async () => {
    const m = new MockTimesketch();
    m.sketches.push({ id: 42, name: "Case Alpha" });
    m.timelines.push({ id: 7, name: "DFIR-Companion Forensic Timeline" });
    m.timelines.push({ id: 8, name: "DFIR-Companion Super Timeline" });
    const res = await pushSuperTimelineToTimesketch(m, {
      sketchName: "Case Alpha",
      events: batches(superEvents()),
    });
    expect(res.replacedTimeline).toBe(true);
    expect(m.deletedTimelines).toEqual([8]);
    expect(m.deletedTimelines).not.toContain(7);
  });

  it("warns and skips the upload when there are no events with a parseable timestamp", async () => {
    const m = new MockTimesketch();
    m.timelines.push({ id: 8, name: "DFIR-Companion Super Timeline" });
    const res = await pushSuperTimelineToTimesketch(m, {
      sketchName: "Case Beta",
      events: batches([event({ timestamp: "bad", description: "x" })]),
    });
    expect(res.events).toBe(0);
    expect(res.omitted).toBe(1);
    expect(m.uploads).toHaveLength(0);
    expect(m.chunks).toHaveLength(0);
    expect(m.deletedTimelines).toEqual([]); // nothing to replace it with → the old timeline stays
    expect(res.warnings.some((w) => w.includes("no events with a parseable timestamp"))).toBe(true);
  });

  // #1444: a capped super-timeline is 900k events — never one array, never one JSONL string.
  it("streams the batches as chunked uploads: first opens the index, later chunks reuse it, the last closes it", async () => {
    const m = new MockTimesketch();
    m.sketches.push({ id: 42, name: "Case Alpha" });
    m.timelines.push({ id: 8, name: "DFIR-Companion Super Timeline" });
    const events = Array.from({ length: 5 }, (_, i) =>
      event({ timestamp: `2026-06-04T08:0${i}:00Z`, description: `row ${i}`, asset: "DC01" }),
    );
    const res = await pushSuperTimelineToTimesketch(
      m,
      { sketchName: "Case Alpha", events: batches(events, 2) },
      {
        chunkEvents: 2,
      },
    );
    expect(m.uploads).toHaveLength(0);
    expect(
      m.chunks.map((c) => ({ n: c.jsonl.trim().split("\n").length, indexName: c.indexName, last: c.last })),
    ).toEqual([
      { n: 2, indexName: undefined, last: false },
      { n: 2, indexName: "idx-1", last: false },
      { n: 1, indexName: "idx-1", last: true },
    ]);
    // #2414: every chunk goes to ONE staging timeline under ONE unique data label; the old
    // timeline is removed only after the last chunk was accepted, then the staging one is renamed.
    expect(m.chunks.every((c) => c.sketchId === 42 && c.timelineName === m.chunks[0].timelineName)).toBe(
      true,
    );
    expect(m.chunks[0].timelineName).toMatch(/^DFIR-Companion Super Timeline \(staging [0-9a-f]{6}\)$/);
    expect(new Set(m.chunks.map((c) => c.dataLabel))).toEqual(new Set([m.chunks[0].dataLabel]));
    expect(m.chunks[0].dataLabel).toMatch(/^dfir-companion-[0-9a-f]{6}$/);
    expect(m.deletedTimelines).toEqual([8]); // replaced once, after the last chunk
    expect(m.calls.indexOf("delete:8")).toBeGreaterThan(m.calls.lastIndexOf("chunk"));
    expect(res.timelineName).toBe("DFIR-Companion Super Timeline");
    expect(m.timelines.map((t) => t.name)).toEqual(["DFIR-Companion Super Timeline"]);
    expect(res.events).toBe(5);
    expect(res.omitted).toBe(0);
    expect(res.replacedTimeline).toBe(true);
    // Row order is the store's scan order (dated ascending) — no whole-list sort is possible.
    expect(
      m.chunks.flatMap((c) =>
        c.jsonl
          .trim()
          .split("\n")
          .map((l) => JSON.parse(l).message),
      ),
    ).toEqual(events.map((e) => e.description));
  });

  it("rows ending exactly on a chunk boundary still close the stream, with an empty final chunk", async () => {
    const m = new MockTimesketch();
    const events = Array.from({ length: 4 }, (_, i) =>
      event({ timestamp: `2026-06-04T08:0${i}:00Z`, description: `row ${i}` }),
    );
    const res = await pushSuperTimelineToTimesketch(
      m,
      { sketchName: "Case Alpha", events: batches(events, 4) },
      {
        chunkEvents: 2,
      },
    );
    expect(m.chunks.map((c) => ({ jsonl: c.jsonl === "" ? "" : "rows", last: c.last }))).toEqual([
      { jsonl: "rows", last: false },
      { jsonl: "rows", last: false },
      { jsonl: "", last: true },
    ]);
    expect(res.events).toBe(4);
  });

  it("counts rows without a parseable time across every batch and names them once in the warnings", async () => {
    const m = new MockTimesketch();
    const events = [
      event({ timestamp: "2026-06-04T08:00:00Z", description: "ok" }),
      event({ timestamp: "bad", description: "x" }),
      event({ timestamp: "", description: "y" }),
    ];
    const res = await pushSuperTimelineToTimesketch(m, {
      sketchName: "Case Alpha",
      events: batches(events, 1),
    });
    expect(res.events).toBe(1);
    expect(res.omitted).toBe(2);
    expect(m.chunks).toHaveLength(1);
    expect(m.chunks[0].last).toBe(true);
    expect(res.warnings.filter((w) => w.includes("2"))).toHaveLength(1);
  });
});

// ---- #2414: upload first, then swap -----------------------------------------

describe("Timesketch re-push swaps safely (#2414)", () => {
  const FORENSIC = "DFIR-Companion Forensic Timeline";
  const SUPER = "DFIR-Companion Super Timeline";

  async function* batches(events: ForensicEvent[], size = 1): AsyncGenerator<ForensicEvent[]> {
    for (let i = 0; i < events.length; i += size) yield events.slice(i, i + size);
  }
  function rows(n: number): ForensicEvent[] {
    return Array.from({ length: n }, (_, i) =>
      event({ timestamp: `2026-06-04T08:0${i}:00Z`, description: `row ${i}` }),
    );
  }
  function existing(...timelines: TimesketchTimelineRef[]): MockTimesketch {
    const m = new MockTimesketch();
    m.sketches.push({ id: 42, name: "Case Alpha" });
    m.timelines.push(...timelines);
    return m;
  }

  it("forensic push uploads before any delete, and deletes only timelines that existed before the upload", async () => {
    const m = existing({ id: 7, name: FORENSIC });
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() });
    expect(m.calls.indexOf("upload")).toBeLessThan(m.calls.indexOf("delete:7"));
    expect(m.deletedTimelines).toEqual([7]); // never the freshly uploaded staging timeline
    expect(m.calls.indexOf("rename:100")).toBeGreaterThan(m.calls.indexOf("delete:7"));
    expect(res.replacedTimeline).toBe(true);
    expect(res.timelineName).toBe(FORENSIC);
    expect(m.timelines).toEqual([{ id: 100, name: FORENSIC }]);
    expect(m.renames).toEqual([{ timelineId: 100, name: FORENSIC, color: "A1B2C3" }]);
    expect(res.warnings).toEqual([]);
  });

  it("uploads under a staging name with a unique data label, different on every push", async () => {
    const m = existing({ id: 7, name: FORENSIC });
    await pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() });
    await pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() });
    expect(m.uploads).toHaveLength(2);
    for (const u of m.uploads) {
      expect(u.timelineName.startsWith(FORENSIC)).toBe(true);
      expect(u.timelineName).toMatch(STAGING);
      expect(u.dataLabel).toMatch(/^dfir-companion-[0-9a-f]{6}$/);
    }
    expect(m.uploads[0].dataLabel).not.toBe(m.uploads[1].dataLabel);
    expect(m.uploads[0].timelineName).not.toBe(m.uploads[1].timelineName);
    expect(m.timelines.map((t) => t.name)).toEqual([FORENSIC]); // second push replaced the first
  });

  it("a failed upload keeps the old timeline, removes the partial staging one, and rethrows", async () => {
    const m = existing({ id: 7, name: FORENSIC });
    m.failUpload = true;
    await expect(pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() })).rejects.toThrow(
      "upload refused",
    );
    expect(m.deletedTimelines).not.toContain(7);
    expect(m.deletedTimelines).toEqual([100]); // the staging timeline the failed upload created
    expect(m.timelines).toEqual([{ id: 7, name: FORENSIC }]);
    expect(m.renames).toEqual([]);
  });

  it("super push: a chunk-2 failure keeps the old timeline and cleans up the staging one", async () => {
    const m = existing({ id: 8, name: SUPER });
    m.failChunkAt = 2;
    await expect(
      pushSuperTimelineToTimesketch(
        m,
        { sketchName: "Case Alpha", events: batches(rows(5), 2) },
        { chunkEvents: 2 },
      ),
    ).rejects.toThrow("chunk 2 refused");
    expect(m.chunks).toHaveLength(2);
    expect(m.chunks[0].timelineName).toMatch(STAGING);
    expect(m.chunks[1].timelineName).toBe(m.chunks[0].timelineName);
    expect(m.chunks[1].dataLabel).toBe(m.chunks[0].dataLabel);
    expect(m.deletedTimelines).toEqual([100]);
    expect(m.timelines).toEqual([{ id: 8, name: SUPER }]);
    expect(m.renames).toEqual([]);
  });

  it("super push: a store read failure mid-stream also keeps the old timeline", async () => {
    const m = existing({ id: 8, name: SUPER });
    async function* broken(): AsyncGenerator<ForensicEvent[]> {
      yield rows(2);
      throw new Error("store read failed");
    }
    await expect(
      pushSuperTimelineToTimesketch(m, { sketchName: "Case Alpha", events: broken() }, { chunkEvents: 2 }),
    ).rejects.toThrow("store read failed");
    expect(m.timelines).toEqual([{ id: 8, name: SUPER }]);
  });

  it("a failed staging cleanup is named in the rethrown error, and the old timeline still survives", async () => {
    const m = existing({ id: 7, name: FORENSIC });
    m.failUpload = true;
    m.failDeleteIds = [100];
    await expect(pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() })).rejects.toThrow(
      /upload refused.*staging.*delete 100 refused/,
    );
    expect(m.timelines.some((t) => t.id === 7)).toBe(true);
  });

  it("a failed rename succeeds with a warning, keeps the data under the staging name, and is not '(replaced)'", async () => {
    const m = existing({ id: 7, name: FORENSIC });
    m.failRename = true;
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() });
    expect(m.deletedTimelines).toEqual([7]);
    expect(res.timelineName).toMatch(STAGING);
    expect(res.replacedTimeline).toBe(false);
    expect(res.warnings.some((w) => w.includes("rename refused") && w.includes("next push"))).toBe(true);
    expect(m.timelines).toEqual([{ id: 100, name: res.timelineName }]);
  });

  it("an old timeline that cannot be deleted is kept, the new one stays under its staging name, with a warning", async () => {
    const m = existing({ id: 7, name: FORENSIC });
    m.failDeleteIds = [7];
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() });
    expect(res.replacedTimeline).toBe(false);
    expect(res.timelineName).toMatch(STAGING);
    expect(m.renames).toEqual([]); // no duplicate managed name next to the stale copy
    expect(res.warnings.some((w) => w.includes("delete 7 refused"))).toBe(true);
  });

  it("the next push tidies a leftover staging timeline from an earlier failed rename", async () => {
    const m = existing({ id: 7, name: `${FORENSIC} (staging abc123)` }, { id: 9, name: SUPER });
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() });
    expect(m.deletedTimelines).toEqual([7]); // the super timeline is not the forensic push's to touch
    expect(res.replacedTimeline).toBe(true);
    expect(m.timelines.map((t) => t.name).sort()).toEqual([FORENSIC, SUPER].sort());
  });

  it("the super push never treats the forensic timeline, or its staging leftovers, as its own", async () => {
    const m = existing({ id: 7, name: FORENSIC }, { id: 6, name: `${FORENSIC} (staging abc123)` });
    const res = await pushSuperTimelineToTimesketch(m, {
      sketchName: "Case Alpha",
      events: batches(rows(2)),
    });
    expect(m.deletedTimelines).toEqual([]);
    expect(res.replacedTimeline).toBe(false);
    expect(res.timelineName).toBe(SUPER);
  });

  it("a timeline list failure before the upload still uploads and renames, with a warning", async () => {
    const m = existing({ id: 7, name: FORENSIC });
    m.listTimelines = async () => {
      throw new Error("list refused");
    };
    const res = await pushCaseToTimesketch(m, { sketchName: "Case Alpha", state: sampleState() });
    expect(m.uploads).toHaveLength(1);
    expect(res.replacedTimeline).toBe(false);
    expect(res.warnings.some((w) => w.includes("list refused"))).toBe(true);
  });
});
