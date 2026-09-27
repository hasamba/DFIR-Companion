// #1715: correlation drops a folded member's id, and analyst records outside the case state (tags,
// comments, stars, hypothesis links) still name it. The case keeps a lineage of absorbed id -> survivor
// id beside the state; a reader resolves an id LIVE-FIRST: an id that is an event today is itself,
// otherwise its lineage is followed to an event that is.
import { describe, it, expect } from "vitest";
import {
  eventAliasResolver,
  recordEventAliases,
  withoutEventAliases,
} from "../../src/analysis/eventAliases.js";
import { remapAbsorbedEventIds } from "../../src/analysis/absorbedCitations.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { mergeConcurrentAdditions } from "../../src/analysis/ai/synthesisPersist.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

const HASH = "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef";
const ctx = { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] };
const baseDelta: AnalysisDelta = {
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "",
};
function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-05-26T08:35:23Z",
    description: "event",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}
type DeltaEvent = NonNullable<AnalysisDelta["forensicEvents"]>[number];
const velo = () =>
  ev({ id: "m1e1", description: `Downloaded file evil.exe flagged, sha256 ${HASH}` }) as DeltaEvent;
const thor = () =>
  ev({
    id: "t2e5",
    severity: "Critical",
    sha256: HASH,
    description: "THOR Alert: Malware file found C:\\Tools\\evil.exe",
  }) as DeltaEvent;

const live = (...ids: string[]) => {
  const set = new Set(ids);
  return (id: string) => set.has(id);
};

describe("recordEventAliases (#1715)", () => {
  it("records each absorbed id against its survivor", () => {
    expect(recordEventAliases(undefined, new Map([["a", "b"]]))).toEqual({ a: "b" });
  });

  it("collapses a chain so every id names the newest survivor", () => {
    const first = recordEventAliases(undefined, new Map([["a", "b"]]));
    expect(recordEventAliases(first, new Map([["b", "c"]]))).toEqual({ a: "c", b: "c" });
  });

  it("never deletes lineage, even for an id that is live again", () => {
    const first = recordEventAliases(undefined, new Map([["a", "b"]]));
    expect(recordEventAliases(first, new Map([["x", "y"]]))).toEqual({ a: "b", x: "y" });
  });

  it("returns the existing record untouched when nothing was absorbed", () => {
    const existing = { a: "b" };
    expect(recordEventAliases(existing, new Map())).toBe(existing);
    expect(recordEventAliases(undefined, new Map())).toBeUndefined();
  });

  it("drops malformed and self-referencing entries from an imported record", () => {
    const bad = { a: 7, b: "b", "": "x", c: "d" } as unknown as Record<string, string>;
    expect(recordEventAliases(bad, new Map([["e", "f"]]))).toEqual({ c: "d", e: "f" });
  });

  it("keeps a __proto__ id as data, not as a prototype", () => {
    const out = recordEventAliases(undefined, new Map([["__proto__", "b"]]));
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(Object.keys(out ?? {})).toEqual(["__proto__"]);
  });
});

describe("eventAliasResolver (#1715)", () => {
  it("resolves an absorbed id to its live survivor", () => {
    expect(eventAliasResolver({ a: "b" }, live("b"))("a")).toBe("b");
  });

  it("prefers the id itself when it is live again", () => {
    expect(eventAliasResolver({ a: "b" }, live("a", "b"))("a")).toBe("a");
  });

  it("follows a multi-hop chain to the first live id", () => {
    expect(eventAliasResolver({ a: "b", b: "c" }, live("c"))("a")).toBe("c");
    expect(eventAliasResolver({ a: "b", b: "c" }, live("b", "c"))("a")).toBe("b");
  });

  it("returns the id unchanged when no live id is reachable, or the chain loops", () => {
    expect(eventAliasResolver({ a: "b" }, live())("a")).toBe("a");
    expect(eventAliasResolver({ a: "b", b: "a" }, live())("a")).toBe("a");
    expect(eventAliasResolver(undefined, live())("a")).toBe("a");
  });

  it("is exact-case: A and a are different events", () => {
    expect(eventAliasResolver({ a: "b" }, live("b"))("A")).toBe("A");
  });
});

describe("the lineage is recorded where correlation folds (#1715)", () => {
  it("remapAbsorbedEventIds records the fold beside the rewritten citations", () => {
    const out = remapAbsorbedEventIds(emptyState("c"), new Map([["m1e1", "t2e5"]]));
    expect(out.eventAliases).toEqual({ m1e1: "t2e5" });
  });

  it("a stored event folded by a later import keeps its lineage across later merges", () => {
    const s = mergeDelta(emptyState("c"), { ...baseDelta, forensicEvents: [velo()] }, ctx);
    const folded = mergeDelta(s, { ...baseDelta, forensicEvents: [thor()] }, ctx);
    expect(folded.eventAliases).toEqual({ m1e1: "t2e5" });
    const later = mergeDelta(folded, { ...baseDelta, summary: "no events" }, ctx);
    expect(later.eventAliases).toEqual({ m1e1: "t2e5" });
  });

  it("a synthesis write keeps lineage an import recorded while it ran", () => {
    const loaded = emptyState("c");
    const next = { ...loaded, eventAliases: { x: "y" } };
    const latest = { ...loaded, eventAliases: { m1e1: "t2e5" } };
    expect(mergeConcurrentAdditions(loaded, next, latest).eventAliases).toEqual({
      x: "y",
      m1e1: "t2e5",
    });
  });
});

describe("withoutEventAliases (#1715)", () => {
  it("drops the lineage from a state on its way to a client or an export", () => {
    const state = { ...emptyState("c"), eventAliases: { a: "b" } };
    const out = withoutEventAliases(state);
    expect("eventAliases" in out).toBe(false);
    expect(state.eventAliases).toEqual({ a: "b" });
  });
});

describe("a synthesis write does not undo a fold an import made while it ran (#1715)", () => {
  const withFinding = (s: ReturnType<typeof emptyState>, cites: string) => ({
    ...s,
    findings: [
      {
        id: "f1",
        severity: "High" as const,
        title: "t",
        description: "d",
        status: "open" as const,
        relatedIocs: [],
        mitreTechniques: [],
        relatedEventIds: [cites],
        firstSeen: "",
        lastUpdated: "",
        sourceScreenshots: [],
      },
    ],
  });

  it("drops the snapshot's copy of the folded event and cites the survivor", () => {
    const loaded = { ...emptyState("c"), forensicTimeline: [velo() as ForensicEvent] };
    const next = withFinding(loaded, "m1e1");
    const latest = {
      ...emptyState("c"),
      forensicTimeline: [thor() as ForensicEvent],
      eventAliases: { m1e1: "t2e5" },
    };
    const out = mergeConcurrentAdditions(loaded, next, latest);
    expect(out.forensicTimeline.map((e) => e.id)).toEqual(["t2e5"]);
    expect(out.findings[0].relatedEventIds).toEqual(["t2e5"]);
    expect(out.eventAliases).toEqual({ m1e1: "t2e5" });
  });

  it("keeps an event the import folded and then brought back", () => {
    const loaded = { ...emptyState("c"), forensicTimeline: [velo() as ForensicEvent] };
    const latest = {
      ...emptyState("c"),
      forensicTimeline: [thor() as ForensicEvent, velo() as ForensicEvent],
      eventAliases: { m1e1: "t2e5" },
    };
    const out = mergeConcurrentAdditions(loaded, loaded, latest);
    expect(out.forensicTimeline.map((e) => e.id).sort()).toEqual(["m1e1", "t2e5"]);
  });

  it("leaves lineage the snapshot already had alone", () => {
    const loaded = {
      ...emptyState("c"),
      forensicTimeline: [velo() as ForensicEvent, thor() as ForensicEvent],
      eventAliases: { m1e1: "t2e5" },
    };
    const out = mergeConcurrentAdditions(loaded, loaded, loaded);
    expect(out.forensicTimeline.map((e) => e.id).sort()).toEqual(["m1e1", "t2e5"]);
  });
});
