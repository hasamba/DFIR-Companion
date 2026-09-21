import { describe, expect, it } from "vitest";
import { deriveStoryShape, STORY_SHAPE_LIMIT } from "../../src/analysis/cockpitStoryShape.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function event(id: string, overrides: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-07-30T09:00:00.000Z",
    description: `Event ${id}`,
    severity: "High",
    mitreTechniques: ["T1059"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...overrides,
  };
}

describe("deriveStoryShape — span and dwell", () => {
  it("takes firstAt from the earliest timestamp and lastAt from the latest, whatever the order", () => {
    const shape = deriveStoryShape([
      event("mid", { timestamp: "2026-07-30T10:00:00.000Z" }),
      event("last", { timestamp: "2026-07-31T22:15:00.000Z" }),
      event("first", { timestamp: "2026-07-30T08:30:00.000Z" }),
    ]);

    expect(shape.firstAt).toBe("2026-07-30T08:30:00.000Z");
    expect(shape.lastAt).toBe("2026-07-31T22:15:00.000Z");
    expect(shape.dwellMs).toBe((24 + 13) * 60 * 60 * 1000 + 45 * 60 * 1000);
  });

  it("uses endTimestamp for lastAt when it is later than every timestamp, never for firstAt", () => {
    const shape = deriveStoryShape([
      event("agg", { timestamp: "2026-07-30T08:00:00.000Z", endTimestamp: "2026-07-30T12:00:00.000Z" }),
      event("later-start", { timestamp: "2026-07-30T10:00:00.000Z" }),
    ]);

    expect(shape.firstAt).toBe("2026-07-30T08:00:00.000Z");
    expect(shape.lastAt).toBe("2026-07-30T12:00:00.000Z");
    expect(shape.dwellMs).toBe(4 * 60 * 60 * 1000);
  });

  it("ignores an endTimestamp that is earlier than the timestamps or unparseable", () => {
    const shape = deriveStoryShape([
      event("a", { timestamp: "2026-07-30T08:00:00.000Z", endTimestamp: "2026-07-30T07:00:00.000Z" }),
      event("b", { timestamp: "2026-07-30T10:00:00.000Z", endTimestamp: "not a date" }),
    ]);

    expect(shape.lastAt).toBe("2026-07-30T10:00:00.000Z");
  });

  it("skips undated and unparseable events when finding the span", () => {
    const shape = deriveStoryShape([
      event("no-time", { timestamp: "" }),
      event("bad-time", { timestamp: "not a date" }),
      event("dated", { timestamp: "2026-07-30T09:00:00.000Z" }),
    ]);

    expect(shape.firstAt).toBe("2026-07-30T09:00:00.000Z");
    expect(shape.lastAt).toBe("2026-07-30T09:00:00.000Z");
    expect(shape.dwellMs).toBe(0);
  });

  it("reports null span and dwell when no event carries a parseable timestamp", () => {
    const shape = deriveStoryShape([event("no-time", { timestamp: "" })]);

    expect(shape.firstAt).toBeNull();
    expect(shape.lastAt).toBeNull();
    expect(shape.dwellMs).toBeNull();
  });

  it("returns nulls and empties for an empty timeline", () => {
    expect(deriveStoryShape([])).toEqual({
      firstAt: null,
      lastAt: null,
      dwellMs: null,
      hosts: [],
      hostsTotal: 0,
      accounts: [],
      accountsTotal: 0,
    });
  });
});

describe("deriveStoryShape — hosts", () => {
  it("lists distinct hosts in order of first touch by timestamp, trimmed, undated last", () => {
    const shape = deriveStoryShape([
      event("undated", { timestamp: "", asset: "FS01" }),
      event("dc-late", { timestamp: "2026-07-30T12:00:00.000Z", asset: "DC01" }),
      event("web-first", { timestamp: "2026-07-30T08:00:00.000Z", asset: "  WEB01 " }),
      event("web-again", { timestamp: "2026-07-30T11:00:00.000Z", asset: "WEB01" }),
      event("wk", { timestamp: "2026-07-30T09:00:00.000Z", asset: "WKSTN-JSMITH" }),
      event("blank", { timestamp: "2026-07-30T10:00:00.000Z", asset: "   " }),
      event("none", { timestamp: "2026-07-30T10:30:00.000Z" }),
    ]);

    expect(shape.hosts).toEqual(["WEB01", "WKSTN-JSMITH", "DC01", "FS01"]);
    expect(shape.hostsTotal).toBe(4);
  });

  it("folds host case — DC01 and dc01 are one host, shown with the first-seen spelling", () => {
    const shape = deriveStoryShape([
      event("lower-first", { timestamp: "2026-07-30T08:00:00.000Z", asset: "dc01" }),
      event("upper", { timestamp: "2026-07-30T09:00:00.000Z", asset: "DC01" }),
      event("other", { timestamp: "2026-07-30T10:00:00.000Z", asset: "FS01" }),
      event("mixed", { timestamp: "2026-07-30T11:00:00.000Z", asset: "fs01.example.com" }),
    ]);

    expect(shape.hosts).toEqual(["dc01", "FS01", "fs01.example.com"]);
    expect(shape.hostsTotal).toBe(3);
  });

  it("caps hosts at STORY_SHAPE_LIMIT and reports the distinct total before the cap", () => {
    const events = Array.from({ length: STORY_SHAPE_LIMIT + 3 }, (_, index) =>
      event(`e-${index}`, {
        timestamp: new Date(Date.UTC(2026, 6, 30, 0, index)).toISOString(),
        asset: `HOST-${index}`,
      }),
    );
    const shape = deriveStoryShape(events);

    expect(STORY_SHAPE_LIMIT).toBe(8);
    expect(shape.hosts).toHaveLength(STORY_SHAPE_LIMIT);
    expect(shape.hosts[0]).toBe("HOST-0");
    expect(shape.hosts[STORY_SHAPE_LIMIT - 1]).toBe(`HOST-${STORY_SHAPE_LIMIT - 1}`);
    expect(shape.hostsTotal).toBe(STORY_SHAPE_LIMIT + 3);
  });
});

describe("deriveStoryShape — accounts", () => {
  it("extracts accounts from descriptions in order of first touch, deduplicated", () => {
    const shape = deriveStoryShape([
      event("late", {
        timestamp: "2026-07-30T12:00:00.000Z",
        description: "Logon by GLOBALTECH\\administrator then GLOBALTECH\\jsmith",
      }),
      event("early", {
        timestamp: "2026-07-30T08:00:00.000Z",
        description: "Phish landed for GLOBALTECH\\jsmith (jsmith@example.com)",
      }),
      event("plain", { timestamp: "2026-07-30T09:00:00.000Z", description: "No account here" }),
      event("blank", { timestamp: "2026-07-30T09:30:00.000Z", description: "" }),
    ]);

    expect(shape.accounts).toEqual(["GLOBALTECH\\jsmith", "jsmith@example.com", "GLOBALTECH\\administrator"]);
    expect(shape.accountsTotal).toBe(3);
  });

  it("caps accounts at STORY_SHAPE_LIMIT and reports the distinct total before the cap", () => {
    const events = Array.from({ length: STORY_SHAPE_LIMIT + 2 }, (_, index) =>
      event(`e-${index}`, {
        timestamp: new Date(Date.UTC(2026, 6, 30, 0, index)).toISOString(),
        description: `Logon by CORP\\user${index}`,
      }),
    );
    const shape = deriveStoryShape(events);

    expect(shape.accounts).toHaveLength(STORY_SHAPE_LIMIT);
    expect(shape.accounts[0]).toBe("CORP\\user0");
    expect(shape.accountsTotal).toBe(STORY_SHAPE_LIMIT + 2);
  });
});

describe("deriveStoryShape — immutability", () => {
  it("never mutates or reorders the input events", () => {
    const events = [
      event("b", { timestamp: "2026-07-30T10:00:00.000Z", asset: "B" }),
      event("a", { timestamp: "2026-07-30T08:00:00.000Z", asset: "A" }),
    ];
    const before = JSON.stringify(events);

    deriveStoryShape(events);

    expect(JSON.stringify(events)).toBe(before);
    expect(events.map((item) => item.id)).toEqual(["b", "a"]);
  });
});
