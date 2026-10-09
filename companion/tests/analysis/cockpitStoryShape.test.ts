import { describe, expect, it } from "vitest";
import { deriveStoryShape, STORY_SHAPE_LIMIT } from "../../src/analysis/cockpitStoryShape.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { buildHostAliasIndex, hostMergesFromAssetIds } from "../../src/analysis/hostAlias.js";

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

  it("folds hosts the analyst merged, shown with the name the analyst chose (#2066)", () => {
    const events = [
      event("short", { timestamp: "2026-07-30T08:00:00.000Z", asset: "WS01" }),
      event("fqdn", { timestamp: "2026-07-30T09:00:00.000Z", asset: "ws01.sub.example" }),
      event("other", { timestamp: "2026-07-30T10:00:00.000Z", asset: "DC01" }),
    ];
    const index = buildHostAliasIndex([], hostMergesFromAssetIds({ "host:ws01": "host:ws01.sub.example" }));

    const merged = deriveStoryShape(events, index);
    expect(merged.hosts).toEqual(["ws01.sub.example", "DC01"]);
    expect(merged.hostsTotal).toBe(2);

    // Without the index nothing has linked the pair, so it stays two hosts.
    const unlinked = deriveStoryShape(events);
    expect(unlinked.hosts).toEqual(["WS01", "ws01.sub.example", "DC01"]);
    expect(unlinked.hostsTotal).toBe(3);
  });

  it("never folds a short name into an FQDN on the first label alone, even with an index (#2066)", () => {
    const shape = deriveStoryShape(
      [
        event("short", { timestamp: "2026-07-30T08:00:00.000Z", asset: "FS01" }),
        event("fqdn", { timestamp: "2026-07-30T09:00:00.000Z", asset: "fs01.example.com" }),
      ],
      buildHostAliasIndex([], {}),
    );

    expect(shape.hosts).toEqual(["FS01", "fs01.example.com"]);
    expect(shape.hostsTotal).toBe(2);
  });

  it("follows the fleet snapshot's hostname-to-FQDN link when the index carries one (#2066)", () => {
    const shape = deriveStoryShape(
      [
        event("short", { timestamp: "2026-07-30T08:00:00.000Z", asset: "SRV7" }),
        event("fqdn", { timestamp: "2026-07-30T09:00:00.000Z", asset: "SRV7.corp.example" }),
      ],
      buildHostAliasIndex([{ hostname: "srv7", fqdn: "srv7.corp.example" }], {}),
    );

    expect(shape.hosts).toEqual(["srv7.corp.example"]);
    expect(shape.hostsTotal).toBe(1);
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
