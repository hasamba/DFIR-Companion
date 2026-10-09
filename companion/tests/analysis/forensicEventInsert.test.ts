import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { byEventTime } from "../../src/analysis/forensicSort.js";
import { insertForensicEventInOrder } from "../../src/analysis/forensicEventInsert.js";

// #2060: a manual event is placed at its time-ordered position by one indexed insert, not by
// loading, re-sorting and saving the whole case. The result must be what that full sort gave.

function ev(id: string, timestamp: string, p: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: `event ${id}`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const BASE = [
  ev("e1", "2026-01-01T00:00:00Z"),
  ev("e2", "2026-01-02T00:00:00Z", { srcIp: "10.0.0.2" }),
  ev("e3", "2026-01-03T00:00:00Z"),
  ev("e4", "2026-01-04T00:00:00Z"),
  ev("e5", "2026-01-05T00:00:00Z", { srcIp: "10.0.0.5" }),
];

let dir: string;
let store: StateStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-insert-"));
  const cases = new CaseStore(dir);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new StateStore(cases);
  // A first save stores contiguous ordinals 0..n-1, so an insert between two rows must respace.
  await store.save({ ...emptyState("c1"), forensicTimeline: BASE, updatedAt: "2026-01-01T00:00:00.000Z" });
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const ids = (events: readonly ForensicEvent[]): string[] => events.map((e) => e.id);

async function storedCount(): Promise<number> {
  const counts = await caseSqliteWorker.request<Record<string, number>>({
    op: "entityCounts",
    dbPath: store.databasePath("c1"),
    kinds: ["forensicTimeline"],
  });
  return counts.forensicTimeline;
}

async function expectSortedInsert(event: ForensicEvent): Promise<void> {
  const before = (await store.load("c1")).forensicTimeline;
  await insertForensicEventInOrder(store, "c1", event);
  const after = (await store.load("c1")).forensicTimeline;
  expect(ids(after)).toEqual(ids([...before, event].sort(byEventTime)));
  expect(await storedCount()).toBe(before.length + 1);
}

describe("insertForensicEventInOrder (#2060)", () => {
  it("places an event in the middle of a contiguous-ordinal timeline", async () => {
    await expectSortedInsert(ev("m", "2026-01-03T12:00:00Z"));
  });

  it("places an event dated before every row at the front", async () => {
    await expectSortedInsert(ev("f", "2025-12-31T00:00:00Z"));
  });

  it("places an event dated after every row at the end", async () => {
    await expectSortedInsert(ev("z", "2026-02-01T00:00:00Z"));
  });

  it("puts an unparseable timestamp last, after earlier unparseable rows", async () => {
    await expectSortedInsert(ev("u1", "not a time"));
    await expectSortedInsert(ev("u2", ""));
    await expectSortedInsert(ev("late", "2026-03-01T00:00:00Z"));
  });

  it("puts an event tied with existing rows after them, as a stable sort does", async () => {
    await expectSortedInsert(ev("t1", "2026-01-03T00:00:00Z"));
    await expectSortedInsert(ev("t2", "2026-01-03T00:00:00.000Z"));
  });

  it("keeps placing correctly across many inserts into the gaps a respace left", async () => {
    for (let i = 0; i < 12; i++) {
      await expectSortedInsert(ev(`g${i}`, `2026-01-03T0${i % 10}:${10 + i}:00Z`));
    }
  });

  it("patches updatedAt and keeps the other case fields", async () => {
    await insertForensicEventInOrder(
      store,
      "c1",
      ev("m", "2026-01-03T12:00:00Z"),
      "2026-05-05T05:05:05.000Z",
    );
    const state = await store.load("c1");
    expect(state.updatedAt).toBe("2026-05-05T05:05:05.000Z");
    expect(state.caseId).toBe("c1");
  });

  it("keeps the IOC index pointing at the rows after a respace", async () => {
    await insertForensicEventInOrder(store, "c1", ev("f", "2025-12-31T00:00:00Z", { srcIp: "10.0.0.9" }));
    const page = await store.queryForensicTimeline("c1", { ioc: "10.0.0.5" });
    expect(ids(page.entities)).toEqual(["e5"]);
    const added = await store.queryForensicTimeline("c1", { ioc: "10.0.0.9" });
    expect(ids(added.entities)).toEqual(["f"]);
    const all = await store.queryForensicTimeline("c1", {});
    expect(ids(all.entities)).toEqual(["f", "e1", "e2", "e3", "e4", "e5"]);
  });

  it("leaves a case a later full save still round-trips", async () => {
    await insertForensicEventInOrder(store, "c1", ev("m", "2026-01-03T12:00:00Z"));
    const loaded = await store.load("c1");
    await store.save({ ...loaded, updatedAt: "2026-06-06T00:00:00.000Z" });
    const again = await store.load("c1");
    expect(again.forensicTimeline).toEqual(loaded.forensicTimeline);
    expect(again.updatedAt).toBe("2026-06-06T00:00:00.000Z");
    expect(await storedCount()).toBe(BASE.length + 1);
  });

  it("creates the case state when the case has none yet", async () => {
    const cases = new CaseStore(dir);
    await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    await insertForensicEventInOrder(store, "c2", ev("only", "2026-01-01T00:00:00Z"));
    const state = await store.load("c2");
    expect(ids(state.forensicTimeline)).toEqual(["only"]);
  });
});
