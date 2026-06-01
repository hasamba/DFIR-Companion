import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { inScope, filterEventsByScope, ScopeStore, NO_SCOPE } from "../../src/analysis/scope.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string): ForensicEvent {
  return { id, timestamp, description: id, severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] };
}

describe("scope filtering", () => {
  it("inScope respects start/end and keeps undated events", () => {
    const scope = { start: "2026-01-01T00:00:00Z", end: "2026-01-31T23:59:59Z" };
    expect(inScope("2026-01-15T12:00:00Z", scope)).toBe(true);
    expect(inScope("2025-12-31T23:59:59Z", scope)).toBe(false); // before window
    expect(inScope("2026-02-01T00:00:00Z", scope)).toBe(false); // after window
    expect(inScope("", scope)).toBe(true);                       // undated kept
    expect(inScope("2025-01-01T00:00:00Z", NO_SCOPE)).toBe(true); // no scope = all
  });

  it("filterEventsByScope drops out-of-window events", () => {
    const events = [
      ev("old", "2024-06-01T00:00:00Z"),
      ev("in", "2026-01-15T00:00:00Z"),
      ev("future", "2027-01-01T00:00:00Z"),
    ];
    const kept = filterEventsByScope(events, { start: "2026-01-01T00:00:00Z", end: "2026-12-31T00:00:00Z" });
    expect(kept.map((e) => e.id)).toEqual(["in"]);
  });
});

describe("ScopeStore", () => {
  let store: ScopeStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-scope-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new ScopeStore(cases);
  });

  it("defaults to no scope and round-trips a window", async () => {
    expect(await store.load("c1")).toEqual({ start: null, end: null });
    await store.save("c1", { start: "2026-01-01T00:00:00Z", end: null });
    expect(await store.load("c1")).toEqual({ start: "2026-01-01T00:00:00Z", end: null });
  });
});
