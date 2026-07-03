import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DwellWindowStore } from "../../src/analysis/dwellWindowStore.js";

describe("DwellWindowStore", () => {
  let store: DwellWindowStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-dwell-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new DwellWindowStore(cases);
  });

  it("returns [] when no windows exist", async () => {
    expect(await store.list("c1")).toEqual([]);
  });

  it("adds a window (server-assigned id + createdAt)", async () => {
    const w = await store.add("c1", { label: "Session 1", start: "2026-06-01T00:00:00Z", end: "2026-06-02T00:00:00Z" });
    expect(w.id).toBeTruthy();
    expect(w.createdAt).toBeTruthy();
    expect(w.label).toBe("Session 1");
    expect(await store.list("c1")).toHaveLength(1);
  });

  it("rejects invalid input (propagates sanitizeDwellWindowInput's error)", async () => {
    await expect(store.add("c1", { label: "", start: "2026-06-01T00:00:00Z", end: "2026-06-02T00:00:00Z" })).rejects.toThrow(/label/);
  });

  it("updates a window by id; returns null for an unknown id", async () => {
    const w = await store.add("c1", { label: "Session 1", start: "2026-06-01T00:00:00Z", end: "2026-06-02T00:00:00Z" });
    const updated = await store.update("c1", w.id, { label: "Session 1 (refined)", start: w.start, end: w.end });
    expect(updated?.label).toBe("Session 1 (refined)");
    expect(await store.update("c1", "nope", { label: "x", start: w.start, end: w.end })).toBeNull();
  });

  it("removes a window by id; returns false when it didn't exist", async () => {
    const w = await store.add("c1", { label: "Session 1", start: "2026-06-01T00:00:00Z", end: "2026-06-02T00:00:00Z" });
    expect(await store.remove("c1", w.id)).toBe(true);
    expect(await store.list("c1")).toEqual([]);
    expect(await store.remove("c1", w.id)).toBe(false);
  });

  it("get() returns one window by id or null", async () => {
    const w = await store.add("c1", { label: "Session 1", start: "2026-06-01T00:00:00Z", end: "2026-06-02T00:00:00Z" });
    expect((await store.get("c1", w.id))?.id).toBe(w.id);
    expect(await store.get("c1", "nope")).toBeNull();
  });
});
