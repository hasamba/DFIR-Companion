import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { PinnedFindingsStore, PinLimitError } from "../../src/analysis/pinnedFindings.js";

describe("PinnedFindingsStore", () => {
  let cases: CaseStore;
  let store: PinnedFindingsStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-pins-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new PinnedFindingsStore(cases);
  });

  it("returns [] when nothing is pinned", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("pins a finding (server-assigned pinnedAt) and lists it", async () => {
    const list = await store.pin("c1", { findingId: "f-1", pinnedBy: "Alice" });
    expect(list).toHaveLength(1);
    expect(list[0].findingId).toBe("f-1");
    expect(list[0].pinnedBy).toBe("Alice");
    expect(list[0].pinnedAt).toBeTruthy();
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("defaults a blank author to anonymous and trims the findingId", async () => {
    const list = await store.pin("c1", { findingId: "  f-2  ", pinnedBy: "   " });
    expect(list[0].findingId).toBe("f-2");
    expect(list[0].pinnedBy).toBe("anonymous");
  });

  it("appends in pin order", async () => {
    await store.pin("c1", { findingId: "f-1" });
    await store.pin("c1", { findingId: "f-2" });
    await store.pin("c1", { findingId: "f-3" });
    expect((await store.load("c1")).map((p) => p.findingId)).toEqual(["f-1", "f-2", "f-3"]);
  });

  it("is idempotent: re-pinning the same finding does not duplicate", async () => {
    await store.pin("c1", { findingId: "f-1", pinnedBy: "Alice" });
    const list = await store.pin("c1", { findingId: "f-1", pinnedBy: "Bob" });
    expect(list).toHaveLength(1);
    expect(list[0].pinnedBy).toBe("Alice"); // original pin preserved
  });

  it("throws on a blank findingId", async () => {
    await expect(store.pin("c1", { findingId: "   " })).rejects.toThrow(/findingId/);
  });

  it("enforces the cap and reports the max via PinLimitError", async () => {
    const small = new PinnedFindingsStore(cases, 2);
    await small.pin("c1", { findingId: "f-1" });
    await small.pin("c1", { findingId: "f-2" });
    await expect(small.pin("c1", { findingId: "f-3" })).rejects.toBeInstanceOf(PinLimitError);
    expect(small.limit).toBe(2);
    // re-pinning an existing one still works at the cap (idempotent, no growth)
    await expect(small.pin("c1", { findingId: "f-1" })).resolves.toHaveLength(2);
  });

  it("defaults the cap to 5", async () => {
    expect(new PinnedFindingsStore(cases).limit).toBe(5);
    expect(new PinnedFindingsStore(cases, 0).limit).toBe(5); // 0 falls back to default
  });

  it("unpins by id (no-op when not pinned)", async () => {
    await store.pin("c1", { findingId: "f-1" });
    await store.pin("c1", { findingId: "f-2" });
    const after = await store.unpin("c1", "f-1");
    expect(after.map((p) => p.findingId)).toEqual(["f-2"]);
    // unpinning something not pinned is a no-op
    expect((await store.unpin("c1", "nope")).map((p) => p.findingId)).toEqual(["f-2"]);
  });

  it("reorders to match the given id order", async () => {
    await store.pin("c1", { findingId: "f-1" });
    await store.pin("c1", { findingId: "f-2" });
    await store.pin("c1", { findingId: "f-3" });
    const after = await store.reorder("c1", ["f-3", "f-1", "f-2"]);
    expect(after.map((p) => p.findingId)).toEqual(["f-3", "f-1", "f-2"]);
  });

  it("reorder ignores unknown ids and appends any omitted pins in their existing order", async () => {
    await store.pin("c1", { findingId: "f-1" });
    await store.pin("c1", { findingId: "f-2" });
    await store.pin("c1", { findingId: "f-3" });
    // only f-3 given (+ a bogus id); f-1 and f-2 keep their relative order at the end
    const after = await store.reorder("c1", ["f-3", "bogus"]);
    expect(after.map((p) => p.findingId)).toEqual(["f-3", "f-1", "f-2"]);
  });

  it("keeps pins independent per case", async () => {
    await cases.createCase({ caseId: "c2", name: "n2", investigator: "i", aiProvider: null });
    await store.pin("c1", { findingId: "f-1" });
    expect(await store.load("c2")).toEqual([]);
  });
});
