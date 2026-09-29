// TagsStore.addMany (#1874): the automatic tagger writes an import's tags in ONE load and ONE save.
// Adding them one at a time re-read, re-validated and rewrote the whole tags file per tag, so a
// rule that matched 20,000 rows of one import spent minutes in the tag loop and the cost grew with
// the square of the tag count. The batch keeps add()'s rules exactly: normalized labels, one tag
// per (target, label) with the first author winning, and cap protection for analyst event tags.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { TagsStore, type EventProtectionSink } from "../../src/analysis/tags.js";

describe("TagsStore.addMany", () => {
  let cases: CaseStore;
  let store: TagsStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-tags-many-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new TagsStore(cases);
  });

  it("creates every new tag in order and returns only the created ones", async () => {
    await store.add("c1", { targetType: "event", targetId: "e1", author: "alice", label: "keep" });
    const created = await store.addMany("c1", [
      { targetType: "event", targetId: "e1", author: "tagger:r1", label: "Keep" }, // exists already
      { targetType: "event", targetId: "e2", author: "tagger:r1", label: "persistence" },
      { targetType: "event", targetId: "e2", author: "tagger:r2", label: "persistence" }, // first author wins
      { targetType: "event", targetId: "e3", author: "tagger:r2", label: "  Lateral  Movement " },
    ]);
    expect(created.map((t) => [t.targetId, t.label, t.author])).toEqual([
      ["e2", "persistence", "tagger:r1"],
      ["e3", "lateral-movement", "tagger:r2"],
    ]);
    const all = await store.load("c1");
    expect(all.map((t) => [t.targetId, t.label, t.author])).toEqual([
      ["e1", "keep", "alice"],
      ["e2", "persistence", "tagger:r1"],
      ["e3", "lateral-movement", "tagger:r2"],
    ]);
    expect(new Set(all.map((t) => t.id)).size).toBe(3);
  });

  it("writes the file once for the whole batch", async () => {
    const inputs = Array.from({ length: 500 }, (_, i) => ({
      targetType: "event",
      targetId: `e${i}`,
      author: "tagger:r1",
      label: "x",
    }));
    const save = vi.spyOn(store as unknown as { save: (...a: unknown[]) => Promise<void> }, "save");
    expect(await store.addMany("c1", inputs)).toHaveLength(500);
    expect(save).toHaveBeenCalledTimes(1);
    expect(await store.addMany("c1", inputs)).toEqual([]);
    expect(save).toHaveBeenCalledTimes(1); // nothing new → no write
  });

  it("protects analyst event tags, never tagger tags, before the save", async () => {
    const protection: EventProtectionSink = {
      protect: vi.fn(async () => true),
      unprotect: vi.fn(async () => {}),
    };
    store = new TagsStore(cases, protection);
    await store.addMany("c1", [
      { targetType: "event", targetId: "e1", author: "tagger:r1", label: "x" },
      { targetType: "event", targetId: "e2", author: "alice", label: "y" },
      { targetType: "ioc", targetId: "i1", author: "alice", label: "z" },
    ]);
    expect(protection.protect).toHaveBeenCalledTimes(1);
    expect(protection.protect).toHaveBeenCalledWith("c1", "e2");
  });

  it("refuses an empty label, as add() does, and writes nothing", async () => {
    await expect(
      store.addMany("c1", [
        { targetType: "event", targetId: "e1", author: "tagger:r1", label: "ok" },
        { targetType: "event", targetId: "e2", author: "tagger:r1", label: "   " },
      ]),
    ).rejects.toThrow(/label is required/);
    expect(await store.load("c1")).toEqual([]);
  });
});

describe("TagsStore.addMany dedup key", () => {
  it("does not treat two different targets as one when their text contains the separator", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-tags-key-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new TagsStore(cases);
    const created = await store.addMany("c1", [
      { targetType: "event", targetId: "a\nb", author: "tagger:r", label: "c" },
      { targetType: "event\na", targetId: "b", author: "tagger:r", label: "c" },
    ]);
    expect(created).toHaveLength(2);
  });
});
