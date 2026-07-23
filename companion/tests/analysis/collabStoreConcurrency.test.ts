import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { NotebookStore } from "../../src/analysis/notebookStore.js";
import { PinnedFindingsStore } from "../../src/analysis/pinnedFindings.js";

// Each of these stores load-modify-writes a whole JSON collection. Two requests arriving together
// both read the same snapshot, both append their own item, and the second save overwrites the
// first — the analyst's comment/tag/note/pin silently disappears (#216).
let cases: CaseStore;
const CASE = "c1";
const CONCURRENT = 12;

beforeEach(async () => {
  cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-collab-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
});

describe("collaboration store concurrency (#216)", () => {
  it("keeps every comment when many are added at once", async () => {
    const store = new CommentsStore(cases);
    await Promise.all(
      Array.from({ length: CONCURRENT }, (_, i) =>
        store.add(CASE, { targetType: "event", targetId: "e1", author: "a", text: `comment ${i}` }),
      ),
    );
    const stored = await store.load(CASE);
    expect(stored).toHaveLength(CONCURRENT);
    // Every distinct text survived — not just the right count.
    expect(new Set(stored.map((c) => c.text)).size).toBe(CONCURRENT);
  });

  it("keeps every tag when many are added at once", async () => {
    const store = new TagsStore(cases);
    await Promise.all(
      Array.from({ length: CONCURRENT }, (_, i) =>
        store.add(CASE, { targetType: "event", targetId: `e${i}`, author: "a", label: `label-${i}` }),
      ),
    );
    const stored = await store.load(CASE);
    expect(stored).toHaveLength(CONCURRENT);
    expect(new Set(stored.map((t) => t.label)).size).toBe(CONCURRENT);
  });

  it("keeps every notebook entry when many are added at once", async () => {
    const store = new NotebookStore(cases);
    await Promise.all(
      Array.from({ length: CONCURRENT }, (_, i) =>
        store.add(CASE, { text: `note ${i}`, type: "note", author: "a" }),
      ),
    );
    const stored = await store.load(CASE);
    expect(stored).toHaveLength(CONCURRENT);
    expect(new Set(stored.map((e) => e.text)).size).toBe(CONCURRENT);
  });

  it("keeps every pin when many are pinned at once", async () => {
    const store = new PinnedFindingsStore(cases, CONCURRENT);
    await Promise.all(
      Array.from({ length: CONCURRENT }, (_, i) => store.pin(CASE, { findingId: `f${i}`, pinnedBy: "a" })),
    );
    const stored = await store.load(CASE);
    expect(stored).toHaveLength(CONCURRENT);
    expect(new Set(stored.map((p) => p.findingId)).size).toBe(CONCURRENT);
  });

  it("does not lose a concurrent add when another item is being removed", async () => {
    // Mixed traffic is the realistic shape: one analyst deletes while another comments.
    const store = new CommentsStore(cases);
    const seed = await store.add(CASE, { targetType: "event", targetId: "e1", author: "a", text: "seed" });
    await Promise.all([
      store.remove(CASE, seed.id),
      store.add(CASE, { targetType: "event", targetId: "e1", author: "b", text: "kept" }),
    ]);
    const stored = await store.load(CASE);
    expect(stored.map((c) => c.text)).toEqual(["kept"]);
  });

  it("keeps the two cases independent while both are written concurrently", async () => {
    // The lock is per case, so a busy case must never serialize (or corrupt) another one.
    await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    const store = new CommentsStore(cases);
    await Promise.all([
      ...Array.from({ length: 6 }, (_, i) => store.add(CASE, { targetType: "event", targetId: "e", author: "a", text: `c1-${i}` })),
      ...Array.from({ length: 6 }, (_, i) => store.add("c2", { targetType: "event", targetId: "e", author: "a", text: `c2-${i}` })),
    ]);
    expect(await store.load(CASE)).toHaveLength(6);
    expect(await store.load("c2")).toHaveLength(6);
  });
});
