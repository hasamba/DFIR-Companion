import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { TagsStore, normalizeLabel } from "../../src/analysis/tags.js";

describe("normalizeLabel", () => {
  it("lowercases, trims, and collapses whitespace to hyphens", () => {
    expect(normalizeLabel("  Confirmed   Malicious ")).toBe("confirmed-malicious");
    expect(normalizeLabel("C2 Comms")).toBe("c2-comms");
    expect(normalizeLabel("already-normal")).toBe("already-normal");
  });
});

describe("TagsStore", () => {
  let store: TagsStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-tags-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new TagsStore(cases);
  });

  it("returns [] when no tags exist", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("adds a tag (server-assigned id + createdAt) and lists it", async () => {
    const t = await store.add("c1", { targetType: "ioc", targetId: "i1", author: "Alice", label: "c2-comms" });
    expect(t.id).toBeTruthy();
    expect(t.createdAt).toBeTruthy();
    expect(t.author).toBe("Alice");
    const list = await store.load("c1");
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ targetType: "ioc", targetId: "i1", label: "c2-comms" });
  });

  it("normalizes the label and defaults a blank author to anonymous", async () => {
    const t = await store.add("c1", { targetType: "event", targetId: "e1", author: "   ", label: "  Key Evidence " });
    expect(t.author).toBe("anonymous");
    expect(t.label).toBe("key-evidence");
  });

  it("is idempotent per target: re-adding the same label returns the existing tag", async () => {
    const a = await store.add("c1", { targetType: "event", targetId: "e1", author: "Bob", label: "Needs Review" });
    const b = await store.add("c1", { targetType: "event", targetId: "e1", author: "Carol", label: "needs-review" });
    expect(b.id).toBe(a.id);
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("allows the same label on different targets", async () => {
    await store.add("c1", { targetType: "event", targetId: "e1", author: "Bob", label: "pivot-point" });
    await store.add("c1", { targetType: "event", targetId: "e2", author: "Bob", label: "pivot-point" });
    expect(await store.load("c1")).toHaveLength(2);
  });

  it("throws on an empty label", async () => {
    await expect(store.add("c1", { targetType: "event", targetId: "e1", author: "Bob", label: "   " })).rejects.toThrow(/label/);
  });

  it("removes a tag by id (true if it existed)", async () => {
    const t = await store.add("c1", { targetType: "finding", targetId: "f1", author: "Bob", label: "false-positive" });
    expect(await store.remove("c1", t.id)).toBe(true);
    expect(await store.load("c1")).toHaveLength(0);
    expect(await store.remove("c1", "does-not-exist")).toBe(false);
  });
});
