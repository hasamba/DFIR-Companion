import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { NotebookStore } from "../../src/analysis/notebookStore.js";

describe("NotebookStore", () => {
  let store: NotebookStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-notebook-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new NotebookStore(cases);
  });

  it("returns [] when no entries exist", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("adds a note (server-assigned id + timestamp) and lists it", async () => {
    const e = await store.add("c1", { type: "note", text: "suspect lateral movement" });
    expect(e.id).toBeTruthy();
    expect(e.timestamp).toBeTruthy();
    expect(e.type).toBe("note");
    expect(e.text).toBe("suspect lateral movement");
    const list = await store.load("c1");
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ type: "note", text: "suspect lateral movement" });
  });

  it("adds a note and a question", async () => {
    await store.add("c1", { type: "note", text: "initial access via phishing" });
    await store.add("c1", { type: "question", text: "when was the first execution?" });
    const list = await store.load("c1");
    expect(list).toHaveLength(2);
    expect(list[0].type).toBe("note");
    expect(list[1].type).toBe("question");
  });

  it("coerces the removed 'hypothesis' type to note (#140 — hypotheses moved to their own panel)", async () => {
    const e = await store.add("c1", { type: "hypothesis" as never, text: "initial access via phishing" });
    expect(e.type).toBe("note");
  });

  it("trims text on add", async () => {
    const e = await store.add("c1", { type: "note", text: "  trimmed  " });
    expect(e.text).toBe("trimmed");
  });

  it("records the author (trimmed) when provided", async () => {
    const e = await store.add("c1", { type: "note", text: "x", author: "  Jane Doe  " });
    expect(e.author).toBe("Jane Doe");
    expect((await store.load("c1"))[0].author).toBe("Jane Doe");
  });

  it("falls back to 'anonymous' when author is missing or blank", async () => {
    const noAuthor = await store.add("c1", { type: "note", text: "a" });
    const blankAuthor = await store.add("c1", { type: "note", text: "b", author: "   " });
    expect(noAuthor.author).toBe("anonymous");
    expect(blankAuthor.author).toBe("anonymous");
  });

  it("preserves the original author when an entry is edited", async () => {
    const e = await store.add("c1", { type: "note", text: "original", author: "Jane" });
    const updated = await store.update("c1", e.id, { text: "revised" });
    expect(updated!.author).toBe("Jane");
  });

  it("falls back to 'note' for unrecognized type", async () => {
    const e = await store.add("c1", { type: "bogus" as never, text: "x" });
    expect(e.type).toBe("note");
  });

  it("stores linkedEntityIds when provided", async () => {
    const e = await store.add("c1", { type: "question", text: "related to event", linkedEntityIds: ["e1", "e2"] });
    expect(e.linkedEntityIds).toEqual(["e1", "e2"]);
  });

  it("omits linkedEntityIds when empty", async () => {
    const e = await store.add("c1", { type: "note", text: "x", linkedEntityIds: [] });
    expect(e.linkedEntityIds).toBeUndefined();
  });

  it("updates text and type of an existing entry", async () => {
    const e = await store.add("c1", { type: "note", text: "original" });
    const updated = await store.update("c1", e.id, { text: "revised", type: "question" });
    expect(updated).not.toBeNull();
    expect(updated!.text).toBe("revised");
    expect(updated!.type).toBe("question");
    const list = await store.load("c1");
    expect(list[0].text).toBe("revised");
  });

  it("trims text on update", async () => {
    const e = await store.add("c1", { type: "note", text: "x" });
    const updated = await store.update("c1", e.id, { text: "  spaces  " });
    expect(updated!.text).toBe("spaces");
  });

  it("returns null when updating a non-existent entry", async () => {
    const result = await store.update("c1", "does-not-exist", { text: "x" });
    expect(result).toBeNull();
  });

  it("removes an entry by id (true if it existed)", async () => {
    const e = await store.add("c1", { type: "question", text: "why?" });
    expect(await store.remove("c1", e.id)).toBe(true);
    expect(await store.load("c1")).toHaveLength(0);
    expect(await store.remove("c1", "does-not-exist")).toBe(false);
  });

  it("persists multiple entries across reloads", async () => {
    await store.add("c1", { type: "note", text: "a" });
    await store.add("c1", { type: "note", text: "b" });
    await store.add("c1", { type: "question", text: "c" });
    const list = await store.load("c1");
    expect(list).toHaveLength(3);
    expect(list.map((e) => e.text)).toEqual(["a", "b", "c"]);
  });
});
