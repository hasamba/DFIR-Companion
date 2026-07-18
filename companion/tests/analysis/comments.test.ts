import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CommentsStore, parseMentions } from "../../src/analysis/comments.js";

describe("CommentsStore", () => {
  let store: CommentsStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-comments-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new CommentsStore(cases);
  });

  it("returns [] when no comments exist", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("adds a comment (server-assigned id + createdAt) and lists it", async () => {
    const c = await store.add("c1", { targetType: "ioc", targetId: "i1", author: "Alice", text: "looks like C2" });
    expect(c.id).toBeTruthy();
    expect(c.createdAt).toBeTruthy();
    expect(c.author).toBe("Alice");
    const list = await store.load("c1");
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ targetType: "ioc", targetId: "i1", text: "looks like C2" });
  });

  it("defaults a blank author to anonymous and trims text", async () => {
    const c = await store.add("c1", { targetType: "event", targetId: "e1", author: "   ", text: "  a note  " });
    expect(c.author).toBe("anonymous");
    expect(c.text).toBe("a note");
  });

  it("removes a comment by id (true if it existed)", async () => {
    const c = await store.add("c1", { targetType: "finding", targetId: "f1", author: "Bob", text: "x" });
    expect(await store.remove("c1", c.id)).toBe(true);
    expect(await store.load("c1")).toHaveLength(0);
    expect(await store.remove("c1", "does-not-exist")).toBe(false);
  });

  it("parses @name mentions and stores them on the comment", async () => {
    const c = await store.add("c1", {
      targetType: "finding", targetId: "f1", author: "Bob",
      text: "cc @alice and @Charlie-99 can you check this?",
    });
    expect(c.mentions).toEqual(["alice", "Charlie-99"]);
  });

  it("de-dupes mentions case-insensitively, keeping first-seen casing and order", () => {
    expect(parseMentions("@Alice ping @alice again, @bob")).toEqual(["Alice", "bob"]);
  });

  it("does not treat email addresses / IOCs as mentions", () => {
    // The `@` in an email is preceded by a handle char, so it must not parse as a mention.
    expect(parseMentions("contact bob@example.com about this")).toEqual([]);
    expect(parseMentions("beacon to admin@evil-domain.net was seen")).toEqual([]);
    // A real leading mention alongside an email: only the mention, never the email domain.
    expect(parseMentions("@alice can you check bob@example.com?")).toEqual(["alice"]);
    // Mid-word @ (e.g. within a token) is not a mention either.
    expect(parseMentions("path/to@v2/thing")).toEqual([]);
  });

  it("returns [] mentions when the text has no @tokens", async () => {
    const c = await store.add("c1", { targetType: "event", targetId: "e1", author: "Bob", text: "no mentions here" });
    expect(c.mentions).toEqual([]);
  });
});
