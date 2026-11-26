import { mkdtemp, readFile, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  MIRROR_SENT_MAX,
  MIRROR_SEEN_MAX,
  WatsonMirrorStore,
} from "../../../src/integrations/telegram/watsonMirrorStore.js";

// #2897: the token lookup must go through crypto.timingSafeEqual; wrap the real one to observe it.
const timingSafe = vi.hoisted(() => ({ calls: 0 }));
vi.mock("node:crypto", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:crypto")>();
  return {
    ...real,
    timingSafeEqual: (a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView) => {
      timingSafe.calls += 1;
      return real.timingSafeEqual(a, b);
    },
  };
});

// #2647: the per-chat mirror state, in one JSON file beside the chat bindings (notifications/),
// never under cases/. Absent entry = mirroring off.

let file: string;
let store: WatsonMirrorStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-mirror-store-"));
  file = join(root, "notifications", "watson-mirror.json");
  store = new WatsonMirrorStore(file);
});

const enable = (chatId: string, caseId = "c1") =>
  store.enable(chatId, {
    caseId,
    chatType: "private",
    by: "42",
    boundAt: "b1",
    at: "2026-11-19T10:00:00.000Z",
  });

describe("WatsonMirrorStore", () => {
  it("is empty when the file is absent, and creates the folder on the first write", async () => {
    expect(await store.listCase("c1")).toEqual([]);
    await enable("100");
    const saved = JSON.parse(await readFile(file, "utf8"));
    expect(saved.chats["100"]).toMatchObject({ caseId: "c1", enabledAt: "2026-11-19T10:00:00.000Z" });
  });

  it("lists only the chats of one case", async () => {
    await enable("100", "c1");
    await enable("200", "c2");
    expect((await store.listCase("c1")).map((c) => c.chatId)).toEqual(["100"]);
  });

  it("enqueues in order, marks sent, and never enqueues a sent or pending id twice", async () => {
    await enable("100");
    await store.enqueue("100", ["t1", "t2"], "t2");
    await store.enqueue("100", ["t2", "t3"], "t3");
    expect((await store.get("100"))?.pending).toEqual(["t1", "t2", "t3"]);
    await store.markSent("100", ["t1", "t2"], [11, 12]);
    const after = await store.get("100");
    expect(after?.pending).toEqual(["t3"]);
    expect(after?.sent).toEqual(["t1", "t2"]);
    expect(after?.messageIds).toEqual([11, 12]);
    expect(after?.cursor).toBe("t3");
    await store.enqueue("100", ["t1", "t3"], "t3");
    expect((await store.get("100"))?.pending).toEqual(["t3"]);
  });

  it("keeps the sent set to its cap", async () => {
    await enable("100");
    const ids = Array.from({ length: MIRROR_SENT_MAX + 20 }, (_, i) => `t${i}`);
    await store.enqueue("100", ids, ids.at(-1)!);
    await store.markSent("100", ids, []);
    const sent = (await store.get("100"))!.sent;
    expect(sent.length).toBe(MIRROR_SENT_MAX);
    expect(sent[0]).toBe("t20");
  });

  it("ignores work for a chat that was switched off in the meantime", async () => {
    await enable("100");
    await store.disable("100");
    await store.enqueue("100", ["t1"], "t1");
    expect(await store.get("100")).toBeUndefined();
  });

  it("drops every chat of a deleted case", async () => {
    await enable("100", "c1");
    await enable("101", "c1");
    await enable("200", "c2");
    const dropped = await store.disableCase("c1");
    expect(dropped.map((c) => c.chatId).sort()).toEqual(["100", "101"]);
    expect(await store.get("200")).toBeDefined();
  });

  it("remembers an inbound update once, up to its cap", async () => {
    expect(await store.markInbound("100:5")).toBe(true);
    expect(await store.markInbound("100:5")).toBe(false);
    for (let i = 0; i < MIRROR_SEEN_MAX; i++) await store.markInbound(`x:${i}`);
    expect(await store.markInbound("100:5")).toBe(true); // rotated out
  });

  it("reads a malformed file as empty (fail closed: nothing mirrors)", async () => {
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, "{not json");
    expect(await store.get("100")).toBeUndefined();
    await writeFile(file, JSON.stringify({ chats: { "100": { caseId: 5 } } }));
    expect(await store.get("100")).toBeUndefined();
  });

  it("holds and releases a chat, and keeps the retry schedule", async () => {
    await enable("100");
    await store.patch("100", { held: true, retry: { attempt: 2, nextAt: "2026-11-19T10:05:00.000Z" } });
    expect(await store.get("100")).toMatchObject({ held: true, retry: { attempt: 2 } });
    await store.patch("100", { held: false, retry: undefined });
    const e = await store.get("100");
    expect(e?.held).toBeFalsy();
    expect(e?.retry).toBeUndefined();
  });
});

describe("#2712 button tokens", () => {
  it("mints one token per proposal, reuses it, and finds it again", async () => {
    await enable("100");
    const first = await store.actionTokens("100", "2026-11-19T10:00:00.000Z", ["wp-1", "wp-2"]);
    expect(Object.keys(first)).toEqual(["wp-1", "wp-2"]);
    expect(first["wp-1"]).not.toBe(first["wp-2"]);
    const again = await store.actionTokens("100", "2026-11-19T10:00:00.000Z", ["wp-1"]);
    expect(again["wp-1"]).toBe(first["wp-1"]);
    const hit = await store.findAction(first["wp-2"]);
    expect(hit?.proposalId).toBe("wp-2");
    expect(hit?.entry).toMatchObject({ chatId: "100", caseId: "c1" });
    expect(await store.findAction("AAAAAAAAAAAAAAAA")).toBeUndefined();
  });

  it("matches a token only exactly, with a constant-time comparison (#2897)", async () => {
    await enable("100");
    const { "wp-1": token } = await store.actionTokens("100", "2026-11-19T10:00:00.000Z", ["wp-1"]);
    const flipped = (token[0] === "A" ? "B" : "A") + token.slice(1);
    expect(await store.findAction(flipped)).toBeUndefined();
    expect(await store.findAction(token.slice(0, 16))).toBeUndefined();
    expect(await store.findAction(token + "A")).toBeUndefined();
    expect(await store.findAction("")).toBeUndefined();
    const before = timingSafe.calls;
    expect((await store.findAction(token))?.proposalId).toBe("wp-1");
    expect(timingSafe.calls).toBeGreaterThan(before);
  });

  it("never honours or re-uses a pre-upgrade 16-character token (#2897)", async () => {
    await enable("100");
    const { "wp-cur": current } = await store.actionTokens("100", "2026-11-19T10:00:00.000Z", ["wp-cur"]);
    const saved = JSON.parse(await readFile(file, "utf8"));
    const legacy = "L".repeat(16);
    saved.chats["100"].actions.push(
      { token: legacy, proposalId: "wp-old" },
      { token: "M".repeat(16), proposalId: "wp-x" },
    );
    await writeFile(file, JSON.stringify(saved));

    expect(await store.findAction(legacy)).toBeUndefined();

    const out = await store.actionTokens("100", "2026-11-19T10:00:00.000Z", ["wp-cur", "wp-old"]);
    expect(out["wp-cur"]).toBe(current);
    expect(out["wp-old"]).not.toBe(legacy);
    expect(out["wp-old"]).toHaveLength(22);

    const reopened = new WatsonMirrorStore(file);
    const actions = JSON.parse(await readFile(file, "utf8")).chats["100"].actions as Array<{ token: string }>;
    expect(actions.every((a) => a.token.length === 22)).toBe(true);
    expect((await reopened.findAction(out["wp-old"]))?.proposalId).toBe("wp-old");
    const again = await reopened.actionTokens("100", "2026-11-19T10:00:00.000Z", ["wp-old"]);
    expect(again["wp-old"]).toBe(out["wp-old"]);
  });

  it("arms no buttons for another enablement or a chat that is off", async () => {
    await enable("100");
    expect(await store.actionTokens("100", "2000-01-01T00:00:00.000Z", ["wp-1"])).toEqual({});
    expect(await store.actionTokens("200", "2026-11-19T10:00:00.000Z", ["wp-1"])).toEqual({});
  });

  it("kills every button when mirroring is switched off or on again", async () => {
    await enable("100");
    const { "wp-1": token } = await store.actionTokens("100", "2026-11-19T10:00:00.000Z", ["wp-1"]);
    await store.disable("100");
    expect(await store.findAction(token)).toBeUndefined();
    await enable("100");
    const { "wp-1": t2 } = await store.actionTokens("100", "2026-11-19T10:00:00.000Z", ["wp-1"]);
    await enable("100"); // on again: a fresh entry
    expect(await store.findAction(t2)).toBeUndefined();
  });
});
