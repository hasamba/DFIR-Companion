import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SlashCommandChannelStore,
  bindingKey,
  telegramChatsFromBindings,
} from "../../src/analysis/slashCommandStore.js";

let file: string;
let store: SlashCommandChannelStore;

beforeEach(async () => {
  const dir = await mkdtemp(join(tmpdir(), "dfir-slashbind-"));
  file = join(dir, "slash-command-bindings.json");
  store = new SlashCommandChannelStore(file);
});

describe("SlashCommandChannelStore", () => {
  it("reads as empty before anything is written", async () => {
    expect(await store.loadAll()).toEqual({});
    expect(await store.get("slack:C1")).toBeUndefined();
  });

  it("round-trips a binding", async () => {
    const bound = await store.bind("slack:C1", "case-1", "2026-07-25T00:00:00Z");
    expect(bound).toEqual({ caseId: "case-1", boundAt: "2026-07-25T00:00:00Z" });
    expect(await store.get("slack:C1")).toEqual({ caseId: "case-1", boundAt: "2026-07-25T00:00:00Z" });
  });

  it("rebinding replaces only that channel's entry", async () => {
    await store.bind("slack:C1", "case-1");
    await store.bind("slack:C2", "case-2");
    await store.bind("slack:C1", "case-9");
    expect((await store.get("slack:C1"))?.caseId).toBe("case-9");
    expect((await store.get("slack:C2"))?.caseId).toBe("case-2");
  });

  it("unbind removes the entry and reports whether there was one", async () => {
    await store.bind("slack:C1", "case-1");
    expect(await store.unbind("slack:C1")).toBe(true);
    expect(await store.get("slack:C1")).toBeUndefined();
    expect(await store.unbind("slack:C1")).toBe(false);
  });

  it("keys by platform so the same channel id on two platforms does not collide", async () => {
    await store.bind(bindingKey("slack", "1001"), "case-slack");
    await store.bind(bindingKey("teams", "1001"), "case-teams");
    await store.bind(bindingKey("telegram", "1001"), "case-telegram");
    expect((await store.get("slack:1001"))?.caseId).toBe("case-slack");
    expect((await store.get("teams:1001"))?.caseId).toBe("case-teams");
    expect((await store.get("telegram:1001"))?.caseId).toBe("case-telegram");
  });

  it("survives a corrupt file rather than throwing at the caller", async () => {
    await writeFile(file, "{ not json", "utf8");
    await expect(store.loadAll()).rejects.toThrow(); // malformed JSON surfaces...
    await writeFile(file, JSON.stringify({ "slack:C1": { caseId: 42 } }), "utf8");
    expect(await store.loadAll()).toEqual({}); // ...but a schema mismatch degrades to empty
  });

  // On a fresh install the notifications/ dir beside cases/ does not exist yet, so the very first
  // `/dfir bind` is what has to create it. Every other test here starts from an mkdtemp'd dir,
  // which hid this.
  it("creates the parent directory on first write", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-slashbind-fresh-"));
    const nested = new SlashCommandChannelStore(join(dir, "notifications", "slash-command-bindings.json"));
    await expect(nested.bind("slack:C1", "case-1")).resolves.toMatchObject({ caseId: "case-1" });
    expect(await nested.get("slack:C1")).toMatchObject({ caseId: "case-1" });
  });

  it("writes readable JSON (an operator may need to edit it by hand)", async () => {
    await store.bind("slack:C1", "case-1");
    expect(JSON.parse(await readFile(file, "utf8"))).toHaveProperty("slack:C1.caseId", "case-1");
  });
});

// Feeds the notification channel form's Chat ID box, so the operator picks a chat the bot already
// talks to instead of hunting the number out of this file.
describe("telegramChatsFromBindings", () => {
  it("keeps only telegram bindings, strips the prefix, and sorts", () => {
    expect(
      telegramChatsFromBindings({
        "telegram:12345678": { caseId: "demo", boundAt: "2026-07-27T19:09:46.655Z" },
        "slack:C123": { caseId: "other", boundAt: "2026-07-27T19:09:46.655Z" },
        "teams:19:meeting": { caseId: "other", boundAt: "2026-07-27T19:09:46.655Z" },
        "telegram:-1001234567890": { caseId: "INC-1", boundAt: "2026-07-28T00:00:00.000Z" },
      }),
    ).toEqual([
      { chatId: "-1001234567890", caseId: "INC-1", boundAt: "2026-07-28T00:00:00.000Z" },
      { chatId: "12345678", caseId: "demo", boundAt: "2026-07-27T19:09:46.655Z" },
    ]);
  });

  it("keeps a channel id containing a colon whole", () => {
    const r = telegramChatsFromBindings({
      "telegram:@my:channel": { caseId: "c", boundAt: "2026-07-27T00:00:00.000Z" },
    });
    expect(r[0].chatId).toBe("@my:channel");
  });

  it("returns nothing for an empty or telegram-free map, and drops an empty chat id", () => {
    expect(telegramChatsFromBindings({})).toEqual([]);
    expect(
      telegramChatsFromBindings({ "slack:C1": { caseId: "c", boundAt: "2026-07-27T00:00:00.000Z" } }),
    ).toEqual([]);
    expect(
      telegramChatsFromBindings({ "telegram:": { caseId: "c", boundAt: "2026-07-27T00:00:00.000Z" } }),
    ).toEqual([]);
  });
});
