import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CaseStore } from "../../../src/storage/caseStore.js";
import { WatsonChatStore, WATSON_MAX_TURNS } from "../../../src/analysis/ai/watson/chatStore.js";
import { emptyWatsonChat, type WatsonTurn } from "../../../src/analysis/ai/watson/types.js";
import { SNAPSHOT_STATE_FILES } from "../../../src/analysis/investigationStateFiles.js";
import { mergeMaskRoster, WATSON_MASK_ROSTER_MAX } from "../../../src/analysis/ai/watson/superRoster.js";

const makeTurns = (n: number): WatsonTurn[] =>
  Array.from({ length: n }, (_, i) => ({
    id: `t${i}`,
    at: "2026-11-13T10:00:00.000Z",
    role: "analyst" as const,
    text: `turn ${i}`,
  }));

describe("WatsonChatStore", () => {
  let dir: string;
  let store: WatsonChatStore;
  let path: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "watson-chat-"));
    store = new WatsonChatStore({ stateDir: () => dir } as unknown as CaseStore);
    path = join(dir, "watson-chat.json");
  });

  it("returns an empty chat when the file is missing or malformed", async () => {
    expect(await store.load("c1")).toEqual(emptyWatsonChat());
    await writeFile(path, "{not json");
    expect(await store.load("c1")).toEqual(emptyWatsonChat());
  });

  it.each([
    ["bad JSON", "{not json"],
    ["valid JSON of the wrong shape", "[1, 2]"],
  ])("keeps a corrupt file (%s) as a backup before the first write replaces it", async (_why, body) => {
    await writeFile(path, body);
    await store.update("c1", (c) => ({ ...c, memory: "new" }));
    const backups = (await readdir(dir)).filter((f) => f.startsWith("watson-chat.json.corrupt-"));
    expect(backups).toHaveLength(1);
    expect(backups[0]).not.toContain(":");
    expect(await readFile(join(dir, backups[0]), "utf8")).toBe(body);
    expect((await store.load("c1")).memory).toBe("new");
    // A healthy file is not backed up again.
    await store.update("c1", (c) => ({ ...c, memory: "newer" }));
    expect((await readdir(dir)).filter((f) => f.includes(".corrupt-"))).toHaveLength(1);
  });

  it("loads a phase-1 chat's string case events as kind other, and keeps typed ones and the pause", async () => {
    const typed = { kind: "import", text: "An import finished", at: "2026-11-13T10:00:00.000Z" };
    await writeFile(
      path,
      JSON.stringify({
        pendingCaseEvents: ["Analyst edited the notebook", typed, { kind: "bogus", text: "odd" }, 7],
        reactionsPaused: "presidio",
      }),
    );
    const chat = await store.load("c1");
    expect(chat.pendingCaseEvents).toEqual([
      { kind: "other", text: "Analyst edited the notebook", at: "" },
      typed,
      { kind: "other", text: "odd", at: "" },
    ]);
    expect(chat.reactionsPaused).toBe("presidio");
    expect(chat.analystEngaged).toBeUndefined();
    await writeFile(path, JSON.stringify({ reactionsPaused: "whenever", reactionFailures: -1 }));
    const junk = await store.load("c1");
    expect(junk.reactionsPaused).toBeUndefined();
    expect(junk.reactionFailures).toBeUndefined();
    // A chat written before the flag counts as engaged when it holds an analyst turn.
    await writeFile(
      path,
      JSON.stringify({ turns: makeTurns(1), reactionsPaused: "errors", reactionFailures: 2 }),
    );
    const legacy = await store.load("c1");
    expect(legacy).toMatchObject({ analystEngaged: true, reactionsPaused: "errors", reactionFailures: 2 });
  });

  it("drops rejected and undone proposals whose turn left the chat, and keeps pending and applied ones", async () => {
    const turns = makeTurns(WATSON_MAX_TURNS + 1); // t0 falls off the end
    const prop = (id: string, turnId: string, status: string) => ({
      id,
      turnId,
      kind: "question_new",
      questionId: "q1",
      status,
      after: { id: "q1", question: "Q?", status: "unknown", answer: "", pointer: "" },
    });
    const proposals = [
      prop("gone-rejected", "t0", "rejected"),
      prop("gone-undone", "t0", "undone"),
      prop("gone-pending", "t0", "pending"),
      prop("gone-applied", "t0", "applied"),
      prop("kept-rejected", "t5", "rejected"),
    ];
    await store.save("c1", { ...emptyWatsonChat(), turns, proposals } as never);
    const ids = (await store.load("c1")).proposals.map((p) => p.id);
    expect(ids).toEqual(["gone-pending", "gone-applied", "kept-rejected"]);
  });

  it("round-trips and caps turns at WATSON_MAX_TURNS", async () => {
    const chat = { ...emptyWatsonChat(), turns: makeTurns(WATSON_MAX_TURNS + 5), memory: "kept" };
    await store.save("c1", chat);
    const back = await store.load("c1");
    expect(back.turns).toHaveLength(WATSON_MAX_TURNS);
    expect(back.turns[0].id).toBe("t5");
    expect(back.memory).toBe("kept");
    expect(chat.turns).toHaveLength(WATSON_MAX_TURNS + 5);
  });

  it("drops turns whose shape is invalid instead of rejecting the file", async () => {
    const good = makeTurns(2);
    const raw = { ...emptyWatsonChat(), turns: [good[0], { id: 5, role: "bogus" }, good[1]], memory: "m" };
    await writeFile(path, JSON.stringify(raw));
    const back = await store.load("c1");
    expect(back.turns.map((t) => t.id)).toEqual(["t0", "t1"]);
    expect(back.memory).toBe("m");
  });

  it("truncates over-long turn text on save", async () => {
    const long = { ...makeTurns(1)[0], text: "x".repeat(9000) };
    await store.save("c1", { ...emptyWatsonChat(), turns: [long] });
    const back = await store.load("c1");
    expect(back.turns[0].text.length).toBeLessThanOrEqual(8000);
    expect(JSON.parse(await readFile(path, "utf8")).turns).toHaveLength(1);
  });

  it("serializes concurrent update() calls so no write is lost", async () => {
    const [a, b] = await Promise.all([
      store.update("c1", async (c) => ({ ...c, turns: [...c.turns, makeTurns(1)[0]] })),
      store.update("c1", async (c) => ({ ...c, turns: [...c.turns, { ...makeTurns(1)[0], id: "other" }] })),
    ]);
    expect(a.turns).toHaveLength(1);
    expect(b.turns).toHaveLength(2);
    const back = await store.load("c1");
    expect(back.turns.map((t) => t.id).sort()).toEqual(["other", "t0"]);
  });

  it("rejects only the call whose fn throws and keeps the chain alive", async () => {
    const bad = store.update("c1", () => {
      throw new Error("boom");
    });
    const good = store.update("c1", (c) => ({ ...c, memory: "after" }));
    await expect(bad).rejects.toThrow("boom");
    expect((await good).memory).toBe("after");
    expect((await store.load("c1")).memory).toBe("after");
  });
});

describe("the persisted mask roster (Watson phase 4, D2d)", () => {
  let dir: string;
  let store: WatsonChatStore;
  let path: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "watson-chat-roster-"));
    store = new WatsonChatStore({ stateDir: () => dir } as unknown as CaseStore);
    path = join(dir, "watson-chat.json");
  });

  it("an old chat file loads without a roster", async () => {
    await writeFile(path, JSON.stringify({ turns: [], memory: "m" }));
    expect((await store.load("c1")).maskRoster).toBeUndefined();
  });

  it("round-trips, lower-cased and deduped case-insensitively; junk entries are dropped", async () => {
    await writeFile(
      path,
      JSON.stringify({
        maskRoster: { hosts: ["FINSRV-07", "finsrv-07", 5, ""], users: "nope", ips: ["10.0.0.1"] },
      }),
    );
    expect((await store.load("c1")).maskRoster).toEqual({
      hosts: ["finsrv-07"],
      users: [],
      ips: ["10.0.0.1"],
    });
  });

  it("keeps each list at 500 names, dropping the oldest; a name seen again counts as newest", () => {
    const older = { hosts: Array.from({ length: 500 }, (_, i) => `h${i}`), users: [], ips: [] };
    const merged = mergeMaskRoster(older, { hosts: ["NEW", "H0"], users: ["Alice"], ips: [] });
    expect(merged.hosts).toHaveLength(WATSON_MASK_ROSTER_MAX);
    expect(merged.hosts.slice(-2)).toEqual(["new", "h0"]);
    expect(merged.hosts).not.toContain("h1"); // the oldest left
    expect(merged.users).toEqual(["alice"]);
    expect(older.hosts).toHaveLength(500); // the input is not changed
  });

  it("a cap applies on load too", async () => {
    const hosts = Array.from({ length: 600 }, (_, i) => `h${i}`);
    await writeFile(path, JSON.stringify({ maskRoster: { hosts, users: [], ips: [] } }));
    const loaded = (await store.load("c1")).maskRoster;
    expect(loaded?.hosts).toHaveLength(500);
    expect(loaded?.hosts[0]).toBe("h100");
  });
});

describe("snapshot allowlist", () => {
  it("includes watson-chat.json so the chat travels with the case", () => {
    expect(SNAPSHOT_STATE_FILES).toContain("watson-chat.json");
  });
});
