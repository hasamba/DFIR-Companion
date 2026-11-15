import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { keepChatRosterDurable, WatsonRosterUnreadable } from "../../../src/analysis/ai/watson/rosterRead.js";
import { BackupManager, resolveBackupConfig } from "../../../src/storage/backupManager.js";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { Scripted, final, toolHarness } from "./roundToolsFixtures.js";

// Task 1 review fixes: a write never clears the fail-closed guard of a corrupt chat, and a backup restore
// folds the current chat roster into the sidecar first, so a case with no sidecar keeps its names.

const CASE = "c1";
const ROSTER_FILE = "watson-mask-roster.json";
const chatJson = (hosts: string[]) =>
  JSON.stringify({ turns: [], maskRoster: { hosts, users: [], ips: [] } });

async function newCases(): Promise<CaseStore> {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-roster-restore-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  return cases;
}

const chatPath = (cases: CaseStore) => join(cases.stateDir(CASE), "watson-chat.json");

describe("a corrupt chat with no readable sidecar refuses every write (review I1)", () => {
  it("update() rejects, writes nothing, and loadRoster still rejects afterwards", async () => {
    const cases = await newCases();
    await writeFile(chatPath(cases), "{bad");
    const store = new WatsonChatStore(cases);
    await expect(store.update(CASE, (c) => ({ ...c, memory: "m" }))).rejects.toBeInstanceOf(
      WatsonRosterUnreadable,
    );
    expect(await readFile(chatPath(cases), "utf8")).toBe("{bad");
    await expect(store.loadRoster(CASE)).rejects.toBeInstanceOf(WatsonRosterUnreadable);
  });

  it("a corrupt sidecar does not count as readable", async () => {
    const cases = await newCases();
    await writeFile(chatPath(cases), "[]");
    await writeFile(join(cases.stateDir(CASE), ROSTER_FILE), "{bad");
    const store = new WatsonChatStore(cases);
    await expect(store.update(CASE, (c) => c)).rejects.toBeInstanceOf(WatsonRosterUnreadable);
  });

  it("with a valid sidecar the write goes ahead, and the sidecar keeps its names", async () => {
    const cases = await newCases();
    await writeFile(chatPath(cases), "{bad");
    await writeFile(join(cases.stateDir(CASE), ROSTER_FILE), JSON.stringify({ hosts: ["ws-fake01"] }));
    const store = new WatsonChatStore(cases);
    await store.update(CASE, (c) => ({ ...c, memory: "m" }));
    expect((await store.loadRoster(CASE))?.hosts).toEqual(["ws-fake01"]);
  });

  it("the round fails with the roster reason before any model call", async () => {
    const p = new Scripted([final()]);
    const h = await toolHarness(p, { anonymize: true });
    await writeFile(chatPath(h.ctx.cases), "{bad");
    await expect(h.run("what ran?")).rejects.toThrow(new WatsonRosterUnreadable().message);
    expect(p.sent).toHaveLength(0);
  });
});

describe("a malformed chat roster counts as corrupt (final review F4, Codex P1#4)", () => {
  const BAD = [
    { maskRoster: { hosts: "fakepc", users: [] } },
    { maskRoster: { hosts: ["fakepc"], users: "fake.user" } },
    { maskRoster: { hosts: ["fakepc", 5], users: [] } },
    { maskRoster: { hosts: [], users: [], ips: "192.0.2.1" } },
    { maskRoster: "fakepc" },
    { maskRoster: ["fakepc"] },
  ];

  it("with no sidecar, loadRoster throws for each malformed shape", async () => {
    for (const bad of BAD) {
      const cases = await newCases();
      await writeFile(chatPath(cases), JSON.stringify({ turns: [], ...bad }));
      await expect(new WatsonChatStore(cases).loadRoster(CASE)).rejects.toBeInstanceOf(
        WatsonRosterUnreadable,
      );
    }
  });

  it("with no sidecar, update() refuses and the malformed field is not erased", async () => {
    const cases = await newCases();
    const text = JSON.stringify({ turns: [], maskRoster: { hosts: "fakepc", users: [] } });
    await writeFile(chatPath(cases), text);
    const store = new WatsonChatStore(cases);
    await expect(store.update(CASE, (c) => ({ ...c, memory: "m" }))).rejects.toBeInstanceOf(
      WatsonRosterUnreadable,
    );
    expect(await readFile(chatPath(cases), "utf8")).toBe(text);
  });

  it("a readable sidecar stands for a malformed chat roster, as for corrupt JSON", async () => {
    const cases = await newCases();
    await writeFile(chatPath(cases), JSON.stringify({ turns: [], maskRoster: { hosts: "fakepc" } }));
    await writeFile(join(cases.stateDir(CASE), ROSTER_FILE), JSON.stringify({ hosts: ["fakepc"] }));
    const store = new WatsonChatStore(cases);
    expect((await store.loadRoster(CASE))?.hosts).toEqual(["fakepc"]);
    await store.update(CASE, (c) => ({ ...c, memory: "m" }));
    expect((await store.loadRoster(CASE))?.hosts).toEqual(["fakepc"]);
  });

  it("a well-formed roster, and a chat with no roster, still read", async () => {
    const cases = await newCases();
    await writeFile(chatPath(cases), JSON.stringify({ turns: [] }));
    expect(await new WatsonChatStore(cases).loadRoster(CASE)).toBeUndefined();
    await writeFile(chatPath(cases), chatJson(["ws-fake01"]));
    expect((await new WatsonChatStore(cases).loadRoster(CASE))?.hosts).toEqual(["ws-fake01"]);
  });
});

describe("the roster is durable before history holds its names (final review F3, Codex P1#3)", () => {
  const turn = (id: string, text: string) => ({
    id,
    at: "2026-11-15T10:00:00Z",
    role: "watson" as const,
    text,
  });

  it("a sidecar write that fails leaves history and the chat unchanged", async () => {
    const cases = await newCases();
    const store = new WatsonChatStore(cases);
    await store.update(CASE, (c) => ({ ...c, turns: [turn("wt-1", "first")] }));
    expect(await store.history.count(CASE)).toBe(1);
    await mkdir(join(cases.stateDir(CASE), ROSTER_FILE)); // reading it now fails with EISDIR
    const before = await readFile(chatPath(cases), "utf8");
    await expect(
      store.update(CASE, (c) => ({
        ...c,
        turns: [...c.turns, turn("wt-2", "fakepc ran it")],
        maskRoster: { hosts: ["fakepc"], users: [], ips: [] },
      })),
    ).rejects.toThrow();
    expect(await store.history.count(CASE)).toBe(1);
    expect((await store.history.text(CASE)).text).not.toContain("fakepc");
    expect(await readFile(chatPath(cases), "utf8")).toBe(before);
  });

  it("the sidecar holds the new names before the history append runs", async () => {
    const cases = await newCases();
    const store = new WatsonChatStore(cases);
    const side = join(cases.stateDir(CASE), ROSTER_FILE);
    let seen = "";
    const append = store.history.append.bind(store.history);
    store.history.append = async (id, turns) => {
      seen = await readFile(side, "utf8").catch(() => "");
      return append(id, turns);
    };
    await store.update(CASE, (c) => ({
      ...c,
      turns: [turn("wt-1", "fakepc ran it")],
      maskRoster: { hosts: ["fakepc"], users: [], ips: [] },
    }));
    expect(seen).toContain("fakepc");
  });
});

describe("a backup restore folds the live chat roster into the sidecar (review Minor 1)", () => {
  const managerFor = (cases: CaseStore) =>
    new BackupManager(cases, resolveBackupConfig({}), { beforeRestore: keepChatRosterDurable });

  it("a legacy case (roster only in the chat, no sidecar) keeps the name across a restore", async () => {
    const cases = await newCases();
    await writeFile(chatPath(cases), JSON.stringify({ turns: [] }));
    const backups = managerFor(cases);
    const info = await backups.createBackup(CASE, "scheduled");
    await writeFile(chatPath(cases), chatJson(["legacy-fake03"]));
    await backups.restoreBackup(CASE, info.filename);
    const store = new WatsonChatStore(cases);
    expect((await store.load(CASE)).maskRoster).toBeUndefined();
    expect((await store.loadRoster(CASE))?.hosts).toContain("legacy-fake03");
  });

  it("a corrupt live chat does not fail the restore: the fold is skipped", async () => {
    const cases = await newCases();
    await writeFile(chatPath(cases), chatJson(["ws-fake01"]));
    const backups = managerFor(cases);
    const info = await backups.createBackup(CASE, "scheduled");
    await writeFile(chatPath(cases), "{bad");
    const { restored } = await backups.restoreBackup(CASE, info.filename);
    expect(restored).toContain("watson-chat.json");
    expect((await new WatsonChatStore(cases).loadRoster(CASE))?.hosts).toEqual(["ws-fake01"]);
  });

  it("the server's BackupManager is built with the roster fold", async () => {
    const src = (
      await readFile(
        fileURLToPath(new URL("../../../src/composition/maintenanceTasks.ts", import.meta.url)),
        "utf8",
      )
    ).replace(/\r\n/g, "\n");
    expect(src).toMatch(
      /new BackupManager\(store, backupConfig, \{ beforeRestore: keepChatRosterDurable \}\)/,
    );
  });
});
