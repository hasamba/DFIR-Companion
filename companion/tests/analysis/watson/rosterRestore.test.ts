import { mkdtemp, readFile, writeFile } from "node:fs/promises";
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
