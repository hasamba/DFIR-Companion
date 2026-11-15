// R6: a restore rewinds the chat, never the record. watson-history.jsonl stays append-only and
// hunt-fingerprints.json is never rewound, so a hunt that already ran cannot look un-run.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { BackupManager, resolveBackupConfig } from "../../src/storage/backupManager.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { HuntFingerprintStore } from "../../src/analysis/ai/watson/velo/huntFingerprintStore.js";
import type { WatsonChat, WatsonTurn } from "../../src/analysis/ai/watson/types.js";

let root: string;
let cases: CaseStore;
let backups: BackupManager;
let chat: WatsonChatStore;

const turn = (id: string): WatsonTurn => ({
  id,
  at: "2026-11-14T10:00:00.000Z",
  role: "analyst",
  text: `text ${id}`,
});
const addTurn =
  (id: string) =>
  (c: WatsonChat): WatsonChat => ({ ...c, turns: [...c.turns, turn(id)] });
const historyIds = async (): Promise<string[]> =>
  (await readFile(join(cases.stateDir("c1"), "watson-history.jsonl"), "utf8"))
    .split("\n")
    .filter(Boolean)
    .map((l) => (JSON.parse(l) as { id: string }).id);

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-watson-scope-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  backups = new BackupManager(cases, resolveBackupConfig({}));
  chat = new WatsonChatStore(cases);
});
afterEach(() => rm(root, { recursive: true, force: true }));

async function backupThenAddLaterTurn(): Promise<string> {
  await chat.update("c1", addTurn("t1"));
  const info = await backups.createBackup("c1", "scheduled");
  await chat.update("c1", addTurn("t2"));
  return info.filename;
}

describe("restore scope for Watson's history and the hunt fingerprints (R6)", () => {
  it("rewinds watson-chat.json but leaves watson-history.jsonl intact", async () => {
    const filename = await backupThenAddLaterTurn();
    const { restored } = await backups.restoreBackup("c1", filename);
    expect(restored).toContain("watson-chat.json");
    expect(restored).not.toContain("watson-history.jsonl");
    expect((await chat.load("c1")).turns.map((t) => t.id)).toEqual(["t1"]);
    expect(await historyIds()).toEqual(["t1", "t2"]);
  });

  it("appends the next round to the history without duplicating or losing turns", async () => {
    const filename = await backupThenAddLaterTurn();
    await backups.restoreBackup("c1", filename);
    await chat.update("c1", addTurn("t3"));
    expect(await historyIds()).toEqual(["t1", "t2", "t3"]);
    expect(await chat.history.count("c1")).toBe(3);
  });

  it("leaves hunt-fingerprints.json intact: a hunt run after the backup still counts as run", async () => {
    const store = new HuntFingerprintStore(cases);
    const info = await backups.createBackup("c1", "scheduled");
    expect((await store.reserve("c1", "fp-late")).ok).toBe(true);
    const { restored } = await backups.restoreBackup("c1", info.filename);
    expect(restored).not.toContain("hunt-fingerprints.json");
    expect([...(await store.load("c1"))]).toEqual(["fp-late"]);
    expect((await store.reserve("c1", "fp-late")).ok).toBe(false);
  });
});
