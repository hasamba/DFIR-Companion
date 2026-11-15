import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { analyzeRestored } from "../../../src/analysis/ai/providerCall.js";
import { converseRestored } from "../../../src/analysis/ai/converseRestored.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { runWatsonRound } from "../../../src/analysis/ai/watson/round.js";
import {
  createRosterReader,
  WatsonRosterUnreadable,
  type RosterFs,
} from "../../../src/analysis/ai/watson/rosterRead.js";
import { rosterEntities, WatsonRosterNames } from "../../../src/analysis/ai/watson/rosterNames.js";
import { emptyState } from "../../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { BackupManager, resolveBackupConfig } from "../../../src/storage/backupManager.js";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { Scripted, call, calls, final, toolHarness } from "./roundToolsFixtures.js";
import { log } from "./superPromoteFixtures.js";

// Task 1 (R1-m2, Codex #1, #2): the roster every masker reads is durable across a backup restore
// (sidecar watson-mask-roster.json), fails closed when a file is unreadable, and is read cheaply
// through one module-level, stat-validated cache shared by every WatsonChatStore instance.

const CASE = "c1";
const ROSTER = (hosts: string[]) => JSON.stringify({ hosts, users: [], ips: [] });

type FakeFs = RosterFs & { reads: number; bump(path: string): void };

function fakeFs(files: Record<string, string>, hold?: Promise<void>): FakeFs {
  const mtimes = new Map<string, number>(Object.keys(files).map((p) => [p, 1]));
  const enoent = () => Object.assign(new Error("ENOENT"), { code: "ENOENT" });
  const fs: FakeFs = {
    reads: 0,
    bump: (p) => mtimes.set(p, (mtimes.get(p) ?? 0) + 1),
    stat: async (p) => {
      if (!(p in files)) throw enoent();
      return { mtimeMs: mtimes.get(p) ?? 1, size: files[p].length, ino: 7 };
    },
    readFile: async (p) => {
      fs.reads++;
      if (hold) await hold;
      if (!(p in files)) throw enoent();
      return files[p];
    },
  };
  return fs;
}

function throwingFs(code: string): RosterFs {
  const fail = async (): Promise<never> => {
    throw Object.assign(new Error(code), { code });
  };
  return { stat: fail, readFile: fail };
}

async function newCases(): Promise<CaseStore> {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-roster-read-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  return cases;
}

describe("the roster reader: a stat-validated cache", () => {
  it("reads the roster once while the file is unchanged", async () => {
    const fs = fakeFs({
      "/c/watson-chat.json": JSON.stringify({
        turns: "junk",
        maskRoster: { hosts: ["ws-fake01"], users: [], ips: [] },
      }),
    });
    const r = createRosterReader(fs);
    expect((await r.read("/c"))?.hosts).toEqual(["ws-fake01"]);
    await r.read("/c");
    expect(fs.reads).toBe(1);
  });

  it("re-reads when stat changes, and after forget() even with an equal stat", async () => {
    const fs = fakeFs({ "/c/watson-chat.json": JSON.stringify({ maskRoster: { hosts: ["ws-fake01"] } }) });
    const r = createRosterReader(fs);
    await r.read("/c");
    fs.bump("/c/watson-chat.json");
    await r.read("/c");
    expect(fs.reads).toBe(2);
    r.forget("/c");
    await r.read("/c");
    expect(fs.reads).toBe(3);
  });

  it("evicts the oldest entry past the cap", async () => {
    const chat = JSON.stringify({ maskRoster: { hosts: ["ws-fake01"] } });
    const fs = fakeFs({ "/a/watson-chat.json": chat, "/b/watson-chat.json": chat });
    const r = createRosterReader(fs, 1);
    await r.read("/a");
    await r.read("/b");
    await r.read("/a");
    expect(fs.reads).toBe(3);
  });

  it("missing files give no roster; EACCES throws", async () => {
    await expect(createRosterReader(fakeFs({})).read("/s")).resolves.toBeUndefined();
    await expect(createRosterReader(throwingFs("EACCES")).read("/s")).rejects.toThrow("EACCES");
  });

  it("a forget() during an in-flight read does not publish the stale result", async () => {
    let release!: () => void;
    const hold = new Promise<void>((res) => (release = res));
    const fs = fakeFs({ "/s/watson-mask-roster.json": ROSTER(["ws-fake01"]) }, hold);
    const r = createRosterReader(fs);
    const inFlight = r.read("/s");
    await new Promise((res) => setImmediate(res));
    r.forget("/s");
    release();
    await inFlight;
    await r.read("/s");
    expect(fs.reads).toBe(2);
  });
});

describe("the roster reader: fail closed", () => {
  it("a corrupt sidecar, or a corrupt chat with no sidecar, throws WatsonRosterUnreadable and is not cached", async () => {
    const side = "/s/watson-mask-roster.json";
    await expect(createRosterReader(fakeFs({ [side]: "{not json" })).read("/s")).rejects.toBeInstanceOf(
      WatsonRosterUnreadable,
    );
    await expect(
      createRosterReader(fakeFs({ "/s/watson-chat.json": "[]" })).read("/s"),
    ).rejects.toBeInstanceOf(WatsonRosterUnreadable);
    await expect(
      createRosterReader(fakeFs({ [side]: '{"hosts":"ws-fake01"}' })).read("/s"),
    ).rejects.toBeInstanceOf(WatsonRosterUnreadable);
    const fs = fakeFs({ [side]: "{not json" });
    const r = createRosterReader(fs);
    await expect(r.read("/s")).rejects.toBeInstanceOf(WatsonRosterUnreadable);
    await expect(r.read("/s")).rejects.toBeInstanceOf(WatsonRosterUnreadable);
    expect(fs.reads).toBe(2);
  });

  it("a corrupt chat with a valid sidecar reads the sidecar", async () => {
    const fs = fakeFs({
      "/s/watson-chat.json": "{bad",
      "/s/watson-mask-roster.json": ROSTER(["ws-fake01"]),
    });
    expect((await createRosterReader(fs).read("/s"))?.hosts).toEqual(["ws-fake01"]);
  });

  it("an unreadable roster holds the AI call: the masker rejects and the provider is never called", async () => {
    const cases = await newCases();
    const anonStore = new AnonControlStore(cases);
    await anonStore.save(CASE, { ...(await anonStore.load(CASE)), enabled: true });
    await writeFile(join(cases.stateDir(CASE), "watson-mask-roster.json"), "{bad");
    const sent: AnalyzeRequest[] = [];
    const provider: AIProvider = {
      name: "capture",
      model: "capture-model",
      analyze: async (req): Promise<AnalyzeResult> => (sent.push(req), { rawText: "{}" }),
    };
    const gate = {
      log,
      opts: { anonStore, rawNamesStore: new WatsonRosterNames(new WatsonChatStore(cases)) },
    };
    const req = { systemPrompt: "s", userPrompt: "u", images: [] };
    await expect(analyzeRestored(gate, CASE, emptyState(CASE), provider, req)).rejects.toBeInstanceOf(
      WatsonRosterUnreadable,
    );
    expect(sent).toHaveLength(0);
  });

  it("a save() never overwrites a corrupt sidecar, and the chat is still saved", async () => {
    const cases = await newCases();
    const side = join(cases.stateDir(CASE), "watson-mask-roster.json");
    await writeFile(side, "{bad");
    const store = new WatsonChatStore(cases);
    await store.update(CASE, (c) => ({ ...c, maskRoster: { hosts: ["ws-fake01"], users: [], ips: [] } }));
    expect((await store.load(CASE)).maskRoster?.hosts).toEqual(["ws-fake01"]);
    await expect(store.loadRoster(CASE)).rejects.toBeInstanceOf(WatsonRosterUnreadable);
  });
});

describe("the durable roster sidecar and the shared read", () => {
  it("a backup restore keeps names learned after the backup (Codex #1)", async () => {
    const p = new Scripted([calls(call("history_search", { terms: ["fakepc"] })), final()]);
    const h = await toolHarness(p, { anonymize: true });
    const backups = new BackupManager(h.ctx.cases, resolveBackupConfig({}));
    await h.ctx.chatStore.update(CASE, (c) => ({ ...c, memory: "before the backup" }));
    const info = await backups.createBackup(CASE, "scheduled");
    await h.ctx.chatStore.update(CASE, (c) => ({
      ...c,
      maskRoster: { hosts: ["fakepc"], users: [], ips: [] },
      turns: [...c.turns, { id: "w1", at: "2026-01-01T00:00:00Z", role: "watson", text: "fakepc ran it" }],
    }));
    await backups.restoreBackup(CASE, info.filename);
    expect((await h.ctx.chatStore.load(CASE)).maskRoster).toBeUndefined();
    expect((await h.ctx.chatStore.loadRoster(CASE))?.hosts).toContain("fakepc");

    const anonStore = h.ctx.opts.anonStore!;
    const rawNamesStore = new WatsonRosterNames(h.ctx.chatStore);
    const gate = { log, opts: { anonStore, aiCostStore: h.ctx.costStore, rawNamesStore } };
    const ctx = {
      ...h.ctx,
      converseRestored: ((caseId, state, prov, req, session, label) =>
        converseRestored(gate, caseId, state, prov, req, session, label)) as typeof h.ctx.converseRestored,
    };
    await runWatsonRound(ctx, CASE, { text: "what ran?", source: "dashboard" });
    const wire = JSON.stringify([p.sent, p.analyzed]);
    expect(wire).toContain("ran it");
    expect(wire).not.toMatch(/fakepc/i);
  });

  it("a write through another WatsonChatStore instance is seen by the first (shared cache)", async () => {
    const cases = await newCases();
    const a = new WatsonChatStore(cases);
    const b = new WatsonChatStore(cases);
    expect(await a.loadRoster(CASE)).toBeUndefined();
    await b.update(CASE, (c) => ({
      ...c,
      maskRoster: { hosts: ["srv-fake-02"], users: ["fake.user"], ips: [] },
    }));
    expect(await a.loadRoster(CASE)).toMatchObject({ hosts: ["srv-fake-02"], users: ["fake.user"] });
  });

  it("WatsonRosterNames gives the same entities as rosterEntities(load())", async () => {
    const cases = await newCases();
    const store = new WatsonChatStore(cases);
    await store.update(CASE, (c) => ({
      ...c,
      maskRoster: { hosts: ["ws-fake01.example.com"], users: ["fake.user"], ips: [] },
    }));
    const names = await new WatsonRosterNames(store).load(CASE);
    expect(names).toEqual(rosterEntities(await store.load(CASE)));
    expect(names.hosts).toContain("ws-fake01");
  });
});
