import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp, setServerLogger, buildRuntimePipeline } from "../../src/server.js";
import { BackupManager, type BackupConfig } from "../../src/storage/backupManager.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { ProviderError, type AIProvider } from "../../src/providers/provider.js";

// One Chainsaw/Sigma detection — enough for resolveImportKind to classify the file as "chainsaw"
// (a deterministic importer, no AI call) so an import-file request reaches the evidence copy.
const CHAINSAW_HUNT = [
  {
    group: "Sigma",
    kind: "individual",
    document: {
      kind: "evtx",
      path: "Sysmon.evtx",
      data: {
        Event: {
          System: {
            Provider: { "#attributes": { Name: "Microsoft-Windows-Sysmon" } },
            EventID: 1,
            Channel: "Microsoft-Windows-Sysmon/Operational",
            Computer: "WIN-DC01.corp.local",
            TimeCreated: { "#attributes": { SystemTime: "2023-01-02T10:00:00.000Z" } },
          },
          EventData: {
            UtcTime: "2023-01-02 10:00:00.000",
            Image: "C:\\Windows\\System32\\cmd.exe",
            CommandLine: "cmd.exe /c whoami",
          },
        },
      },
    },
    rule: { name: "Suspicious Command", level: "high", tags: ["attack.execution"] },
    timestamp: "2023-01-02T10:00:00.000Z",
  },
];

let store: CaseStore;
let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-diag-"));
  store = new CaseStore(root);
  setServerLogger(createConsoleLogger("error"));
});

describe("GET /diagnostics", () => {
  it("returns the report shape and a shareable text blob", async () => {
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics");
    expect(res.status).toBe(200);
    const r = res.body.report;
    expect(r).toBeTruthy();
    expect(r.disk).toHaveProperty("freeBytes");
    expect(r.disk).toHaveProperty("level");
    expect(r.cases).toEqual({ count: 0, open: 0, closed: 0, archived: 0 });
    expect(r.queue).toHaveProperty("bufferedCaptures", 0);
    expect(r.queue).toHaveProperty("synthInFlight", 0);
    expect(r.ai).toHaveProperty("configured");
    expect(Array.isArray(r.importers.recentFailures)).toBe(true);
    expect(typeof res.body.text).toBe("string");
    expect(res.body.text).toContain("DFIR Companion — Diagnostics");
  });

  it("counts open vs closed cases", async () => {
    await store.createCase({ caseId: "open-1", name: "A", investigator: "x", aiProvider: null });
    await store.createCase({ caseId: "closed-1", name: "B", investigator: "x", aiProvider: null });
    await store.updateCaseMeta("closed-1", { status: "closed" });
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics");
    expect(res.body.report.cases).toEqual({ count: 2, open: 1, closed: 1, archived: 0 });
  });

  it("counts archived cases separately, not as open or closed", async () => {
    await store.createCase({ caseId: "open-1", name: "A", investigator: "x", aiProvider: null });
    await store.createCase({ caseId: "closed-1", name: "B", investigator: "x", aiProvider: null });
    await store.updateCaseMeta("closed-1", { status: "closed" });
    await store.createCase({ caseId: "archived-1", name: "C", investigator: "x", aiProvider: null });
    await store.archiveCaseFolder("archived-1");
    await store.updateCaseMeta("archived-1", { status: "archived" });
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics");
    expect(res.body.report.cases).toEqual({ count: 3, open: 1, closed: 1, archived: 1 });
  });

  it("NEVER leaks an API key into the diagnostics payload", async () => {
    process.env.DFIR_AI_PROVIDER = "openai";
    process.env.DFIR_AI_MODEL = "gpt-4o";
    process.env.DFIR_AI_KEY = "sk-must-not-leak-12345";
    try {
      const app = createApp(store, {});
      const res = await request(app).get("/diagnostics");
      expect(JSON.stringify(res.body)).not.toContain("sk-must-not-leak-12345");
      expect(res.body.report.ai.provider).toBe("openai");
      expect(res.body.report.ai.configured).toBe(true);
    } finally {
      delete process.env.DFIR_AI_PROVIDER;
      delete process.env.DFIR_AI_MODEL;
      delete process.env.DFIR_AI_KEY;
    }
  });

  // #250: /diagnostics is unauthenticated, so the absolute cases-root path must never reach the
  // client — it is free reconnaissance for a file-targeting attack (symlink, env injection).
  // Asserted against the whole payload, not a named field, so reintroducing the path under ANY
  // key (or interpolated into the text blob) fails here.
  it("NEVER leaks the absolute cases-root path into the diagnostics payload", async () => {
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics");
    expect(res.status).toBe(200);
    expect(res.body.report).not.toHaveProperty("casesRoot");
    expect(JSON.stringify(res.body)).not.toContain(root);
    expect(res.body.text).not.toContain(root);
    expect(res.body.text).not.toContain("cases root");
  });
});

// #267 fixed "the retain number shown isn't the number enforced"; the byte budget must not
// reintroduce the same gap, so /diagnostics reports the budget and who is breaching it.
describe("GET /diagnostics backup byte budget (#295)", () => {
  const config = (maxBytes: number): BackupConfig => ({
    retain: 24,
    preSynthRetain: 10,
    intervalMs: 0,
    maxBytes,
  });

  it("reports the byte budget and counts the cases over it", async () => {
    await store.createCase({ caseId: "over-budget", name: "A", investigator: "x", aiProvider: null });
    // A 1-byte budget no real bundle can fit, so the case is over the moment it has a backup —
    // and the backup survives anyway, because the newest one is never evicted.
    const backupManager = new BackupManager(store, config(1));
    await backupManager.createBackup("over-budget", "scheduled", "2026-06-28T01:00:00.000Z");
    const app = createApp(store, { backupManager });

    const res = await request(app).get("/diagnostics");

    expect(res.body.report.backups.maxBytes).toBe(1);
    expect(res.body.report.backups.overBudgetCases).toBe(1);
  });

  it("counts no case as over budget when the byte cap is off", async () => {
    await store.createCase({ caseId: "uncapped", name: "A", investigator: "x", aiProvider: null });
    const backupManager = new BackupManager(store, config(0));
    await backupManager.createBackup("uncapped", "scheduled", "2026-06-28T01:00:00.000Z");
    const app = createApp(store, { backupManager });

    const res = await request(app).get("/diagnostics");

    expect(res.body.report.backups.maxBytes).toBe(0);
    expect(res.body.report.backups.overBudgetCases).toBe(0);
  });
});

describe("GET /diagnostics/sizes", () => {
  it("totals bytes and lists per-case sizes after a file is written", async () => {
    await store.createCase({ caseId: "case-1", name: "C", investigator: "x", aiProvider: null });
    await store.saveImport("case-1", "0001_evidence.json", "x".repeat(1234));
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics/sizes");
    expect(res.status).toBe(200);
    expect(res.body.totalBytes).toBeGreaterThanOrEqual(1234);
    const c = res.body.cases.find((x: { caseId: string }) => x.caseId === "case-1");
    expect(c).toBeTruthy();
    expect(c.bytes).toBeGreaterThanOrEqual(1234);
    expect(res.body.largestFiles.length).toBeGreaterThan(0);
    expect(res.body.truncated).toBe(false);
    expect(res.body.lockedCases).toBe(0);
  });

  // #250: this route spans every case, so it cannot sit behind the /cases/:id lock gate. It must
  // enforce the same rule itself — evidence FILENAMES are case content, not metadata.
  it("withholds a locked case's filenames but still counts its bytes", async () => {
    await store.createCase({ caseId: "open-c", name: "O", investigator: "x", aiProvider: null });
    await store.saveImport("open-c", "0001_open_evidence.json", "x".repeat(2000));
    await store.createCase({ caseId: "locked-c", name: "L", investigator: "x", aiProvider: null });
    await store.saveImport("locked-c", "0001_victim_acme_breach.json", "y".repeat(3000));
    const app = createApp(store, {});
    await request(app).post("/cases/locked-c/password").send({ newPassword: "correct horse" });

    // Fresh, cookie-less client: the case is locked for it.
    const res = await request(app).get("/diagnostics/sizes?top=50");
    expect(res.status).toBe(200);
    expect(res.body.lockedCases).toBe(1);
    // Bytes and the case id still show — both are aggregates, and GET /cases already lists ids.
    const locked = res.body.cases.find((x: { caseId: string }) => x.caseId === "locked-c");
    expect(locked.bytes).toBeGreaterThanOrEqual(3000);
    // The filename must not appear anywhere in the payload.
    expect(JSON.stringify(res.body)).not.toContain("victim_acme_breach");
    const paths = res.body.largestFiles.map((f: { caseId: string }) => f.caseId);
    expect(paths).toContain("open-c");
    expect(paths).not.toContain("locked-c");
  });

  it("lists a locked case's filenames again once the caller unlocks it", async () => {
    await store.createCase({ caseId: "locked-c", name: "L", investigator: "x", aiProvider: null });
    await store.saveImport("locked-c", "0001_victim_acme_breach.json", "y".repeat(3000));
    const app = createApp(store, {});
    const agent = request.agent(app);
    await agent.post("/cases/locked-c/password").send({ newPassword: "correct horse" });
    await agent.post("/cases/locked-c/unlock").send({ password: "correct horse" });

    const res = await agent.get("/diagnostics/sizes?top=50");
    expect(res.status).toBe(200);
    expect(res.body.lockedCases).toBe(0);
    expect(JSON.stringify(res.body)).toContain("victim_acme_breach");
  });
});

// #250: ~60 route catch blocks return err.message verbatim, and Node's fs errors embed the absolute
// path — so removing casesRoot from /diagnostics buys nothing if the next failed read prints it back.
// Covered once, centrally, by the res.json wrapper in createApp.
describe("absolute paths in error responses", () => {
  it("redacts the absolute path out of a failed server-side import-file read", async () => {
    await store.createCase({ caseId: "c1", name: "C", investigator: "x", aiProvider: null });
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore });

    // A path that does not exist, under the cases root itself — ENOENT will quote it in full.
    const missing = join(root, "c1", "imports", "definitely_not_here.json");
    const res = await request(app).post("/cases/c1/import-file").send({ path: missing });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/cannot read file/i);
    // The reason for the failure survives; the filesystem layout does not.
    expect(res.body.error).toContain("ENOENT");
    expect(res.body.error).not.toContain(root);
    expect(res.body.error).toContain("<path>");
  });

  // The other half of the leak: /diagnostics replays the import-failure ring, so a path that reached
  // the ring is served to every later caller even though the failing request is long gone.
  it("keeps the absolute path out of the diagnostics failure ring, JSON and text alike", async () => {
    await store.createCase({ caseId: "c1", name: "C", investigator: "x", aiProvider: null });
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore });

    // Provoke a real EEXIST out of the evidence copy: nextImportSeq counts audit-log lines, not
    // files, so pre-creating the destination leaves the sequence at 1 and the COPYFILE_EXCL copy
    // collides. Its message quotes BOTH absolute paths — source and the one under the cases root.
    const src = join(await mkdtemp(join(tmpdir(), "dfir-diag-src-")), "hunt.json");
    await writeFile(src, JSON.stringify(CHAINSAW_HUNT), "utf8");
    await store.saveImport("c1", "0001_hunt.json", "already here");

    const failed = await request(app).post("/cases/c1/import-file").send({ path: src });
    expect(failed.status).toBe(500);
    expect(failed.body.error).not.toContain(root);

    // Now the ring: the report AND the copy-to-clipboard blob must both be clean.
    const diag = await request(app).get("/diagnostics");
    expect(diag.status).toBe(200);
    const failures = diag.body.report.importers.recentFailures;
    expect(failures.length).toBeGreaterThan(0);
    expect(failures[0].error).toContain("EEXIST");
    expect(failures[0].error).toContain("<path>");
    expect(JSON.stringify(diag.body.report)).not.toContain(root);
    expect(diag.body.text).not.toContain(root);
  });
});

describe("POST /diagnostics/ai-test", () => {
  it("returns 501 when no provider builder is configured", async () => {
    const app = createApp(store, {});
    const res = await request(app).post("/diagnostics/ai-test");
    expect(res.status).toBe(501);
    expect(res.body.ok).toBe(false);
  });

  it("returns ok with latency when the provider responds", async () => {
    let seen: { systemPrompt: string; userPrompt: string } | null = null;
    const fake: AIProvider = {
      name: "fake",
      model: "mock-model",
      analyze: async (req) => {
        seen = { systemPrompt: req.systemPrompt, userPrompt: req.userPrompt };
        return { rawText: '{"ok":true}' };
      },
    };
    const app = createApp(store, { aiTestProvider: () => fake });
    const res = await request(app).post("/diagnostics/ai-test");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.provider).toBe("fake");
    expect(res.body.reply).toBe('{"ok":true}');
    expect(typeof res.body.latencyMs).toBe("number");
    // Regression guard: the OpenAI/OpenRouter JSON mode (response_format: json_object) 400s unless the
    // messages contain the word "json", so the probe MUST mention it. (See server.ts ai-test route.)
    expect(seen).not.toBeNull();
    const probe = `${seen!.systemPrompt} ${seen!.userPrompt}`.toLowerCase();
    expect(probe).toContain("json");
  });

  it("maps a ProviderError to an actionable kind without 500ing", async () => {
    const fake: AIProvider = {
      name: "fake",
      model: "mock-model",
      analyze: async () => {
        throw new ProviderError("bad key", "auth");
      },
    };
    const app = createApp(store, { aiTestProvider: () => fake });
    const res = await request(app).post("/diagnostics/ai-test");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
    expect(res.body.kind).toBe("auth");
    expect(res.body.error).toContain("bad key");
  });
});
