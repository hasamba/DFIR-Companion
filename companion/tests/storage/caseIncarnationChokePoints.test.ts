// #1855: one test per guarded choke point and capture point that caseIncarnation.test.ts does not
// already drive — each proves a deleted case's late work creates nothing and a live case still works.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, readFile, writeFile, open } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  capturedGeneration,
  isCaseWriteRefused,
  runInCaseScope,
  setCaseWriteRefusalReporter,
} from "../../src/storage/caseIncarnation.js";
import { BackupManager } from "../../src/storage/backupManager.js";
import { resolveBackupConfig } from "../../src/storage/backupManager.js";
import { ReportGeneration } from "../../src/reports/reportGeneration.js";
import { writeFailedAnswer } from "../../src/analysis/ai/failedAnswerLog.js";
import { appendDropLog } from "../../src/analysis/dropLog.js";
import { copyHandleExclusive } from "../../src/routes/importFileSource.js";
import { archiveCase } from "../../src/analysis/caseArchive.js";
import { importZipArchiveCase } from "../../src/analysis/caseZipImport.js";
import { mountCaseWriteExistsGate } from "../../src/composition/caseWriteExistsGate.js";
import { atomicWrite } from "../../src/storage/atomicWrite.js";
import { sanitizeCaseMeta } from "../../src/analysis/casePassword.js";

let root: string;
let store: CaseStore;

const create = (caseId = "c1") =>
  store.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
const generation = async (caseId = "c1") =>
  (JSON.parse(await readFile(store.caseMetaPath(caseId), "utf8")) as { generation?: string }).generation;

async function deleted(caseId = "c1"): Promise<void> {
  await store.updateCaseMeta(caseId, { status: "closed" });
  await store.deleteCaseFolder(caseId);
}

async function expectRefusedAndNoFolder(write: () => Promise<unknown>, caseId = "c1"): Promise<void> {
  expect(isCaseWriteRefused(await write().catch((e: unknown) => e))).toBe(true);
  expect(existsSync(join(root, caseId))).toBe(false);
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-incarnation-cp-"));
  store = new CaseStore(root);
  setCaseWriteRefusalReporter(null);
});
afterEach(() => setCaseWriteRefusalReporter(null));

describe("guarded writers refuse a deleted case and recreate nothing (#1855)", () => {
  it("backup create", async () => {
    await create();
    const backups = new BackupManager(store, resolveBackupConfig({}));
    await deleted();
    await expectRefusedAndNoFolder(() => backups.createBackup("c1", "scheduled"));
  });

  it("report staging", async () => {
    await create();
    const target = join(store.reportsDir("c1"), "report.md");
    await deleted();
    await expectRefusedAndNoFolder(() => new ReportGeneration().stage(target, "# late"));
  });

  it("failed-answer log", async () => {
    await create();
    const dir = store.caseDir("c1");
    await deleted();
    const answer = { kind: "synthesis", attempt: 1, error: "e", text: "t" };
    await expectRefusedAndNoFolder(() => writeFailedAnswer(dir, answer));
  });

  it("drop log and drop folders", async () => {
    await create();
    const dropDir = join(store.caseDir("c1"), "drop");
    await deleted();
    await expectRefusedAndNoFolder(() => appendDropLog(dropDir, ["line"]));
  });

  it("server-path import copy", async () => {
    await create();
    const src = join(root, "..", `src-${Date.now()}.bin`);
    await writeFile(src, "x");
    const dest = join(store.importsDir("c1"), "copy.bin");
    await deleted();
    const handle = await open(src, "r");
    try {
      await expectRefusedAndNoFolder(() => copyHandleExclusive(handle, dest));
    } finally {
      await handle.close();
    }
  });

  it("analysis-run record: the whole marker-to-removal append is one admitted write", async () => {
    const { AnalysisRunStore } = await import("../../src/analysis/analysisRunStore.js");
    await create();
    const runs = new AnalysisRunStore(store, { appVersion: "0.0.0" });
    const run = (id: string) => ({
      id,
      kind: "deterministic" as const,
      startedAt: "2026-07-31T10:00:00.000Z",
      finishedAt: "2026-07-31T10:00:01.000Z",
      versions: {},
      input: { artifacts: [], eventIds: [], entityIds: [] },
      output: { entityIds: [], hashes: [], claims: [] },
    });
    await runs.record("c1", run("run-1"));
    await deleted();
    await expectRefusedAndNoFolder(() => runs.record("c1", run("run-2")));
  });

  it("the same writers still work on a live case", async () => {
    await create();
    await new BackupManager(store, resolveBackupConfig({})).createBackup("c1", "scheduled");
    const gen = new ReportGeneration();
    await gen.stage(join(store.reportsDir("c1"), "report.md"), "# ok");
    await gen.publish();
    await appendDropLog(join(store.caseDir("c1"), "drop"), ["line"]).catch(() => undefined);
    expect(existsSync(join(store.reportsDir("c1"), "report.md"))).toBe(true);
  });
});

describe("new incarnations get a fresh generation (#1855)", () => {
  it("a whole-case import replaces the archive's generation", async () => {
    await create("INC-1");
    const exported = await generation("INC-1");
    const { archivePath } = await archiveCase(store.casesRoot, "INC-1", {}, "n", store.caseDir("INC-1"));
    await importZipArchiveCase(store, await readFile(archivePath), { targetCaseId: "INC-2" });
    const imported = await generation("INC-2");
    expect(imported).toMatch(/^[0-9a-f-]{36}$/);
    expect(imported).not.toBe(exported);
  });

  it("a seed writes its generation in its first case.json, and a reseed gets a new one", async () => {
    const seen: (string | undefined)[] = [];
    const seed = () =>
      store.withSeedSlot("demo", async (_isNew, gen) => {
        await mkdir(join(root, "demo"), { recursive: true }); // the seeder writes its own files
        await writeFile(join(root, "demo", "case.json"), JSON.stringify({ caseId: "demo", generation: gen }));
        seen.push(await generation("demo"));
      });
    await seed();
    expect(seen[0]).toMatch(/^[0-9a-f-]{36}$/);
    expect(await generation("demo")).toBe(seen[0]);
    await seed();
    expect(seen[1]).not.toBe(seen[0]);
  });

  it("a seeder that ignores the generation still ends with one", async () => {
    await store.withSeedSlot("demo2", async () => {
      await mkdir(join(root, "demo2"), { recursive: true });
      await writeFile(join(root, "demo2", "case.json"), JSON.stringify({ caseId: "demo2" }));
    });
    expect(await generation("demo2")).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("the demo seeder writes the generation it is given", async () => {
    const { seedDemoCase } = await import("../../src/analysis/seedDemoCase.js");
    await seedDemoCase(root, { caseId: "demo3", generation: "gen-from-slot" });
    expect(await generation("demo3")).toBe("gen-from-slot");
  });

  it("API responses do not carry the generation", async () => {
    const meta = await create();
    expect(meta.generation).toBeDefined();
    expect("generation" in sanitizeCaseMeta(meta)).toBe(false);
  });
});

describe("the /cases/:id gate puts the request in the case's scope (#1855)", () => {
  it("captures the generation before its await, and a late write after delete + re-create is refused", async () => {
    await create();
    const gen = await generation();
    const app = express();
    mountCaseWriteExistsGate(app, store);
    let seen: string | null = null;
    let late: unknown = null;
    app.post("/cases/:id/work", async (_req, res) => {
      seen = capturedGeneration(root, "c1");
      await deleted();
      await create();
      late = await atomicWrite(join(store.stateDir("c1"), "late.json"), "{}").catch((e: unknown) => e);
      res.json({ ok: true });
    });
    const server = app.listen(0);
    try {
      const port = (server.address() as { port: number }).port;
      const res = await fetch(`http://127.0.0.1:${port}/cases/c1/work`, { method: "POST" });
      expect(res.status).toBe(200);
    } finally {
      server.close();
    }
    expect(seen).toBe(gen);
    expect(isCaseWriteRefused(late)).toBe(true);
    expect(existsSync(join(store.stateDir("c1"), "late.json"))).toBe(false);
  });

  it("a sweep that passes the listed generation cannot adopt a newer case", async () => {
    await create();
    const [listed] = await store.listCases();
    await deleted();
    await create();
    const err = await runInCaseScope(
      root,
      "c1",
      () => atomicWrite(join(store.stateDir("c1"), "x.json"), "{}"),
      listed.generation,
    ).catch((e: unknown) => e);
    expect(isCaseWriteRefused(err)).toBe(true);
  });
});

describe("a tail kicked before a delete stays old work (#1855)", () => {
  it("resynthesizeInBackground's writes are refused after delete + re-create", async () => {
    const { createCaptureAnalysis } = await import("../../src/composition/captureAnalysis.js");
    await create();
    let release: () => void = () => undefined;
    let outcome: unknown = "not run";
    const pipeline = {
      hasSynthesisProvider: () => true,
      synthesize: async (caseId: string) => {
        await new Promise<void>((ok) => (release = ok));
        outcome = await atomicWrite(join(store.stateDir(caseId), "synth.json"), "{}").catch(
          (e: unknown) => e,
        );
        return {};
      },
    };
    const analysis = createCaptureAnalysis({
      store,
      options: { pipeline } as never,
      hasAiProvider: () => true,
      getControl: async () => ({ enabled: true }) as never,
      setControl: async () => ({ enabled: true }) as never,
      recordAiError: () => {},
      autoEnrichIfEnabled: () => {},
      dispatchNotify: () => {},
    });
    analysis.resynthesizeInBackground("c1");
    await new Promise((ok) => setTimeout(ok, 20));
    await deleted();
    await create();
    release();
    await new Promise((ok) => setTimeout(ok, 20));
    expect(isCaseWriteRefused(outcome)).toBe(true);
    expect(existsSync(join(store.stateDir("c1"), "synth.json"))).toBe(false);
  });
});
