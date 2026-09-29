// #1866 (item 1): work that started outside a /cases/:id request — a queued OCR job, a case log
// line, a job-ledger row — belongs to the case incarnation it was started for. After a delete, and
// after a same-id re-create, old work neither recreates the deleted folder nor writes into the new
// case, and the new case's own work still runs.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readFile, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createOcrIndexer } from "../../src/composition/ocrIndexer.js";
import { LoggerImpl } from "../../src/logging/logger.js";
import { JobLedgerStore } from "../../src/analysis/jobLedgerStore.js";
import { captureCaseScope, isCaseWriteRefused } from "../../src/storage/caseIncarnation.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { SlashCommandChannelStore } from "../../src/analysis/slashCommandStore.js";
import { clearStateOutlivingCase } from "../../src/routes/caseIdentity.js";
import type { RouteContext } from "../../src/routes/context.js";
import type { CaptureMetadata } from "../../src/types.js";
import type { Job } from "../../src/analysis/jobRegistry.js";
import { pollFor } from "../helpers/poll.js";

const ID = "t1866";
let root: string;
let store: CaseStore;

const create = (name = "n") => store.createCase({ caseId: ID, name, investigator: "i", aiProvider: null });
async function deleteCase(): Promise<void> {
  await store.updateCaseMeta(ID, { status: "closed" });
  await store.deleteCaseFolder(ID);
}
async function screenshot(file: string): Promise<CaptureMetadata> {
  await mkdir(store.screenshotsDir(ID), { recursive: true });
  await writeFile(join(store.screenshotsDir(ID), file), "png");
  return { caseId: ID, screenshotFile: file, sequenceNumber: 1, isDuplicate: false } as CaptureMetadata;
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-1866-tokenless-"));
  store = new CaseStore(root);
  vi.stubEnv("DFIR_OCR_SEARCH", "on"); // the suite turns OCR search off by default
});
afterEach(() => vi.unstubAllEnvs());

describe("tokenless per-case work across delete + same-id re-create (#1866)", () => {
  it("a queued OCR job of the deleted case never indexes into the new case; the new case's job still runs", async () => {
    const gates: (() => void)[] = [];
    const recognized: string[] = [];
    const ocr = createOcrIndexer({
      store,
      ocrRunner: {
        recognize: (bytes: Buffer) =>
          new Promise((resolve) => {
            recognized.push(bytes.toString());
            gates.push(() => resolve([{ text: "word", confidence: 99 }] as never));
          }),
      },
    });
    await create();
    // Two workers busy on the old case, a third old item waits in the queue.
    for (const f of ["a.png", "b.png", "c.png"]) ocr.indexCaptureText(await screenshot(f));
    await pollFor("two OCR workers busy", async () => (gates.length === 2 ? true : undefined));
    await deleteCase();
    await create("new");
    await screenshot("c.png"); // the new case happens to hold a file with the old queued name
    ocr.indexCaptureText(await screenshot("n.png")); // the new case's own capture
    // Release every OCR call as it arrives: the old c.png item starts from an old job's tail, and
    // the new n.png item from the tail after it.
    let released = 0;
    await pollFor("all four OCR calls", async () => {
      while (released < gates.length) gates[released++]();
      return recognized.length === 4 ? true : undefined;
    });
    while (released < gates.length) gates[released++]();
    await pollFor("the new case's index", async () => (existsSync(store.ocrIndexPath(ID)) ? true : undefined));
    await new Promise((r) => setTimeout(r, 50));
    const index = JSON.parse(await readFile(store.ocrIndexPath(ID), "utf8")) as Record<string, unknown>;
    expect(Object.keys(index), "only the new case's screenshot is indexed").toEqual(["n.png"]);
  });

  it("a late log line for a deleted case recreates nothing, and the re-created case logs to a fresh file", async () => {
    const logger = new LoggerImpl({
      console: false,
      caseLogPath: (caseId) => join(root, caseId, "logs", "session.log"),
    });
    await create();
    logger.info("old case line", { caseId: ID });
    await new Promise((r) => setTimeout(r, 20));
    await deleteCase();
    logger.info("late line after delete", { caseId: ID });
    await new Promise((r) => setTimeout(r, 20));
    expect(existsSync(join(root, ID)), "a late log line must not recreate the case folder").toBe(false);
    await create("new");
    logger.info("new case line", { caseId: ID });
    await logger.close();
    const text = await readFile(join(root, ID, "logs", "session.log"), "utf8");
    expect(text).toContain("new case line");
    expect(text).not.toContain("old case line");
    expect(text).not.toContain("late line after delete");
  });

  it("a late job-ledger write for a deleted case is refused and recreates nothing", async () => {
    await create();
    const ledger = new JobLedgerStore(store);
    await deleteCase();
    const at = new Date().toISOString();
    const job: Job = {
      id: "job-1",
      caseId: ID,
      kind: "synthesis",
      status: "queued",
      priority: "normal",
      queuedAt: at,
      updatedAt: at,
      warnings: [],
      attempt: 1,
      maxRetries: 0,
      resumable: false,
      cancellable: true,
    } as Job;
    const err = await ledger.insert(job).catch((e: unknown) => e);
    expect(isCaseWriteRefused(err), String(err)).toBe(true);
    expect(existsSync(join(root, ID)), "the ledger worker must not recreate state/").toBe(false);
  });

  it("a job-ledger list for a deleted case reads empty and recreates nothing", async () => {
    await create();
    const ledger = new JobLedgerStore(store);
    await deleteCase();
    expect(await ledger.list(ID)).toEqual([]);
    expect(existsSync(join(root, ID))).toBe(false);
  });

  it("old work cannot register a job against a same-id successor, nor supersede its queued job", async () => {
    const jobs = new JobManager({ perCaseConcurrency: 1 });
    await create();
    const old = captureCaseScope(root, ID); // old work, suspended before it registers
    await deleteCase();
    await create("new");
    const blocker = jobs.register({ caseId: ID, kind: "import", label: "new import" });
    const successor = jobs.register({ caseId: ID, kind: "enrichment", label: "new", exclusive: true });
    const late = old(() => jobs.register({ caseId: ID, kind: "enrichment", label: "old", exclusive: true }));
    await expect(late.ready).rejects.toSatisfy(isCaseWriteRefused);
    expect(late.signal?.aborted).toBe(true);
    const labels = jobs.list(ID).map((j) => j.label);
    expect(labels, "the successor's queued job survives").toContain("new");
    expect(labels).not.toContain("old");
    await blocker.ready;
    await jobs.finish(blocker.jobId);
    await successor.ready;
    await jobs.finish(successor.jobId);
  });

  it("a chat channel bound to the deleted case is unbound, so it never serves a same-id successor", async () => {
    await create();
    const channels = new SlashCommandChannelStore(`${root}-bindings.json`);
    await channels.bind("slack:C1", ID);
    await channels.bind("slack:C2", "other-case");
    const ctx = {
      store,
      options: { slashCommandChannelStore: channels },
      serverLogger: { error: () => {} },
      captureBuffers: () => new Map(),
    } as unknown as RouteContext;
    await deleteCase();
    await clearStateOutlivingCase(ctx, ID);
    expect(await channels.get("slack:C1")).toBeUndefined();
    expect((await channels.get("slack:C2"))?.caseId).toBe("other-case");
  });
});
