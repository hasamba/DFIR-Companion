import { describe, expect, it } from "vitest";
import express from "express";
import type { Request, Response } from "express";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { ImportLock } from "../../src/analysis/importLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { withArchiveBarrier } from "../../src/routes/archiveImportBarrier.js";
import { admitIngest, isCaseArchiving } from "../../src/analysis/caseIngestAdmission.js";
import { registerImportCaseGuard } from "../../src/routes/importCaseGuard.js";
import type { RouteContext } from "../../src/routes/context.js";

// #1903: archiving a case while imports ran produced a torn archive — every raw import in the zip but
// a half-merged state database — and with removeFromList the archived case kept changing afterwards.
// An archive (and the other two routes that zip the whole case: delete-with-archive and the encrypted
// export) now WAITS for an in-flight import to finish — answering 409 only past a bounded wait — and
// holds the case's import section while it builds the file, during which a new import is refused
// before it writes anything. The 409 tests shorten the wait (archiveIngestWaitMs) so they stay fast.

const SHORT_WAIT_MS = 100;

async function setup(archiveIngestWaitMs = SHORT_WAIT_MS) {
  const root = await mkdtemp(join(tmpdir(), "dfir-archive-lock-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save(emptyState("c1"));
  const importLock = new ImportLock();
  const app = createApp(store, { stateStore, importLock, archiveIngestWaitMs });
  return { root, store, app, importLock };
}

const zipsIn = async (root: string) => (await readdir(root)).filter((f) => f.endsWith(".zip"));

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

function fakeCtx(
  casesRoot: string,
  importLock: ImportLock,
  activeJob: false | "import" | "mcp" = false,
): RouteContext {
  return {
    store: { casesRoot },
    importLock,
    options: {
      archiveIngestWaitMs: SHORT_WAIT_MS,
      jobManager: { hasActive: (_id: string, kind: string) => kind === activeJob },
    },
  } as unknown as RouteContext;
}

describe("archive vs a running import (#1903)", () => {
  // #1921 CI: an import's events show in the state while its settle tail (demote, import meta, undo
  // checkpoint, whitelist/NSRL/deobfuscation) still holds the import section. "Import, then export at
  // once" answered 409 about one run in three. The export now waits for that tail, then succeeds.
  it("an export right after an import waits for the import's settle tail instead of answering 409", async () => {
    const { app, importLock } = await setup(5_000);
    const release = await importLock.acquire("c1"); // the import's section, still settling
    const settleTail = setTimeout(release, 150);
    const startedAt = Date.now();
    const exp = await request(app)
      .post("/cases/c1/export/encrypted")
      .send({ password: "a-long-enough-pass" });
    clearTimeout(settleTail);
    expect(exp.status).toBe(200);
    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(140); // it waited for the tail
  });

  it("the archive waits for an ingest that holds a reservation, then builds once it drains", async () => {
    const { root, app } = await setup(5_000);
    const releaseIngest = admitIngest(root, "c1"); // e.g. a push storing its raw file
    const settled = setTimeout(releaseIngest, 120);
    const ok = await request(app).post("/cases/c1/archive").send({});
    clearTimeout(settled);
    expect(ok.status).toBe(200);
    expect(await zipsIn(root)).toHaveLength(1);
  });

  it("POST /archive answers 409 and writes no zip when the import section stays held past the wait", async () => {
    const { root, app, importLock } = await setup();
    const release = await importLock.acquire("c1");
    const refused = await request(app).post("/cases/c1/archive").send({ removeFromList: true });
    expect(refused.status).toBe(409);
    expect(refused.body.error).toMatch(/import or an archive in progress/);
    expect(await zipsIn(root)).toEqual([]);
    release();
    await new Promise((r) => setImmediate(r)); // the lock's tail is dropped once it settles
    const ok = await request(app).post("/cases/c1/archive").send({});
    expect(ok.status).toBe(200);
    expect(await zipsIn(root)).toHaveLength(1);
  });

  it("delete-with-archive and the encrypted export refuse the same way", async () => {
    const { app, importLock } = await setup();
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    const release = await importLock.acquire("c1");
    const del = await request(app).post("/cases/c1/delete").send({ archiveFirst: "zip" });
    expect(del.status).toBe(409);
    const exp = await request(app)
      .post("/cases/c1/export/encrypted")
      .send({ password: "a-long-enough-pass" });
    expect(exp.status).toBe(409);
    // A delete that builds no archive still goes through: it aborts the case's work (#1831).
    const plain = await request(app).post("/cases/c1/delete").send({ archiveFirst: "none" });
    expect(plain.body).toMatchObject({ deleted: true });
    release();
  });

  it("an import that is queued for the section counts as running", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-archive-lock-"));
    const lock = new ImportLock();
    const hold = deferred();
    const first = lock.runExclusive("c1", () => hold.promise);
    const queued = lock.runExclusive("c1", async () => undefined);
    const handler = async (_req: Request, res: Response) => res.status(200).json({ ok: true });
    const app = express().post("/cases/:id/archive", withArchiveBarrier(fakeCtx(root, lock), handler));
    expect((await request(app).post("/cases/c1/archive")).status).toBe(409);
    hold.resolve();
    await Promise.all([first, queued]);
  });

  it("an import job that is queued or running counts as running, even before it takes the section", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-archive-lock-"));
    const handler = async (_req: Request, res: Response) => res.status(200).json({ ok: true });
    const busy = express().post(
      "/cases/:id/archive",
      withArchiveBarrier(fakeCtx(root, new ImportLock(), "import"), handler),
    );
    expect((await request(busy).post("/cases/c1/archive")).status).toBe(409);
    const idle = express().post(
      "/cases/:id/archive",
      withArchiveBarrier(fakeCtx(root, new ImportLock()), handler),
    );
    expect((await request(idle).post("/cases/c1/archive")).status).toBe(200);
  });

  it("while an archive builds its file it holds the import section, refuses new imports, and a second archive", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-archive-lock-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const lock = new ImportLock();
    const building = deferred();
    const entered = deferred();
    const handler = async (_req: Request, res: Response) => {
      entered.resolve();
      await building.promise;
      return res.status(200).json({ ok: true });
    };
    const app = express();
    app.use(express.json());
    registerImportCaseGuard(app, store);
    app.post("/cases/:id/import", (_req, res) => res.status(202).json({ accepted: true }));
    app.post("/cases/:id/archive", withArchiveBarrier(fakeCtx(root, lock), handler));

    const archive = request(app)
      .post("/cases/c1/archive")
      .then((r) => r);
    await entered.promise;

    expect(isCaseArchiving(root, "c1")).toBe(true);
    expect(lock.isBusy("c1")).toBe(true);
    const imp = await request(app).post("/cases/c1/import").send({});
    expect(imp.status).toBe(409);
    expect(imp.body.error).toMatch(/being archived/);
    expect((await request(app).post("/cases/c1/archive")).status).toBe(409);

    let importRan = false;
    const section = lock.runExclusive("c1", async () => {
      importRan = true;
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(importRan).toBe(false); // waits behind the archive

    building.resolve();
    expect((await archive).status).toBe(200);
    await section;
    expect(importRan).toBe(true);
    expect(isCaseArchiving(root, "c1")).toBe(false);
    expect((await request(app).post("/cases/c1/import").send({})).status).toBe(202);
  });

  it("an import request that passed the guard holds the archive off until its response closes", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-archive-lock-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const storing = deferred();
    const entered = deferred();
    const app = express();
    app.use(express.json());
    registerImportCaseGuard(app, store);
    // Stands in for a route that writes the raw file BEFORE the import is a job or in the section.
    app.post("/cases/:id/import", async (_req, res) => {
      entered.resolve();
      await storing.promise;
      res.status(202).json({ accepted: true });
    });
    const handler = async (_req: Request, res: Response) => res.status(200).json({ ok: true });
    app.post("/cases/:id/archive", withArchiveBarrier(fakeCtx(root, new ImportLock()), handler));

    const imp = request(app)
      .post("/cases/c1/import")
      .send({})
      .then((r) => r);
    await entered.promise;
    expect((await request(app).post("/cases/c1/archive")).status).toBe(409);
    storing.resolve();
    expect((await imp).status).toBe(202);
    await new Promise((r) => setTimeout(r, 10)); // 'close' follows the response
    expect((await request(app).post("/cases/c1/archive")).status).toBe(200);
  });

  it("an MCP run or agent job counts too: it writes its output after its request answered (#1920)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-archive-lock-"));
    const handler = async (_req: Request, res: Response) => res.status(200).json({ ok: true });
    const app = express().post(
      "/cases/:id/archive",
      withArchiveBarrier(fakeCtx(root, new ImportLock(), "mcp"), handler),
    );
    expect((await request(app).post("/cases/c1/archive")).status).toBe(409);
  });

  it("the mark is cleared when the archive fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-archive-lock-"));
    const lock = new ImportLock();
    const handler = async () => {
      throw new Error("disk full");
    };
    const barrier = withArchiveBarrier(fakeCtx(root, lock), handler);
    const res = { status: () => res, json: () => res } as unknown as Response;
    await expect(barrier({ params: { id: "c1" } } as unknown as Request, res)).rejects.toThrow("disk full");
    expect(isCaseArchiving(root, "c1")).toBe(false);
  });
});
