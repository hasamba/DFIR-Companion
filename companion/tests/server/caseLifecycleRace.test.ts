// #1808 — a status or password write that arrives while a delete runs must not bring the case back
// as a nameless "ghost" (a fabricated case.json that made the rm fail with ENOTEMPTY and reported
// the delete as failed after the evidence was already gone). #1809 — setting an archived case to
// "open" must not strand it where neither restore nor re-archive can reach it.

import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile, stat, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore, CaseNotFoundError } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-lifecycle-race-"));
  const store = new CaseStore(root);
  const app = createApp(store, { stateStore: new StateStore(store) });
  return { app, store, root };
}

async function seedClosedCase(app: ReturnType<typeof createApp>, store: CaseStore, caseId: string) {
  await request(app).post("/cases").send({ caseId, name: "Race", investigator: "alice", aiProvider: "mock" });
  expect((await request(app).patch(`/cases/${caseId}/status`).send({ status: "closed" })).status).toBe(200);
  // Enough files that the recursive rm takes long enough for the writes to land mid-delete.
  const dir = join(store.caseDir(caseId), "imports");
  await mkdir(dir, { recursive: true });
  await Promise.all(Array.from({ length: 400 }, (_, i) => writeFile(join(dir, `f${i}.txt`), "x")));
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const exists = (p: string) =>
  stat(p).then(
    () => true,
    () => false,
  );

describe("updateCaseMeta never fabricates a case (#1808)", () => {
  it("refuses a case whose metadata is gone and writes nothing", async () => {
    const { store, root } = await harness();
    await expect(store.updateCaseMeta("ghost", { status: "closed" })).rejects.toBeInstanceOf(
      CaseNotFoundError,
    );
    expect(await exists(join(root, "ghost"))).toBe(false);
  });

  it("a guard that refuses leaves the metadata untouched", async () => {
    const { app, store } = await harness();
    await request(app)
      .post("/cases")
      .send({ caseId: "g1", name: "n", investigator: "i", aiProvider: "mock" });
    await expect(
      store.updateCaseMeta("g1", { status: "closed" }, () => {
        throw new Error("no");
      }),
    ).rejects.toThrow("no");
    expect((await store.getCaseMeta("g1"))?.status).not.toBe("closed");
  });
});

describe("status and password writes racing a delete (#1808)", () => {
  it("PATCH /status during delete: the delete wins and no ghost case remains (5 runs)", async () => {
    const { app, store, root } = await harness();
    for (let run = 0; run < 5; run++) {
      const id = `race-${run}`;
      await seedClosedCase(app, store, id);
      const del = request(app).post(`/cases/${id}/delete`).send({ archiveFirst: "none" });
      // Staggered across the rm, so some writes land mid-delete rather than all before it starts.
      const patches = Array.from({ length: 15 }, (_, i) =>
        sleep(i * 3).then(() => request(app).patch(`/cases/${id}/status`).send({ status: "closed" })),
      );
      const [delRes, ...patchRes] = await Promise.all([del, ...patches]);
      expect(delRes.status).toBe(200);
      expect(delRes.body).toMatchObject({ deleted: true });
      for (const r of patchRes) expect([200, 404]).toContain(r.status);
      expect(await exists(join(root, id))).toBe(false);
      const list = await request(app).get("/cases");
      expect(JSON.stringify(list.body)).not.toContain(`"${id}"`);
    }
  });

  it("a password write during delete does not resurrect the case", async () => {
    const { app, store, root } = await harness();
    await seedClosedCase(app, store, "pw-race");
    const del = request(app).post("/cases/pw-race/delete").send({ archiveFirst: "none" });
    const sets = Array.from({ length: 5 }, () =>
      request(app).post("/cases/pw-race/password").send({ newPassword: "correct horse battery" }),
    );
    const [delRes, ...setRes] = await Promise.all([del, ...sets]);
    expect(delRes.body).toMatchObject({ deleted: true });
    for (const r of setRes) expect([200, 404]).toContain(r.status);
    expect(await exists(join(root, "pw-race"))).toBe(false);
  });

  it("a case reopened after the delete's status check is not deleted", async () => {
    const { app, store } = await harness();
    await seedClosedCase(app, store, "reopen");
    const original = store.deleteCaseFolder.bind(store);
    const patch = store as { deleteCaseFolder: CaseStore["deleteCaseFolder"] };
    patch.deleteCaseFolder = async (id, opts) => {
      // A reopen that lands between the route's status check and the removal.
      await store.updateCaseMeta(id, { status: "open" });
      return original(id, opts);
    };
    try {
      const res = await request(app).post("/cases/reopen/delete").send({ archiveFirst: "none" });
      expect(res.body.deleted).toBe(false);
      expect(res.body.deleteError).toMatch(/closed or archived/);
      expect((await store.getCaseMeta("reopen"))?.status).toBe("open");
    } finally {
      patch.deleteCaseFolder = original;
    }
  });
});

describe("PATCH /status on an archived case (#1809)", () => {
  it("answers 409 'restore the case first' and leaves it restorable", async () => {
    const { app, store, root } = await harness();
    await request(app)
      .post("/cases")
      .send({ caseId: "arc", name: "n", investigator: "i", aiProvider: "mock" });
    await request(app).patch("/cases/arc/status").send({ status: "closed" });
    const archived = await request(app).post("/cases/arc/archive").send({ removeFromList: true });
    expect(archived.body.removedFromList).toBe(true);

    const res = await request(app).patch("/cases/arc/status").send({ status: "open" });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/restore the case first/);
    const meta = JSON.parse(await readFile(join(root, "_archived", "arc", "case.json"), "utf8"));
    expect(meta.status).toBe("archived");

    const restored = await request(app).post("/cases/arc/restore").send({});
    expect(restored.status).toBe(200);
    expect((await store.getCaseMeta("arc"))?.status).toBe("closed");
    expect(await exists(join(root, "arc", "case.json"))).toBe(true);
  });

  it("archiving moves the folder and sets the status in one step", async () => {
    const { app, store, root } = await harness();
    await request(app)
      .post("/cases")
      .send({ caseId: "one", name: "n", investigator: "i", aiProvider: "mock" });
    await store.archiveCaseFolder("one", "archived");
    const meta = JSON.parse(await readFile(join(root, "_archived", "one", "case.json"), "utf8"));
    expect(meta.status).toBe("archived");
  });

  it("restore recovers a case a pre-fix status change left in _archived/ labelled open", async () => {
    const { app, store, root } = await harness();
    await request(app)
      .post("/cases")
      .send({ caseId: "stuck", name: "n", investigator: "i", aiProvider: "mock" });
    await request(app).patch("/cases/stuck/status").send({ status: "closed" });
    await request(app).post("/cases/stuck/archive").send({ removeFromList: true });
    // The stranded state #1809 left behind: the folder in _archived/, its case.json saying open.
    const metaPath = join(root, "_archived", "stuck", "case.json");
    const meta = JSON.parse(await readFile(metaPath, "utf8"));
    await writeFile(metaPath, JSON.stringify({ ...meta, status: "open" }));

    const restored = await request(app).post("/cases/stuck/restore").send({});
    expect(restored.status).toBe(200);
    expect(await exists(join(root, "stuck", "case.json"))).toBe(true);
    expect((await store.getCaseMeta("stuck"))?.status).toBe("closed");
  });
});

describe("create racing a delete of the same id (#1808)", () => {
  it("the create waits for the delete; the new case is whole and the delete succeeded", async () => {
    const { app, store } = await harness();
    await seedClosedCase(app, store, "reuse");
    const del = request(app).post("/cases/reuse/delete").send({ archiveFirst: "none" });
    const create = sleep(5).then(() =>
      store.createCase({ caseId: "reuse", name: "second", investigator: "bob", aiProvider: null }).then(
        () => "created",
        (err: Error) => err.name,
      ),
    );
    const [delRes, created] = await Promise.all([del, create]);
    expect(delRes.body).toMatchObject({ deleted: true });
    if (created === "created") expect((await store.getCaseMeta("reuse"))?.name).toBe("second");
    else expect(created).toBe("CaseAlreadyExistsError");
  });
});
