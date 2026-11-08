import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { ImportLock } from "../../src/analysis/importLock.js";

// #2404: analyst writes that change the case's record had no closed/archived check — import
// undo/redo, finding workflow and severity restore, hypotheses, playbook, remediation, cockpit.
// The central gate (composition/caseWriteGuard.ts) now refuses each on a frozen case with 423,
// and lets every one of them through on an open case.

const WRITES: ReadonlyArray<readonly ["post" | "patch" | "put" | "delete", string]> = [
  ["post", "/import/undo"],
  ["post", "/import/redo"],
  ["patch", "/findings/f1/workflow"],
  ["post", "/findings/f1/severity-restore"],
  ["delete", "/findings/f1/severity-restore"],
  ["post", "/hypotheses"],
  ["patch", "/hypotheses/h1"],
  ["delete", "/hypotheses/h1"],
  ["post", "/playbook"],
  ["put", "/playbook/control"],
  ["post", "/playbook/sync"],
  ["post", "/playbook/suggest-hunts"],
  ["patch", "/playbook/order"],
  ["patch", "/playbook/t1"],
  ["delete", "/playbook/t1"],
  ["post", "/remediation"],
  ["delete", "/remediation/b1"],
  ["post", "/remediation/b1/verify"],
  ["post", "/remediation/b1/attach"],
  ["patch", "/remediation/b1/status"],
  ["patch", "/cockpit/cards/c1"],
  ["post", "/cockpit/review"],
];

async function makeApp() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-2404-")));
  const stateStore = new StateStore(store);
  const hypothesisStore = new HypothesisStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const importLock = new ImportLock();
  const app = createApp(store, {
    pipeline,
    stateStore,
    hypothesisStore,
    importLock,
    importUndoStore: new ImportUndoStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, hypothesisStore, importLock };
}

function send(app: Awaited<ReturnType<typeof makeApp>>["app"], method: string, path: string) {
  const agent = request(app) as unknown as Record<string, (p: string) => request.Test>;
  const call = agent[method];
  return call(`/cases/c1${path}`).send({});
}

describe("closed and archived cases refuse case-changing writes (#2404)", () => {
  it("refuses every listed write on a closed case with 423, and the gate lets them through when open", async () => {
    const { app } = await makeApp();
    for (const [method, path] of WRITES) {
      const open = await send(app, method, path);
      expect(open.status, `${method.toUpperCase()} ${path} on an open case`).not.toBe(423);
    }
    expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
    for (const [method, path] of WRITES) {
      const res = await send(app, method, path);
      expect(res.status, `${method.toUpperCase()} ${path} on a closed case`).toBe(423);
      expect(res.body.error).toMatch(/closed — reopen it before changing it/);
    }
  });

  it("matches case-insensitively and with a trailing slash, and never blocks reads or reopen", async () => {
    const { app } = await makeApp();
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    expect((await request(app).post("/cases/c1/IMPORT/UNDO/").send({})).status).toBe(423);
    expect((await request(app).get("/cases/c1/hypotheses")).status).not.toBe(423);
    expect((await request(app).get("/cases/c1/import/undo-stack")).status).not.toBe(423);
    expect((await request(app).patch("/cases/c1/status").send({ status: "open" })).status).toBe(200);
    expect((await request(app).post("/cases/c1/hypotheses").send({ title: "after reopen" })).status).toBe(
      201,
    );
  });

  it("a closed case keeps its hypotheses exactly as they were", async () => {
    const { app, hypothesisStore } = await makeApp();
    const created = await request(app).post("/cases/c1/hypotheses").send({ title: "lateral movement" });
    expect(created.status).toBe(201);
    const id = created.body.id as string;
    expect((await request(app).patch(`/cases/c1/hypotheses/${id}`).send({ title: "renamed" })).status).toBe(
      200,
    );
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    const before = JSON.stringify(await hypothesisStore.load("c1"));
    expect(
      (await request(app).patch(`/cases/c1/hypotheses/${id}`).send({ title: "edited after close" })).status,
    ).toBe(423);
    expect((await request(app).delete(`/cases/c1/hypotheses/${id}`)).status).toBe(423);
    expect(JSON.stringify(await hypothesisStore.load("c1"))).toBe(before);
  });

  it("refuses them on an archived case too, naming restore", async () => {
    const { app, store } = await makeApp();
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    await store.archiveCaseFolder("c1", "archived");
    for (const [method, path] of WRITES.slice(0, 6)) {
      const res = await send(app, method, path);
      expect(res.status, `${method.toUpperCase()} ${path} on an archived case`).toBe(423);
      expect(res.body.error).toMatch(/archived — restore it before changing it/);
    }
  });

  // The gate checks the case when the request arrives; an undo then waits for the import lock, and a
  // close can land meanwhile. The step checks again once it holds the lock.
  it("an undo that was waiting for the import lock when the case closed is refused", async () => {
    const { app, importLock } = await makeApp();
    const release = await importLock.acquire("c1");
    const pending = request(app)
      .post("/cases/c1/import/undo")
      .send({})
      .then((r) => r);
    await new Promise((r) => setTimeout(r, 100));
    expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
    release();
    const res = await pending;
    expect(res.status).toBe(423);
    expect(res.body.error).toMatch(/closed — reopen it before changing it/);
  });
});
