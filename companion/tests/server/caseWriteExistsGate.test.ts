import { describe, it, expect } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import type { Express } from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";
import { bypassesCaseWriteExistsGate } from "../../src/composition/caseWriteExistsGate.js";

// #1570: a write to a case that was never created is a 404 and leaves nothing on disk.
//
// #1549 found the Jev review opening the per-case database for any id it was handed, and the SQLite
// worker mkdirs on open. A probe of every write route then found six more that left
// casesRoot/<id>/ behind and eight that read case state for it. The fix is ONE gate mounted ahead of
// every /cases/:id route; this file walks the LIVE router, so a route added later is covered here
// without anyone remembering to list it.

const WRITE_METHODS = ["post", "put", "patch", "delete"] as const;
type Method = (typeof WRITE_METHODS)[number];

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-case-write-gate-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save(emptyState("c1"));
  const app = createApp(store, { stateStore });
  return { root, store, app };
}

/** Every [method, path] the app registers under /cases/:id for a write method. */
function caseWriteRoutes(app: Express): Array<[Method, string]> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const layers = (app as any)._router.stack as Array<{
    route?: { path: string | string[]; methods: Record<string, boolean> };
  }>;
  const out: Array<[Method, string]> = [];
  for (const layer of layers) {
    if (!layer.route) continue;
    const paths = Array.isArray(layer.route.path) ? layer.route.path : [layer.route.path];
    for (const path of paths) {
      if (!path.startsWith("/cases/:id/")) continue;
      for (const m of WRITE_METHODS) if (layer.route.methods[m]) out.push([m, path]);
    }
  }
  return out;
}

/** A concrete URL for a route pattern: the case id goes in :id, every other param gets a filler. */
const concrete = (path: string, caseId: string) => path.replace(":id", caseId).replace(/:[A-Za-z]+/g, "p1");

describe("writes to a case that does not exist (#1570)", () => {
  it("every write route under /cases/:id answers 404 and creates nothing, except the documented bypasses", async () => {
    const { root, app } = await harness();
    const routes = caseWriteRoutes(app);
    // The walk has to have found the routes before its silence means anything.
    expect(routes.length).toBeGreaterThan(150);

    const before = [...(await readdir(root))].sort();
    const leaked: string[] = [];
    let n = 0;
    for (const [method, path] of routes) {
      const caseId = `ghost-${n++}`;
      const url = concrete(path, caseId);
      if (bypassesCaseWriteExistsGate(url)) continue;
      const res = await request(app)[method](url).send({});
      // The WORDING, not just the status: a handler's own 404 for some other missing thing (an IOC,
      // a monitor) would otherwise read as the case being refused, while a valid body still wrote.
      const refused =
        res.status === 404 && String(res.body?.error ?? "").includes(`case ${caseId} does not exist`);
      if (!refused)
        leaked.push(`${method.toUpperCase()} ${path} → ${res.status} ${JSON.stringify(res.body)}`);
    }
    expect(leaked).toEqual([]);
    expect([...(await readdir(root))].sort()).toEqual(before);
  });

  it("is mounted ahead of every case write route, so no route can answer before it", async () => {
    const { app } = await harness();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const stack = (app as any)._router.stack as Array<{ name?: string; route?: { path: string | string[] } }>;
    const gateAt = stack.findIndex((l) => l.name === "caseWriteExistsGate");
    expect(gateAt).toBeGreaterThan(-1);
    const firstCaseRoute = stack.findIndex((l) => {
      const p = l.route?.path;
      return (Array.isArray(p) ? p : p ? [p] : []).some((x) => x.startsWith("/cases/:id/"));
    });
    expect(gateAt).toBeLessThan(firstCaseRoute);
  });

  it("every Velociraptor write route refuses an unknown case through its own gate", async () => {
    const { root, app } = await harness();
    const velo = caseWriteRoutes(app).filter(([, path]) => path.startsWith("/cases/:id/velociraptor"));
    expect(velo.length).toBeGreaterThan(5);
    const leaked: string[] = [];
    let n = 0;
    for (const [method, path] of velo) {
      const caseId = `ghost-velo-${n++}`;
      const res = await request(app)[method](concrete(path, caseId)).send({});
      const refused =
        res.status === 404 && String(res.body?.error ?? "").includes(`case "${caseId}" not found`);
      if (!refused) leaked.push(`${method.toUpperCase()} ${path} → ${res.status}`);
    }
    expect(leaked).toEqual([]);
    expect((await readdir(root)).filter((d) => d.startsWith("ghost"))).toEqual([]);
  });

  it("the only case routes the gate lets through are the documented ones", async () => {
    const { app } = await harness();
    const bypassed = [
      ...new Set(
        caseWriteRoutes(app)
          .filter(([, path]) => bypassesCaseWriteExistsGate(concrete(path, "ghost")))
          .map(([, path]) => path.replace(/^\/cases\/:id/, "").replace(/^(\/velociraptor)\/.*/, "$1/*")),
      ),
    ].sort();
    expect(bypassed).toEqual(["/hunt-query/validate", "/lock", "/push", "/sigma/compile", "/velociraptor/*"]);
  });

  it("/lock stays an idempotent 200 for a case that is gone", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/ghost/lock").send({});
    expect(res.status).toBe(200);
  });

  it("/push does not tell a caller with no token whether the case exists", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-case-write-gate-push-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    // /push answers 501 before anything else without a pipeline; any truthy object gets past that.
    const app = createApp(store, { pipeline: {} as never, pushToken: "the-real-token" });
    const known = await request(app).post("/cases/c1/push").send({});
    const unknown = await request(app).post("/cases/ghost/push").send({});
    expect(known.status).toBeGreaterThanOrEqual(401);
    expect(known.status).toBeLessThan(404);
    expect(unknown.status).toBe(known.status);
    expect(unknown.body).toEqual(known.body);
  });

  it("the two /cases/* paths that are not a case are not refused as one", () => {
    for (const path of [
      "/cases/seed-demo",
      "/cases/seed-demo/",
      "/cases/import/encrypted",
      "/cases/IMPORT/Encrypted",
    ]) {
      expect(bypassesCaseWriteExistsGate(path), path).toBe(true);
    }
    // A case genuinely named "import" is still a case.
    expect(bypassesCaseWriteExistsGate("/cases/import/delete")).toBe(false);
    expect(bypassesCaseWriteExistsGate("/cases/import/import-file")).toBe(false);
  });

  it("reaches the demo seeder rather than answering the gate's 404", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/seed-demo").send({});
    expect(String(res.body?.error ?? "")).not.toMatch(/create it in the dashboard first/);
  });

  it("reads are not gated: the dashboard's Jev probe still answers for an unknown case", async () => {
    const { app } = await harness();
    const res = await request(app).get("/cases/ghost/jev/status");
    expect(res.status).toBe(200);
  });

  it("a real case still reaches its routes, and a closed one still gets its 423", async () => {
    const { app, store } = await harness();
    const open = await request(app).post("/cases/c1/lock").send({});
    expect(open.status).toBe(200);
    await store.updateCaseMeta("c1", { status: "closed" });
    const closed = await request(app).post("/cases/c1/events").send({});
    expect(closed.status).toBe(423);
  });

  it("an archived case passes the gate — restoring it is a write to a case that exists", async () => {
    const { app } = await harness();
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    const archived = await request(app).post("/cases/c1/archive").send({ removeFromList: true });
    expect(archived.status).toBeLessThan(300);
    const res = await request(app).post("/cases/c1/restore").send({});
    expect(res.status).toBeLessThan(300);
  });
});
