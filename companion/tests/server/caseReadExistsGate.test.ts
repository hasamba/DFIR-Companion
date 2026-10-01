import { describe, it, expect, afterAll } from "vitest";
import { mkdtemp, mkdir, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import type { Express } from "express";
import { createRuntimeStores } from "../../src/composition/runtimeStores.js";
import { buildAppOptions } from "../../src/composition/appWiring.js";
import { createApp } from "../../src/server.js";
import { STORE_OPENING_READS } from "../../src/composition/caseWriteExistsGate.js";

// #1901: a GET for a case that was never created must not create its folder. These eleven reads
// opened the per-case database, and the SQLite worker mkdirs on open, so a stale dashboard poll or a
// typo'd id left casesRoot/<id>/state/investigation.sqlite behind — a folder GET /cases never lists,
// which then made POST /cases for that id answer 409.
//
// FULL RUNTIME WIRING, not a bare createApp: with optional stores missing most of these routes answer
// 501 before they reach the database, and a test that never reaches the disk proves nothing.

const LISTED_IN_ISSUE = [
  "/export/redacted",
  "/host-scope",
  "/login-graph",
  "/proxy-host-identity-matches",
  "/remediation",
  "/report.docx",
  "/resolver-endpoint-matches",
  "/static-report-attestations",
  "/super-timeline",
  "/super-timeline.jsonl",
  "/tls-graph",
];

const roots: string[] = [];

async function harness(): Promise<{ root: string; app: Express }> {
  const base = await mkdtemp(join(tmpdir(), "dfir-case-read-gate-"));
  roots.push(base);
  const root = join(base, "cases");
  await mkdir(root);
  const rt = createRuntimeStores({ casesRoot: root, host: "127.0.0.1", port: 0, logDir: join(base, "logs") });
  await rt.store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const app = createApp(rt.store, buildAppOptions(rt, {} as Parameters<typeof buildAppOptions>[1]));
  return { root, app };
}

/** Every GET path the app registers under /cases/:id/. */
function caseReadRoutes(app: Express): string[] {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const layers = (app as any)._router.stack as Array<{
    route?: { path: string | string[]; methods: Record<string, boolean> };
  }>;
  const out: string[] = [];
  for (const layer of layers) {
    if (!layer.route?.methods.get) continue;
    const paths = Array.isArray(layer.route.path) ? layer.route.path : [layer.route.path];
    for (const path of paths) if (path.startsWith("/cases/:id/")) out.push(path);
  }
  return out;
}

// Only the ghost ids matter: the runtime stores create their own files in the cases root
// (.dfir-companion-jobs.sqlite, .instance-secret) on their own schedule, so a whole-listing compare races.
const ghostsIn = async (root: string) => (await readdir(root)).filter((name) => name.startsWith("ghost"));

const concrete = (path: string, caseId: string) => path.replace(":id", caseId).replace(/:[A-Za-z]+/g, "p1");

afterAll(async () => {
  for (const root of roots) await rm(root, { recursive: true, force: true });
});

describe("reads of a case that does not exist (#1901)", () => {
  it("gates exactly the eleven reads the issue lists", () => {
    expect([...STORE_OPENING_READS].sort()).toEqual([...LISTED_IN_ISSUE].sort());
  });

  it.each(LISTED_IN_ISSUE)(
    "GET %s answers 404, creates nothing, and leaves the id free",
    async (rel) => {
      const { root, app } = await harness();
      const caseId = `ghost${rel.replace(/[^a-z]/gi, "-")}`;
      const res = await request(app).get(`/cases/${caseId}${rel}`);
      expect(res.status).toBe(404);
      expect(String(res.body?.error ?? "")).toContain(`case ${caseId} does not exist`);
      expect(await ghostsIn(root)).toEqual([]);
      const created = await request(app).post("/cases").send({ caseId, name: "n", investigator: "i" });
      expect(created.status).toBe(201);
      // Generous: the first case spins up the runtime stores and SQLite workers cold, and under a
      // parallel run that alone has gone past vitest's 5s default.
    },
    30_000,
  );

  it("HEAD is gated too, and Express's spelling variants (case, trailing slash) do not slip past", async () => {
    const { root, app } = await harness();
    expect((await request(app).head("/cases/ghost-head/login-graph")).status).toBe(404);
    expect((await request(app).get("/cases/ghost-upper/Login-Graph")).status).toBe(404);
    expect((await request(app).get("/cases/ghost-slash/tls-graph/")).status).toBe(404);
    expect(await ghostsIn(root)).toEqual([]);
  }, 30_000);

  it("the gated reads still answer for a case that exists", async () => {
    const { app } = await harness();
    for (const rel of ["/login-graph", "/tls-graph", "/super-timeline", "/remediation"]) {
      const res = await request(app).get(`/cases/c1${rel}`);
      expect(res.status, rel).toBe(200);
    }
  }, 30_000);

  it("no GET under /cases/:id/ leaves a folder behind for an unknown case", async () => {
    const { root, app } = await harness();
    const routes = caseReadRoutes(app);
    // The walk has to have found the routes before its silence means anything.
    expect(routes.length).toBeGreaterThan(100);
    let n = 0;
    for (const path of routes) await request(app).get(concrete(path, `ghost-walk-${n++}`));
    expect(await ghostsIn(root)).toEqual([]);
  }, 120_000);
});
