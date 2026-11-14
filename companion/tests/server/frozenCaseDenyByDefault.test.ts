import { describe, it, expect, beforeAll } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import type { Express } from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { frozenWritePurpose } from "../../src/composition/caseWriteGuard.js";

// #2437: a closed or archived case refuses EVERY case-changing request unless the route is on the
// explicit allowlist in composition/caseWriteAllowlist.ts. This file walks the live Express stack,
// so a new write route under /cases/:id is refused on a frozen case the day it is added — and if
// someone allowlists it instead, the EXPECTED_ALLOWED list below changes in review.

interface Layer {
  route?: { path: string | string[]; methods: Record<string, boolean> };
  name?: string;
}

const READS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Every non-GET route under /cases/:id/, as [METHOD, relative path], in registration order. */
function caseWriteRoutes(app: Express): Array<[string, string]> {
  const layers = (app as unknown as { _router: { stack: Layer[] } })._router.stack;
  const out: Array<[string, string]> = [];
  for (const layer of layers) {
    if (!layer.route) continue;
    const paths = Array.isArray(layer.route.path) ? layer.route.path : [layer.route.path];
    for (const method of Object.keys(layer.route.methods).map((m) => m.toUpperCase())) {
      if (READS.has(method)) continue;
      for (const p of paths) {
        if (p.startsWith("/cases/:id/")) out.push([method, p.slice("/cases/:id".length)]);
      }
    }
  }
  return out;
}

/** A route pattern with its parameters filled in, lowercased like the gate compares it. */
const concrete = (rel: string) => rel.replace(/:[A-Za-z]+/g, "p1").toLowerCase();

/**
 * The routes a frozen case still accepts — the reviewable form of the allowlist. Adding a route
 * here is a product decision (#2437): write the reason next to the allowlist entry.
 */
const EXPECTED_ALLOWED = [
  // lifecycle and credentials
  "PATCH /status",
  "POST /archive",
  "POST /restore",
  "POST /delete",
  "POST /export/encrypted",
  "POST /unlock",
  "POST /password",
  "DELETE /password",
  "POST /lock",
  "DELETE /push-token",
  "POST /cloud-accounts/:accountId/attach",
  "POST /cloud-accounts/:accountId/detach",
  "POST /cloud-accounts/:accountId/check",
  "PUT /cloud-accounts/:accountId",
  "DELETE /cloud-accounts/:accountId",
  // exports
  "POST /report",
  "POST /push/iris",
  "POST /push/timesketch",
  "POST /push/timesketch-super",
  "POST /push/misp",
  "POST /push/notion",
  "POST /push/clickup",
  "POST /push/jira",
  "POST /push/jira/bulk",
  "POST /push/servicenow",
  "POST /push/servicenow/bulk",
  // reads sent as POST
  "POST /tags/tagger-for",
  "POST /false-positive/suggest",
  "POST /tagger/suggest-rule",
  "POST /tagger/preview",
  "POST /sigma/compile",
  "POST /sigma/dry-run",
  "POST /translate-query",
  "POST /hunt-query/validate",
  "POST /hunt-query/execute",
  "POST /hunt-query/finding-evidence",
  "POST /timeline-gaps/hypothesize",
  "POST /sessions/:sid/summary",
  "POST /custody/verify",
  "POST /executive-summary",
  "POST /view-summary",
  "POST /remediation-plan",
  "POST /hypothesis-review",
  "POST /adversary-hints/hunt-technique",
  "POST /memory/next-steps",
  "POST /velociraptor/suggest-hunts",
  "POST /velociraptor/hunt-rows",
  "POST /cloud-collect/precheck",
  "POST /cloud-collect/regions",
  "POST /tools/:toolId/update-rules",
  // stopping or finishing work that is already running
  "POST /hunt-query/executions/:executionId/cancel",
  "DELETE /mcp/preview/:jobId",
  "POST /velociraptor/monitors/:mid/stop",
  "DELETE /velociraptor/monitors/:mid",
  "POST /velociraptor/hunt-jobs/:huntId/poll-status",
  // self-guarded: authenticates its push token first, then refuses a frozen case itself
  "POST /push",
].sort();

/** Named by the owner (#2437): each must be refused, and a failure must say which. */
const OWNER_NAMED_REFUSALS: ReadonlyArray<readonly [string, string]> = [
  ["POST", "/ioc-whitelist/apply"],
  ["POST", "/nsrl/apply"],
  ["POST", "/tagger/run"],
  ["POST", "/second-opinion/apply"],
  ["POST", "/second-opinion/apply-all"],
  ["POST", "/super-timeline/promote"],
  ["POST", "/host-duplicates/merge"],
  ["POST", "/restore-backup"],
  ["POST", "/host-scope/p1"],
  ["PUT", "/correlation-profile"],
  ["POST", "/notebook"],
  ["PATCH", "/notebook/p1"],
  ["POST", "/comments"],
  ["POST", "/pinned-findings"],
];

async function makeApp() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-2437-deny-")));
  const app = createApp(store);
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

function send(app: Express, method: string, rel: string) {
  const agent = request(app) as unknown as Record<string, (p: string) => request.Test>;
  return agent[method.toLowerCase()](`/cases/c1${rel}`).send({});
}

describe("a frozen case refuses every write route that is not allowlisted (#2437)", () => {
  let app: Express;
  let store: CaseStore;
  let routes: Array<[string, string]>;

  beforeAll(async () => {
    ({ app, store } = await makeApp());
    routes = caseWriteRoutes(app);
  });

  it("finds a route surface of the expected size", () => {
    expect(routes.length).toBeGreaterThan(200);
  });

  it("allows exactly the reviewed list, and every allowlist entry names a real route", () => {
    const allowed = routes
      .filter(([m, rel]) => frozenWritePurpose(m, concrete(rel)) === null)
      .map(([m, rel]) => `${m} ${rel}`);
    expect([...new Set(allowed)].sort()).toEqual(EXPECTED_ALLOWED);
  });

  it("mounts the gate ahead of every case write route", () => {
    const layers = (app as unknown as { _router: { stack: Layer[] } })._router.stack;
    const gate = layers.findIndex((l) => l.name === "caseWriteGuardGate");
    const firstWrite = layers.findIndex(
      (l) =>
        !!l.route &&
        [l.route.path].flat().some((p) => p.startsWith("/cases/:id/")) &&
        Object.keys(l.route.methods).some((m) => !READS.has(m.toUpperCase())),
    );
    expect(gate).toBeGreaterThan(-1);
    expect(firstWrite).toBeGreaterThan(gate);
  });

  it("answers 423 for every other write route on a closed case, then on an archived one", async () => {
    expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
    const refused = routes.filter(([m, rel]) => frozenWritePurpose(m, concrete(rel)) !== null);
    for (const [method, rel] of refused) {
      const res = await send(app, method, concrete(rel));
      expect(res.status, `${method} ${rel} on a closed case`).toBe(423);
      expect(res.body.error, `${method} ${rel}`).toMatch(/^Case "c1" is closed — reopen it before /);
    }
    await store.archiveCaseFolder("c1", "archived");
    for (const [method, rel] of refused) {
      const res = await send(app, method, concrete(rel));
      expect(res.status, `${method} ${rel} on an archived case`).toBe(423);
      expect(res.body.error, `${method} ${rel}`).toMatch(/^Case "c1" is archived — restore it before /);
    }
  });
});

describe("the routes the owner named are refused on a closed case (#2437)", () => {
  it.each(OWNER_NAMED_REFUSALS)("%s %s → 423", async (method, rel) => {
    const { app } = await makeApp();
    expect((await send(app, method, rel)).status, "open case").not.toBe(423);
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    const res = await send(app, method, rel);
    expect(res.status).toBe(423);
    expect(res.body.error).toBe('Case "c1" is closed — reopen it before changing it');
  });
});

describe("the refusal keeps each route's own wording (#2437)", () => {
  it.each([
    ["POST", "/synthesize", "running synthesis"],
    ["POST", "/deep-pass", "running a deep pass"],
    ["POST", "/jev/promote", "promoting evidence"],
    ["POST", "/custody", "recording custody"],
    ["POST", "/sigma/regrade", "re-grading its evidence"],
    ["POST", "/mcp/p1/run", "running a tool"],
    ["POST", "/mcp/preview/p1/import", "importing"],
    ["POST", "/mcp/agent", "running the investigation"],
    ["POST", "/tools/p1/run", "importing evidence"],
    ["POST", "/import-csv", "importing evidence"],
    ["POST", "/events", "adding evidence"],
    ["POST", "/second-look", "running a second look"],
  ])("%s %s ends with %s", (method, rel, purpose) => {
    expect(frozenWritePurpose(method, rel)).toBe(purpose);
  });

  it("an allowlisted read sent as POST still answers on a closed case", async () => {
    const { app } = await makeApp();
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    expect((await send(app, "POST", "/tags/tagger-for")).status).not.toBe(423);
    expect((await send(app, "POST", "/false-positive/suggest")).status).not.toBe(423);
    expect((await send(app, "POST", "/sigma/compile")).status).not.toBe(423);
  });
});
