import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";

/**
 * POST /cases/seed-demo is the one mutating route demo mode leaves open, so on the public demo it
 * is reachable with no authentication at all. That is intended — a visitor may reset the demo.
 *
 * What is not intended is letting the caller name the case. Honouring the body id there turns one
 * reset button into unbounded case creation: loop over names and the server scaffolds a directory
 * per request until the volume fills. Demo mode therefore ignores the id and reseeds the single
 * default case, which keeps the write bounded however often the route is called.
 */
async function harness(demoMode: boolean) {
  const root = await mkdtemp(join(tmpdir(), "dfir-seed-demo-"));
  const store = new CaseStore(root);
  const app = createApp(store, { stateStore: new StateStore(store), demoMode });
  return { app, store };
}

async function caseIds(app: ReturnType<typeof createApp>): Promise<string[]> {
  const res = await request(app).get("/cases");
  return (res.body as Array<{ caseId: string }>).map((c) => c.caseId);
}

describe("POST /cases/seed-demo in demo mode", () => {
  it("ignores a caller-supplied caseId so the write cannot be multiplied", async () => {
    const { app } = await harness(true);

    const first = await request(app).post("/cases/seed-demo").send({ caseId: "attacker-picked" });
    expect(first.status).toBe(201);

    // Repeating with different names must not accumulate cases.
    for (const name of ["another-one", "and-another", "third"]) {
      await request(app).post("/cases/seed-demo").send({ caseId: name, force: true });
    }

    const ids = await caseIds(app);
    expect(ids).not.toContain("attacker-picked");
    expect(ids).not.toContain("another-one");
    expect(ids).not.toContain("third");
    expect(ids).toHaveLength(1); // the one default demo case, reseeded rather than duplicated
  });

  it("still honours an explicit caseId when demo mode is off", async () => {
    const { app } = await harness(false);

    const res = await request(app).post("/cases/seed-demo").send({ caseId: "chosen-name" });
    expect(res.status).toBe(201);
    expect(await caseIds(app)).toContain("chosen-name");
  });
});
