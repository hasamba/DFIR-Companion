import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { huntHeldStoreFor } from "../../src/analysis/huntHeldStore.js";

// #2746: list held hunt files, record Import anyway / Skip. Synthetic values only.

const ID = "c".repeat(32);
const MEMBER = "WS-A-C.1/results/Hayabusa.json";

async function makeApp() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-held-routes-")));
  const app = createApp(store, {});
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await huntHeldStoreFor(store).put("c1", {
    ...{ archiveId: ID, relpath: "hunt.zip", size: 1, mtimeMs: 1, waiting: true },
    entries: [
      {
        member: MEMBER,
        artifact: "Hayabusa",
        host: "WS-A",
        bytes: 9,
        groupBytes: 9,
        reason: "host",
        limitMb: 50,
      },
    ],
  });
  return app;
}

describe("held hunt file routes (#2746)", () => {
  it("lists the held files with the limits in force", async () => {
    const res = await request(await makeApp()).get("/cases/c1/drop/held");
    expect(res.status).toBe(200);
    expect(res.body.limits).toEqual({ hostMb: 50, totalMb: 200 });
    expect(res.body.archives[0].entries[0]).toMatchObject({ member: MEMBER, reason: "host" });
  });

  it("records a decision and counts the ones that matched nothing", async () => {
    const app = await makeApp();
    const res = await request(app)
      .post("/cases/c1/drop/held/decide")
      .send({
        decisions: [
          { archiveId: ID, member: MEMBER, decision: "skip" },
          { archiveId: "d".repeat(32), member: MEMBER, decision: "import" },
        ],
      });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ updated: 1, ignored: 1 });
    const list = await request(app).get("/cases/c1/drop/held");
    expect(list.body.archives[0].entries[0].decision).toBe("skip");
  });

  it("400s a malformed body and 404s an unknown case", async () => {
    const app = await makeApp();
    for (const body of [
      {},
      { decisions: [] },
      { decisions: [{ archiveId: "x", member: MEMBER, decision: "import" }] },
      { decisions: [{ archiveId: ID, member: MEMBER, decision: "delete" }] },
    ])
      expect((await request(app).post("/cases/c1/drop/held/decide").send(body)).status).toBe(400);
    expect((await request(app).get("/cases/nope/drop/held")).status).toBe(404);
  });
});
