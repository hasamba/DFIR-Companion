// #2758 — archiving a case that is still open is refused (409, "close it first"). A refused
// request writes no archive, logs no custody event and leaves the case in the active list. A
// closed case archives as before. A plain encrypted export of an open case is not an archive and
// stays allowed; only its removeFromList form is refused.

import { describe, it, expect, vi } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";

const PASSWORD = "correct-horse-battery";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-archive-open-"));
  const store = new CaseStore(root);
  const recorded: string[] = [];
  const custodyStore = new CustodyStore(store);
  const realRecordExport = custodyStore.recordExport.bind(custodyStore);
  vi.spyOn(custodyStore, "recordExport").mockImplementation(async (caseId, opts) => {
    recorded.push(caseId);
    return realRecordExport(caseId, opts);
  });
  const app = createApp(store, { stateStore: new StateStore(store), custodyStore });
  return { app, store, root, recorded };
}

async function seedOpenCase(app: ReturnType<typeof createApp>, caseId: string) {
  const res = await request(app)
    .post("/cases")
    .send({ caseId, name: "Open case", investigator: "alice", aiProvider: "mock" });
  expect(res.status).toBe(201);
}

const zipFiles = async (root: string) => (await readdir(root)).filter((f) => f.endsWith(".zip"));

describe("archiving an open case is refused (#2758)", () => {
  for (const body of [{ removeFromList: true }, {}]) {
    it(`POST /cases/:id/archive ${JSON.stringify(body)} → 409, nothing written`, async () => {
      const { app, store, root, recorded } = await harness();
      await seedOpenCase(app, "c-open");
      const res = await request(app).post("/cases/c-open/archive").send(body);
      expect(res.status).toBe(409);
      expect(res.body.error).toMatch(/still open/i);
      expect(res.body.error).toMatch(/close it first/i);
      expect((await store.getCaseMeta("c-open"))?.status ?? "open").toBe("open");
      expect(store.isInArchive("c-open")).toBe(false);
      expect(await zipFiles(root)).toEqual([]);
      expect(recorded).toEqual([]);
    });
  }

  it("encrypted export with removeFromList of an open case → 409, case stays active", async () => {
    const { app, store, recorded } = await harness();
    await seedOpenCase(app, "c-enc");
    const res = await request(app)
      .post("/cases/c-enc/export/encrypted")
      .send({ password: PASSWORD, removeFromList: true });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/close it first/i);
    expect((await store.getCaseMeta("c-enc"))?.status ?? "open").toBe("open");
    expect(store.isInArchive("c-enc")).toBe(false);
    expect(recorded).toEqual([]);
  });

  it("a plain encrypted export of an open case is still allowed", async () => {
    const { app, store } = await harness();
    await seedOpenCase(app, "c-plain");
    const res = await request(app).post("/cases/c-plain/export/encrypted").send({ password: PASSWORD });
    expect(res.status).toBe(200);
    expect((await store.getCaseMeta("c-plain"))?.status ?? "open").toBe("open");
  });

  it("a closed case archives and leaves the list as before", async () => {
    const { app, store, recorded } = await harness();
    await seedOpenCase(app, "c-closed");
    expect((await request(app).patch("/cases/c-closed/status").send({ status: "closed" })).status).toBe(200);
    const res = await request(app).post("/cases/c-closed/archive").send({ removeFromList: true });
    expect(res.status).toBe(200);
    expect(res.body.removedFromList).toBe(true);
    expect((await store.getCaseMeta("c-closed"))?.status).toBe("archived");
    expect(recorded).toEqual(["c-closed"]);
  });
});
