import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
let artifactPath: string;

const custodyRecords = async () =>
  (await request(app).get("/cases/c1/custody")).body.records as Array<Record<string, unknown>>;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-custodyexportev-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, { custodyStore: new CustodyStore(cases) });
  // Goes through the auto-record hook, so the artifact is under custody as "collected".
  artifactPath = await cases.saveImport("c1", "0001_evidence.csv", "ts,message\n2026-01-01T00:00:00Z,hi\n");
});

describe("exported custody events", () => {
  it("records an export when the case is archived to a ZIP", async () => {
    const res = await request(app).post("/cases/c1/archive").send({});
    expect(res.status).toBe(200);

    const records = await custodyRecords();
    expect(records.map((r) => r.event)).toEqual(["collected", "exported"]);
    expect(records[1]).toMatchObject({ artifactPath, event: "exported", trigger: "export" });
  });

  it("records an export when the case leaves as an encrypted archive", async () => {
    const res = await request(app)
      .post("/cases/c1/export/encrypted")
      .send({ password: "a-long-enough-password" });
    expect(res.status).toBe(200);

    const records = await custodyRecords();
    expect(records.map((r) => r.event)).toEqual(["collected", "exported"]);
    expect(records[1]).toMatchObject({ artifactPath, event: "exported" });
  });

  it("leaves the chain intact after an export", async () => {
    await request(app).post("/cases/c1/archive").send({});

    const verify = await request(app).get("/cases/c1/custody/verify");
    expect(verify.body).toMatchObject({ ok: true, chainBreaks: [] });
  });

  it("records no export when the archive fails", async () => {
    const res = await request(app).post("/cases/nope/archive").send({});
    expect(res.status).toBe(404);

    expect((await custodyRecords()).map((r) => r.event)).toEqual(["collected"]);
  });
});
