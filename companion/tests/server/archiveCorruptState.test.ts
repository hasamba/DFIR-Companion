import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";

// #2794: archiving, exporting or reporting a case whose investigation.sqlite is damaged answered a
// raw 500 "file is not a database". They now answer the same named 409 GET /cases/:id/state gives.

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-archive-corrupt-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "INC-1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  const app = createApp(store, { stateStore, reportWriter: new ReportWriter(store, stateStore) });
  expect((await request(app).patch("/cases/INC-1/status").send({ status: "closed" })).status).toBe(200);
  const stateDir = store.stateDir("INC-1");
  await mkdir(stateDir, { recursive: true });
  await writeFile(join(stateDir, "investigation.sqlite"), "this is not a sqlite database".repeat(200));
  vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
  return app;
}

function expectNamedCorrupt(res: request.Response) {
  expect(res.status).toBe(409);
  expect(res.body.code).toBe("state_file_corrupt");
  expect(res.body.file).toBe("investigation.sqlite");
  expect(res.body.error).toContain("INC-1");
  expect(JSON.stringify(res.body)).not.toMatch(/file is not a database|malformed|SQLITE_/i);
}

afterEach(() => vi.restoreAllMocks());

describe("archive / export / report of a case with a damaged database (#2794)", () => {
  it("ZIP archive answers the named 409", async () => {
    expectNamedCorrupt(
      await request(await harness())
        .post("/cases/INC-1/archive")
        .send({}),
    );
  });

  it("encrypted export answers the named 409", async () => {
    const res = await request(await harness())
      .post("/cases/INC-1/export/encrypted")
      .send({ password: "correct horse battery staple" });
    expectNamedCorrupt(res);
  });

  it("report generation answers the named 409", async () => {
    expectNamedCorrupt(
      await request(await harness())
        .post("/cases/INC-1/report")
        .send({}),
    );
  });
});
