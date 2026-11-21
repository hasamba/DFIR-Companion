import { describe, it, expect, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CaseFileVanishedError } from "../../src/analysis/caseArchiveSettle.js";

// #2795: a case folder that never settled while it was packaged is a retry-later condition, not a
// server fault — the archive routes answered it with a 500.
vi.mock("../../src/analysis/caseArchive.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/analysis/caseArchive.js")>();
  return {
    ...actual,
    archiveCase: async () => {
      throw new CaseFileVanishedError("notes/churn.txt");
    },
  };
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-archive-vanished-"));
  const store = new CaseStore(root);
  const app = createApp(store, { stateStore: new StateStore(store) });
  await request(app).post("/cases").send({ caseId: "INC-V", name: "n", investigator: "i", aiProvider: null });
  expect((await request(app).patch("/cases/INC-V/status").send({ status: "closed" })).status).toBe(200);
  return { app, store };
}

describe("archive of a case whose files keep changing (#2795)", () => {
  it("CaseFileVanishedError carries a retryable status", () => {
    expect(new CaseFileVanishedError("a.txt").httpStatus).toBe(503);
  });

  it("the ZIP archive answers 503 with the named, try-again message", async () => {
    const { app, store } = await harness();
    const res = await request(app).post("/cases/INC-V/archive").send({});
    expect(res.status).toBe(503);
    expect(res.body.code).toBe("DFIR_CASE_FILE_VANISHED");
    expect(res.body.error).toMatch(/notes\/churn\.txt.*try again/s);
    expect((await store.getCaseMeta("INC-V"))?.status).toBe("closed");
  });

  it("the delete-with-ZIP answers 503 and deletes nothing", async () => {
    const { app, store } = await harness();
    const res = await request(app).post("/cases/INC-V/delete").send({ archiveFirst: "zip" });
    expect(res.status).toBe(503);
    expect(await store.caseExists("INC-V")).toBe(true);
  });
});
