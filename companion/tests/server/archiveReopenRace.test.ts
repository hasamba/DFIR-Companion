import { describe, it, expect } from "vitest";
import { mkdtemp, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { CustodyStore } from "../../src/analysis/custody.js";

// #2786: a case reopened while its archive was being built must not end up archived while open.
// The custody hook runs after the archive is built and before the case leaves the list — exactly
// the window an analyst's Reopen can land in — so it stands in for that Reopen here.
async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-archive-reopen-"));
  const store = new CaseStore(root);
  class ReopenDuringBuild extends CustodyStore {
    override async recordExport(...args: Parameters<CustodyStore["recordExport"]>) {
      const recorded = await super.recordExport(...args);
      await store.setCaseStatus(args[0], "open");
      return recorded;
    }
  }
  const app = createApp(store, {
    stateStore: new StateStore(store),
    commentsStore: new CommentsStore(store),
    custodyStore: new ReopenDuringBuild(store),
  });
  await request(app)
    .post("/cases")
    .send({ caseId: "INC-R", name: "Race", investigator: "a", aiProvider: "anthropic" });
  expect((await request(app).patch("/cases/INC-R/status").send({ status: "closed" })).status).toBe(200);
  return { app, store };
}

describe("archive vs a reopen during the build (#2786)", () => {
  it("refuses the ZIP archive with 409 and keeps the reopened case open in the active list", async () => {
    const { app, store } = await harness();
    const res = await request(app).post("/cases/INC-R/archive").send({ removeFromList: true });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/reopened/);
    expect(res.body.removedFromList).toBe(false);
    expect((await store.getCaseMeta("INC-R"))?.status).toBe("open");
    expect((await stat(join(store.casesRoot, "INC-R", "case.json"))).isFile()).toBe(true);
  });

  it("keeps the reopened case open after an encrypted export with removeFromList", async () => {
    const { app, store } = await harness();
    const res = await request(app)
      .post("/cases/INC-R/export/encrypted")
      .send({ password: "correct horse battery staple", removeFromList: true });
    expect(res.status).toBe(200);
    expect(res.headers["x-case-removed-from-list"]).toBe("false");
    expect(res.headers["x-case-remove-error"]).toBe("case-reopened");
    expect((await store.getCaseMeta("INC-R"))?.status).toBe("open");
  });
});
