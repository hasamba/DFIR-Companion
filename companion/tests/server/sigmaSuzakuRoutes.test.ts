import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { bundledSigmaDir } from "../../src/analysis/sigmaBundledRules.js";
import { SigmaRuleStore } from "../../src/analysis/sigmaRuleStore.js";
import { bundledSuzakuDir } from "../../src/analysis/sigmaSuzakuRules.js";
import { SuzakuRuleStore } from "../../src/analysis/suzakuRuleStore.js";

// Settings → Sigma rules → Suzaku routes (#2508). Nothing here touches the network: the check and
// download are covered with a fake GitHub in tests/analysis/suzakuRuleStore.test.ts.

let store: CaseStore;
let sigma: SigmaRuleStore;
let suzaku: SuzakuRuleStore;

beforeEach(async () => {
  const dir = await mkdtemp(join(tmpdir(), "dfir-suzaku-routes-"));
  store = new CaseStore(join(dir, "cases"));
  setServerLogger(createConsoleLogger("error"));
  suzaku = new SuzakuRuleStore(dir, bundledSuzakuDir());
  await suzaku.init();
  sigma = new SigmaRuleStore(dir, bundledSigmaDir(), {}, suzaku);
  await sigma.init();
});

const app = (opts: Record<string, unknown> = {}) =>
  createApp(store, {
    stateStore: new StateStore(store),
    sigmaRuleStore: sigma,
    suzakuRuleStore: suzaku,
    ...opts,
  });

describe("Suzaku rule update routes", () => {
  it("reports the Suzaku version in effect in /sigma/status", async () => {
    const res = await request(app()).get("/sigma/status");
    expect(res.status).toBe(200);
    expect(res.body.settings.suzaku).toMatchObject({
      enabled: true,
      active: { id: "bundled", release: "suzaku-2026-11-01", source: "bundled" },
      previous: null,
      lastCheck: null,
    });
  });

  it("refuses an install without a live preview", async () => {
    const res = await request(app()).post("/sigma/suzaku/install").send({ token: "nope" });
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/preview is gone/);
    expect((await request(app()).post("/sigma/suzaku/install").send({})).status).toBe(400);
  });

  it("refuses a roll back with nothing to roll back to", async () => {
    const res = await request(app()).post("/sigma/suzaku/rollback").send({});
    expect(res.status).toBe(409);
  });

  it("answers 501 when the server has no Suzaku store", async () => {
    const res = await request(app({ suzakuRuleStore: undefined }))
      .post("/sigma/suzaku/rollback")
      .send({});
    expect(res.status).toBe(501);
  });
});
