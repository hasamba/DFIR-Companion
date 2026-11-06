import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { QueryUsageStore } from "../../src/integrations/cloudCollect/collectBudget.js";
import { RETENTION } from "../../src/integrations/cloudCollect/collectDefaults.js";
import type { CloudCollectProvider } from "../../src/integrations/cloudCollect/collectTypes.js";
import { awsKeyInput, fakeAwsSecret } from "../helpers/cloudAccountFixtures.js";
import { fakeSession } from "../helpers/cloudCollectFakes.js";

// #2312: the pre-check route — retention, overlap and this companion's quota use before a start —
// and a start refused when the tenant budget is already used.

let dir: string;
let logged: string[];
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cloud-precheck-route-"));
  logged = [];
  const logger = getServerLogger();
  const keep = (m: string): void => void logged.push(String(m));
  vi.spyOn(logger, "info").mockImplementation(keep);
  vi.spyOn(logger, "warn").mockImplementation(keep);
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

const SCOPE = "microsoft:00000000-0000-4000-a000-000000000002";

async function makeApp(opts: { demo?: boolean } = {}) {
  const cases = new CaseStore(join(dir, "cases"));
  await cases.createCase({ caseId: "c1", name: "Case", investigator: "i", aiProvider: null });
  const vault = new CloudAccountVault(
    join(dir, "cloud-accounts"),
    new VaultKeyFile(join(dir, "k", "vault.key")),
  );
  const provider: CloudCollectProvider = {
    provider: "aws",
    sources: [
      {
        id: "ual",
        label: "Audit log",
        streamKind: "aws",
        queryCost: 1,
        overlapMs: 3_600_000,
        retention: RETENTION.unifiedAuditLog,
      },
      { id: "entra", label: "Sign-ins", streamKind: "aws", retention: RETENTION.entra },
    ],
    open: () => fakeSession({ pages: 1 }),
    quotaScope: () => SCOPE,
  };
  const usage = new QueryUsageStore(join(dir, "cloud-quota", "query-usage.json"));
  const app = createApp(cases, {
    aiConfigured: false,
    cloudAccountVault: vault,
    jobManager: new JobManager(),
    cloudCollectProviders: { aws: provider },
    cloudQueryUsage: usage,
    cloudQueryBudget: 4,
    ...(opts.demo ? { demoMode: true } : {}),
  });
  const account = opts.demo ? null : vault.create(awsKeyInput("Lab", fakeAwsSecret()), "c1").account;
  return { app, account, usage };
}

const day = 86_400_000;
const window = () => ({
  start: new Date(Date.now() - 40 * day).toISOString(),
  end: new Date(Date.now()).toISOString(),
});

describe("cloud collect pre-check (#2312)", () => {
  it("shows retention, the overlap and this companion's quota use — no credential opened", async () => {
    const { app, account, usage } = await makeApp();
    await usage.tryReserve(SCOPE, 1, 100);
    const res = await request(app)
      .post("/cases/c1/cloud-collect/precheck")
      .send({ accountId: account!.id, sources: ["ual", "entra"], ...window() });
    expect(res.status).toBe(200);
    const [ual, entra] = res.body.sources;
    expect(ual.overlapMs).toBe(3_600_000);
    expect(ual.warnings.join(" ")).toMatch(/may still be arriving/);
    expect(entra.outOfRetention).toBeDefined();
    expect(entra.warnings.join(" ")).toMatch(/Outside retention \(7–30 days\)/);
    expect(res.body.quota).toMatchObject({
      usedByCompanion: 1,
      budget: 4,
      estimatedQueries: 1,
      enough: true,
    });
    expect(res.body.quota.note).toMatch(/Used by this companion \(estimate\)/);
    expect(res.body.quota.note).toMatch(/2N−1/);
    expect(JSON.stringify(res.body)).not.toMatch(/remaining/i);
    expect(logged.some((l) => l.includes("cloud-account-collect"))).toBe(false);
  });

  it("an analyst overlap replaces the defaults; a bad one is refused", async () => {
    const { app, account } = await makeApp();
    const post = (extra: object) =>
      request(app)
        .post("/cases/c1/cloud-collect/precheck")
        .send({ accountId: account!.id, sources: ["entra"], ...window(), ...extra });
    expect((await post({ overlapMinutes: 30 })).body.sources[0].overlapMs).toBe(1_800_000);
    expect((await post({ overlapMinutes: -1 })).status).toBe(400);
    expect((await post({ sources: [] })).status).toBe(400);
  });

  it("refuses a start when the tenant budget is used up", async () => {
    const { app, account, usage } = await makeApp();
    await usage.tryReserve(SCOPE, 4, 4);
    const res = await request(app)
      .post("/cases/c1/cloud-collect")
      .send({ accountId: account!.id, sources: ["ual"], ...window() });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/partial — budget used: this companion has used 4 of its 4/);
  });

  it("an unreadable quota record fails closed: the pre-check says so and a start is refused", async () => {
    const { app, account } = await makeApp();
    mkdirSync(join(dir, "cloud-quota"), { recursive: true });
    writeFileSync(join(dir, "cloud-quota", "query-usage.json"), "{not json");
    const body = { accountId: account!.id, sources: ["ual"], ...window() };
    const check = await request(app).post("/cases/c1/cloud-collect/precheck").send(body);
    expect(check.body.quota).toMatchObject({ enough: false });
    expect(check.body.quota.note).toMatch(
      /quota record unreadable at .*query-usage\.json — check or remove it/,
    );
    const start = await request(app).post("/cases/c1/cloud-collect").send(body);
    expect(start.status).toBe(409);
    expect(start.body.error).toMatch(/check or remove it/);
  });

  it("is refused on the public demo", async () => {
    const { app } = await makeApp({ demo: true });
    expect((await request(app).post("/cases/c1/cloud-collect/precheck").send({})).status).toBe(403);
  });
});
