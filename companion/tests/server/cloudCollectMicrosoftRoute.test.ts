import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { QueryUsageStore } from "../../src/integrations/cloudCollect/collectBudget.js";
import { microsoftCollectProvider } from "../../src/integrations/cloudCollectMicrosoft/microsoftProvider.js";
import { makeCertPem, microsoftPemInput } from "../helpers/cloudAccountFixtures.js";
import { mockTenant } from "../helpers/microsoftCollectMocks.js";

// #2315: what the Collect panel is told about Microsoft — its sources, what it does NOT collect,
// and the tenant quota in the pre-check. Mocked tenant only.

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cloud-collect-ms-route-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

async function makeApp() {
  const cases = new CaseStore(join(dir, "cases"));
  await cases.createCase({ caseId: "c1", name: "Case", investigator: "i", aiProvider: null });
  const vault = new CloudAccountVault(
    join(dir, "cloud-accounts"),
    new VaultKeyFile(join(dir, "k", "vault.key")),
  );
  const tenant = mockTenant({});
  const microsoft = microsoftCollectProvider({ wire: () => ({ graph: tenant.call, arm: tenant.call }) });
  const app = createApp(cases, {
    cloudAccountVault: vault,
    cloudCollectProviders: { microsoft },
    cloudQueryUsage: new QueryUsageStore(join(dir, "cloud-quota", "query-usage.json")),
  });
  const account = vault.create(microsoftPemInput("Lab tenant", makeCertPem().pem), "c1").account;
  return { app, account, tenant };
}

describe("Microsoft in the Collect cloud logs panel (#2315)", () => {
  it("lists every source and says what is not collected and where to get it", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/cloud-collect");
    expect(res.status).toBe(200);
    const ms = res.body.providers.find((p: { provider: string }) => p.provider === "microsoft");
    expect(ms.available).toBe(true);
    expect(ms.sources.map((s: { id: string }) => s.id)).toEqual([
      "m365-ual",
      "entra-directory-audits",
      "entra-signins-interactive",
      "entra-signins-noninteractive",
      "entra-signins-serviceprincipal",
      "entra-signins-managedidentity",
      "azure-activity",
    ]);
    expect(ms.notes.join(" ")).toMatch(/mailbox audit, transport rules and message trace/);
    expect(ms.notes.join(" ")).toMatch(/MES/);
    expect(ms.notes.join(" ")).toMatch(/#2300/);
  });

  it("pre-checks the unified audit log against the tenant's query budget, sending nothing", async () => {
    const { app, account, tenant } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/cloud-collect/precheck")
      .send({
        accountId: account.id,
        sources: ["m365-ual", "entra-signins-interactive"],
        start: new Date(Date.now() - 2 * 86_400_000).toISOString(),
        end: new Date(Date.now() - 86_400_000).toISOString(),
      });
    expect(res.status, res.text).toBe(200);
    expect(res.body.quota).toMatchObject({ usedByCompanion: 0, estimatedQueries: 1, enough: true });
    expect(res.body.sources.map((s: { source: string }) => s.source)).toEqual([
      "m365-ual",
      "entra-signins-interactive",
    ]);
    expect(tenant.requests).toEqual([]);
  });
});
