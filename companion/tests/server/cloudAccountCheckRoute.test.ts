import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import type { CheckClientFactory } from "../../src/integrations/cloudCheck/checkClients.js";
import { MINIMUM_POLICIES } from "../../src/integrations/cloudCheck/minimumPolicies.js";
import {
  runCloudAccountCheck,
  type CloudCheckRunner,
} from "../../src/integrations/cloudCheck/runCloudCheck.js";
import {
  awsKeyInput,
  fakeAwsSecret,
  makeCertPem,
  makePfxBase64InMemory,
  microsoftPemInput,
} from "../helpers/cloudAccountFixtures.js";
import { AWS_ALL_OK, awsDenied, mockAws, mockGraph } from "../integrations/cloudCheck/readCheckMocks.js";

// #2309: POST /cases/:id/cloud-accounts/:accountId/check — one read per source, the fixed wording,
// no secret in any answer or log line, the same case gate as collection, and refused on the demo.

let dir: string;
let vault: CloudAccountVault;
let cases: CaseStore;
let logged: string[];
let sentinels: string[];
let sent: string[];

function secret(): string {
  const s = fakeAwsSecret();
  sentinels.push(s);
  return s;
}

function expectNoSecret(text: string, where: string): void {
  for (const s of sentinels) expect(text, `${where} carried a secret`).not.toContain(s);
}

/** A runner over mocked AWS clients whose LookupEvents error echoes the account's secret key. */
function mockedRunner(): CloudCheckRunner {
  return (account, req) => {
    const echo = account.provider === "aws" ? String(account.secrets.secretAccessKey) : "";
    const { clients, sent: calls } = mockAws({
      ...AWS_ALL_OK,
      LookupEventsCommand: awsDenied("AccessDenied", `key ${echo}`),
    });
    sent = calls;
    const factory = { aws: () => clients } as unknown as CheckClientFactory;
    return runCloudAccountCheck(account, req, () => factory);
  };
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "cloud-check-route-"));
  vault = new CloudAccountVault(join(dir, "cloud-accounts"), new VaultKeyFile(join(dir, "k", "vault.key")));
  cases = new CaseStore(join(dir, "cases"));
  for (const id of ["c1", "c2"])
    await cases.createCase({ caseId: id, name: `Case ${id}`, investigator: "i", aiProvider: null });
  logged = [];
  sentinels = [];
  sent = [];
  const logger = getServerLogger();
  const keep = (m: string): void => void logged.push(String(m));
  vi.spyOn(logger, "info").mockImplementation(keep);
  vi.spyOn(logger, "warn").mockImplementation(keep);
  vi.spyOn(logger, "error").mockImplementation(keep);
  vi.spyOn(logger, "debug").mockImplementation(keep);
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

describe("POST /cases/:id/cloud-accounts/:accountId/check", () => {
  it("reports per source with the fixed wording, and leaks no secret", async () => {
    const id = vault.create(awsKeyInput("Prod", secret()), "c1").account.id;
    const app = createApp(cases, { cloudAccountVault: vault, cloudCheck: mockedRunner() });
    const res = await request(app)
      .post(`/cases/c1/cloud-accounts/${id}/check`)
      .send({ sources: ["cloudtrail-lookup", "s3-trail"], s3Bucket: "trail-bucket" });
    expect(res.status, res.text).toBe(200);
    expect(res.body.report.results.map((r: { status: string }) => r.status)).toEqual(["failed", "succeeded"]);
    expect(res.body.report.summary).toBe(
      "Tested reads succeeded for: CloudTrail S3 bucket. Failed: CloudTrail event history (HTTP 403 AccessDenied: " +
        "key [redacted]). The companion did not test whether this identity can also write. Use the minimum policy.",
    );
    expect(res.text).not.toMatch(/read-only|verified/i);
    expect(sent).toEqual([
      "GetCallerIdentityCommand",
      "LookupEventsCommand",
      "ListObjectsV2Command",
      "GetObjectCommand",
    ]);
    expectNoSecret(res.text, "check response");
    expectNoSecret(logged.join("\n"), "server log");
    expect(logged.some((l) => l.includes("cloud-account-check") && l.includes('case="c1"'))).toBe(true);
  });

  it("checks a PFX account by opening it in memory, and leaks neither the PFX nor its password", async () => {
    const password = secret();
    const pfxBase64 = makePfxBase64InMemory(makeCertPem().pem, password);
    sentinels.push(pfxBase64);
    const input = microsoftPemInput("Tenant", "");
    const id = vault.create(
      {
        ...input,
        settings: { ...input.settings, certificateFormat: "pfx" },
        secrets: { pfxBase64, pfxPassword: password },
      },
      "c1",
    ).account.id;
    const pems: string[] = [];
    // Sign-ins answer; directory audits are refused (an unlisted path answers 403).
    const { clients } = mockGraph({ "/v1.0/auditLogs/signIns": { status: 200 } });
    const runner: CloudCheckRunner = (account, req) =>
      runCloudAccountCheck(
        account,
        req,
        () =>
          ({
            microsoft: (_s: unknown, pem: string) => (pems.push(pem), clients),
          }) as unknown as CheckClientFactory,
      );
    const app = createApp(cases, { cloudAccountVault: vault, cloudCheck: runner });
    const res = await request(app).post(`/cases/c1/cloud-accounts/${id}/check`).send({});
    expect(res.status, res.text).toBe(200);
    expect(res.body.report.results.map((r: { status: string }) => r.status)).toEqual(["succeeded", "failed"]);
    expect(pems).toHaveLength(1);
    expect(res.text).not.toMatch(/not tested/i);
    expectNoSecret(res.text, "pfx check");
    expectNoSecret(logged.join("\n"), "pfx server log");
  });

  it("refuses an unknown source with 400 and opens nothing", async () => {
    const id = vault.create(awsKeyInput("Prod", secret()), "c1").account.id;
    const runner = vi.fn(mockedRunner());
    const app = createApp(cases, { cloudAccountVault: vault, cloudCheck: runner });
    const res = await request(app)
      .post(`/cases/c1/cloud-accounts/${id}/check`)
      .send({ sources: ["entra-signins"] });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("Valid: cloudtrail-lookup, s3-trail");
    expect(runner).not.toHaveBeenCalled();
    expect(logged.some((l) => l.includes("cloud-account-check"))).toBe(false);
  });

  it("answers 404 from a case the account is not attached to", async () => {
    const id = vault.create(awsKeyInput("Prod", secret()), "c1").account.id;
    const runner = vi.fn(mockedRunner());
    const app = createApp(cases, { cloudAccountVault: vault, cloudCheck: runner });
    expect((await request(app).post(`/cases/c2/cloud-accounts/${id}/check`).send({})).status).toBe(404);
    expect((await request(app).post(`/cases/c1/cloud-accounts/nope/check`).send({})).status).toBe(404);
    expect(runner).not.toHaveBeenCalled();
  });

  it("answers 503 when no check runner is wired", async () => {
    const id = vault.create(awsKeyInput("Prod", secret()), "c1").account.id;
    const res = await request(createApp(cases, { cloudAccountVault: vault })).post(
      `/cases/c1/cloud-accounts/${id}/check`,
    );
    expect(res.status).toBe(503);
  });

  it("is refused on the public demo", async () => {
    const id = vault.create(awsKeyInput("Demo", secret()), "c1").account.id;
    const runner = vi.fn(mockedRunner());
    const app = createApp(cases, { cloudAccountVault: vault, cloudCheck: runner, demoMode: true });
    const res = await request(app).post(`/cases/c1/cloud-accounts/${id}/check`).send({});
    expect(res.status).toBe(403);
    expect(runner).not.toHaveBeenCalled();
  });
});

describe("the minimum policies in the account lists", () => {
  it("come with the case list and the administrator's list", async () => {
    const app = createApp(cases, { cloudAccountVault: vault });
    const inCase = await request(app).get("/cases/c1/cloud-accounts");
    expect(inCase.body.minimumPolicies).toEqual(JSON.parse(JSON.stringify(MINIMUM_POLICIES)));
    const all = await request(app).get("/cloud-accounts");
    expect(all.body.minimumPolicies.aws.grant).toContain("cloudtrail:LookupEvents");
  });
});
