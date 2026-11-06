import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { CloudAccountVault } from "../../src/integrations/cloudAccounts/cloudAccountVault.js";
import { VaultKeyFile } from "../../src/integrations/cloudAccounts/vaultKeyFile.js";
import { createAwsCollectProvider } from "../../src/integrations/cloudCollect/aws/awsCollectProvider.js";
import type { CloudCollectProvider } from "../../src/integrations/cloudCollect/collectTypes.js";
import { awsKeyInput, fakeAwsSecret } from "../helpers/cloudAccountFixtures.js";
import { fakeAwsClients, recordJson, type FakeAwsOptions, type Sent } from "../helpers/awsCollectFakes.js";
import { fakeSession } from "../helpers/cloudCollectFakes.js";
import { pollFor, pollBudget, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #2363: the region picker's route, and the start / pre-check / resume of an AWS collection with a
// region choice — through the real AWS provider on scripted AWS fakes (no real AWS is reached).

let dir: string;
let logged: string[];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cloud-regions-route-"));
  logged = [];
  const logger = getServerLogger();
  const keep = (m: string): void => void logged.push(String(m));
  vi.spyOn(logger, "info").mockImplementation(keep);
  vi.spyOn(logger, "warn").mockImplementation(keep);
  vi.spyOn(logger, "debug").mockImplementation(keep);
  vi.spyOn(logger, "error").mockImplementation(keep);
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

const ENABLED = [
  { RegionName: "eu-west-1", OptInStatus: "opt-in-not-required" },
  { RegionName: "us-east-1", OptInStatus: "opt-in-not-required" },
  { RegionName: "af-south-1", OptInStatus: "opted-in" },
];
const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-01T06:00:00Z" };

async function makeApp(opts: { aws?: FakeAwsOptions; provider?: CloudCollectProvider; demo?: boolean } = {}) {
  const root = mkdtempSync(join(dir, "app-"));
  const cases = new CaseStore(join(root, "cases"));
  await cases.createCase({ caseId: "c1", name: "Case", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const superTimelineStore = new SuperTimelineStore(cases);
  const cloudRecordStore = new CloudRecordStore(cases);
  const pipeline = new AnalysisPipeline({
    stateStore,
    superTimelineStore,
    cloudRecordStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const vault = new CloudAccountVault(
    join(root, "cloud-accounts"),
    new VaultKeyFile(join(root, "k", "vault.key")),
  );
  const scripted: FakeAwsOptions = opts.aws ?? { trails: [], buckets: {}, enabledRegions: ENABLED };
  const made: Sent[][] = [];
  const sent = (): Sent[] => made.flat();
  const awsProvider = createAwsCollectProvider({
    transport: () => {
      throw new Error("no transport in a mocked test");
    },
    // A fresh set of fakes per opened session (start, resume), all recorded into one list.
    clients: () => {
      const c = fakeAwsClients(scripted);
      made.push(c.sent);
      return c;
    },
  });
  const app = createApp(cases, {
    stateStore,
    superTimelineStore,
    cloudRecordStore,
    pipeline,
    aiConfigured: false,
    cloudAccountVault: vault,
    jobManager: new JobManager(),
    ...(opts.demo ? { demoMode: true } : {}),
    cloudCollectProviders: { aws: opts.provider ?? awsProvider },
  });
  const account = opts.demo ? null : vault.create(awsKeyInput("Lab account", fakeAwsSecret()), "c1").account;
  return { app, cases, account, sent, scripted };
}

async function settled(app: ReturnType<typeof createApp>, want: string[]) {
  return pollFor(
    `a collection reaching ${want.join("/")}`,
    async () => {
      const res = await request(app).get("/cases/c1/cloud-collect");
      const c = res.body.collections?.[0];
      return c && want.includes(c.checkpoint.status) ? c : null;
    },
    { timeoutMs: pollBudget(8_000) },
  );
}

const lookupRegionsSent = (sent: Sent[]) => [
  ...new Set(sent.filter((c) => c.op === "LookupEvents").map((c) => c.region)),
];

describe("the region picker route (#2363)", () => {
  it("lists the regions enabled on the account, opt-in included, and audits the sign-in", async () => {
    const { app, account } = await makeApp();
    const res = await request(app).post("/cases/c1/cloud-collect/regions").send({ accountId: account!.id });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      regions: ["eu-west-1", "af-south-1", "us-east-1"],
      home: "eu-west-1",
      source: "ec2:DescribeRegions",
    });
    expect(logged.some((l) => l.includes("cloud-account-regions") && l.includes('case="c1"'))).toBe(true);
    expect(JSON.stringify(res.body)).not.toMatch(/secret/i);
  });

  it("without ec2:DescribeRegions answers with the default list and the disclosure", async () => {
    const { app, account } = await makeApp({ aws: { trails: [], buckets: {}, enabledRegions: "denied" } });
    const res = await request(app).post("/cases/c1/cloud-collect/regions").send({ accountId: account!.id });
    expect(res.status).toBe(200);
    expect(res.body.source).toBe("fallback");
    expect(res.body.regions).toContain("us-west-2");
    expect(res.body.note).toMatch(/could not be listed \(UnauthorizedOperation \(HTTP 403\)\)/);
  });

  it("a provider without a picker answers 501 and opens no credential", async () => {
    const plain: CloudCollectProvider = {
      provider: "aws",
      sources: [{ id: "ct", label: "CloudTrail", streamKind: "aws" }],
      open: () => fakeSession({ pages: 1 }),
    };
    const { app, account } = await makeApp({ provider: plain });
    const res = await request(app).post("/cases/c1/cloud-collect/regions").send({ accountId: account!.id });
    expect(res.status).toBe(501);
    expect(logged.some((l) => l.includes("cloud-account-regions"))).toBe(false);
    const start = await request(app)
      .post("/cases/c1/cloud-collect")
      .send({ accountId: account!.id, sources: ["ct"], ...WINDOW, regions: ["eu-west-1"] });
    expect(start.status).toBe(400);
    expect(start.body.error).toMatch(/only be picked for an AWS account/);
  });

  it("an unknown account is 404 and the provider list says AWS has a picker", async () => {
    const { app } = await makeApp();
    expect(
      (await request(app).post("/cases/c1/cloud-collect/regions").send({ accountId: "nope" })).status,
    ).toBe(404);
    const list = await request(app).get("/cases/c1/cloud-collect");
    const aws = list.body.providers.find((p: { provider: string }) => p.provider === "aws");
    expect(aws.regionPicker).toBe(true);
  });

  it("is refused on the public demo", async () => {
    const { app } = await makeApp({ demo: true });
    expect((await request(app).post("/cases/c1/cloud-collect/regions").send({ accountId: "a" })).status).toBe(
      403,
    );
  });
});

describe("starting with a region choice (#2363)", () => {
  it("refuses a bad choice at the start and at the pre-check", async () => {
    const { app, account } = await makeApp();
    const body = { accountId: account!.id, sources: ["cloudtrail-lookup"], ...WINDOW };
    for (const bad of [{ regions: [] }, { regions: ["eu-west-1;rm"] }, { excludeRegions: "us-east-1" }]) {
      expect(
        (
          await request(app)
            .post("/cases/c1/cloud-collect")
            .send({ ...body, ...bad })
        ).status,
      ).toBe(400);
      expect(
        (
          await request(app)
            .post("/cases/c1/cloud-collect/precheck")
            .send({ ...body, ...bad })
        ).status,
      ).toBe(400);
    }
    const ok = await request(app)
      .post("/cases/c1/cloud-collect/precheck")
      .send({ ...body, regions: ["eu-west-1"], excludeRegions: ["us-east-1"] });
    expect(ok.status).toBe(200);
    expect(logged.some((l) => l.includes("cloud-account-"))).toBe(false); // the pre-check opens nothing
  });

  it(
    "walks the ticked regions, records the scope in the header, names what was skipped; resume keeps it",
    async () => {
      const { app, cases, account, sent, scripted } = await makeApp({
        aws: {
          trails: [],
          buckets: {},
          enabledRegions: ENABLED,
          lookup: { "af-south-1": [[recordJson(1)]], "eu-west-1": [[recordJson(2)]] },
          lookupDnsFail: { region: "af-south-1", page: 0, times: 1 },
        },
      });
      const res = await request(app)
        .post("/cases/c1/cloud-collect")
        .send({
          accountId: account!.id,
          sources: ["cloudtrail-lookup"],
          ...WINDOW,
          regions: ["eu-west-1", "af-south-1"],
          excludeRegions: ["us-east-1"],
        });
      expect(res.status).toBe(202);
      const first = await settled(app, ["partial", "failed"]);
      expect(first.header.filters).toMatchObject({
        regions: "eu-west-1,af-south-1",
        regionsSkippedByChoice: "us-east-1",
        regionList: "ec2:DescribeRegions",
      });
      expect(lookupRegionsSent(sent())).toEqual(["eu-west-1", "af-south-1"]);
      const manifest = readFileSync(
        join(cases.caseDir("c1"), "evidence", "cloud", res.body.collectionId, "manifest.jsonl"),
        "utf8",
      );
      expect(JSON.parse(manifest.split("\n")[0]).filters.regionsSkippedByChoice).toBe("us-east-1");

      // The account now lists one more region: the resume must not pick it up, nor list again.
      scripted.enabledRegions = [...ENABLED, { RegionName: "us-west-2" }];
      const listedBefore = sent().filter((c) => c.op === "DescribeRegions").length;
      const resumed = await request(app).post(`/cases/c1/cloud-collect/${res.body.collectionId}/resume`);
      expect(resumed.status).toBe(202);
      const done = await settled(app, ["complete"]);
      expect(sent().filter((c) => c.op === "DescribeRegions").length).toBe(listedBefore);
      expect(lookupRegionsSent(sent())).toEqual(["eu-west-1", "af-south-1"]);
      const notes = done.checkpoint.coverage.find(
        (c: { source: string }) => c.source === "cloudtrail-lookup",
      ).notes;
      expect(notes.join("\n")).toMatch(/skipped by choice \(unticked\): us-east-1/);
    },
    POLL_TIMEOUT_MS * 4,
  );

  it(
    "without the permission the start falls back and the header and result say so",
    async () => {
      const { app, account } = await makeApp({
        aws: {
          trails: [],
          buckets: {},
          enabledRegions: "denied",
          lookup: { "eu-west-1": [[recordJson(1)]] },
        },
      });
      const res = await request(app)
        .post("/cases/c1/cloud-collect")
        .send({ accountId: account!.id, sources: ["cloudtrail-lookup"], ...WINDOW });
      expect(res.status).toBe(202);
      const done = await settled(app, ["complete", "partial"]);
      expect(done.header.filters.regionList).toBe("fallback");
      expect(done.header.filters.regionListReason).toBe("UnauthorizedOperation (HTTP 403)");
      const notes = done.checkpoint.coverage[0].notes.join("\n");
      expect(notes).toMatch(
        /could not be listed \(UnauthorizedOperation \(HTTP 403\)\) — grant ec2:DescribeRegions/,
      );
    },
    POLL_TIMEOUT_MS * 4,
  );
});
