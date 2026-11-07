import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
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
import type { CloudCollectProvider } from "../../src/integrations/cloudCollect/collectTypes.js";
import { awsKeyInput, fakeAwsSecret } from "../helpers/cloudAccountFixtures.js";
import { fakeSession } from "../helpers/cloudCollectFakes.js";
import { pollFor, pollBudget, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #2311: the collect routes — start, progress, resume with the credential re-opened, demo refusal.

let dir: string;
let logged: string[];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cloud-collect-route-"));
  logged = [];
  const logger = getServerLogger();
  const keep = (m: string): void => void logged.push(String(m));
  vi.spyOn(logger, "info").mockImplementation(keep);
  vi.spyOn(logger, "warn").mockImplementation(keep);
  vi.spyOn(logger, "debug").mockImplementation(keep);
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

function fakeProvider(state: { failPage?: number }): CloudCollectProvider & { opened: number } {
  const provider = {
    opened: 0,
    provider: "aws" as const,
    sources: [{ id: "ct", label: "CloudTrail", streamKind: "aws" as const }],
    open() {
      provider.opened++;
      return fakeSession({ pages: 2, ...(state.failPage !== undefined ? { failPage: state.failPage } : {}) });
    },
  };
  return provider;
}

async function makeApp(opts: { providers?: boolean; demo?: boolean; failPage?: number } = {}) {
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
  const state = { ...(opts.failPage !== undefined ? { failPage: opts.failPage } : {}) };
  const provider = fakeProvider(state);
  const jobManager = new JobManager();
  const app = createApp(cases, {
    stateStore,
    superTimelineStore,
    cloudRecordStore,
    pipeline,
    aiConfigured: false,
    cloudAccountVault: vault,
    jobManager,
    ...(opts.demo ? { demoMode: true } : {}),
    ...(opts.providers === false ? {} : { cloudCollectProviders: { aws: provider } }),
  });
  const secret = fakeAwsSecret();
  const account = opts.demo ? null : vault.create(awsKeyInput("Lab account", secret), "c1").account;
  return { app, cases, stateStore, jobManager, provider, state, account, secret };
}

const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-02T00:00:00Z" };

interface SettleWatch {
  jobManager: JobManager;
  jobId: string;
  /** The job attempt whose failure counts: 1 for a start, 2 after one resume (requeue increments). */
  attempt: number;
}

/** What the poll last saw, for a failure message that says where the job stopped (#2370). */
function settleReport(watch: SettleWatch, lastStatus: string | undefined): string {
  const job = watch.jobManager.get(watch.jobId);
  const failure = job?.failure ? JSON.stringify(job.failure) : (job?.error ?? "none");
  const tail = logged.filter((l) => /\[(cloud-collect|import|import-debug)\]/.test(l)).slice(-6);
  return (
    `checkpoint status ${lastStatus ?? "(no collection listed)"}; job ${job?.status ?? "missing"} ` +
    `attempt ${job?.attempt ?? "?"}, detail "${job?.detail ?? ""}", failure ${failure}; ` +
    `last log lines:\n  ${tail.join("\n  ") || "(none)"}`
  );
}

/**
 * Wait for the collection to reach one of `want`. Bounded: a real hang still fails, and the message
 * names the job's state and its last log lines (the logger is mocked, so nothing else would). A job
 * that FAILS on the watched attempt, when failing is not wanted, ends the wait at once instead of
 * spinning the whole budget (#2370: every Windows failure was the full 24 s, every pass under 1 s).
 */
async function settled(app: ReturnType<typeof createApp>, want: string[], watch: SettleWatch) {
  let lastStatus: string | undefined;
  return pollFor(
    () => `a collection reaching ${want.join("/")} — ${settleReport(watch, lastStatus)}`,
    async () => {
      const res = await request(app).get("/cases/c1/cloud-collect");
      const c = res.body.collections?.[0];
      lastStatus = c?.checkpoint.status;
      if (c && want.includes(c.checkpoint.status)) return c;
      const job = watch.jobManager.get(watch.jobId);
      if (!want.includes("failed") && job?.status === "failed" && job.attempt >= watch.attempt)
        throw new Error(`the collect job failed instead — ${settleReport(watch, lastStatus)}`);
      return null;
    },
    { timeoutMs: pollBudget(8_000) },
  );
}

describe("cloud collect routes (#2311)", () => {
  it("lists providers: an absent one says it is not available yet", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/cloud-collect");
    expect(res.status).toBe(200);
    const byId = Object.fromEntries(res.body.providers.map((p: { provider: string }) => [p.provider, p]));
    expect(byId.aws).toMatchObject({ available: true, sources: [{ id: "ct", label: "CloudTrail" }] });
    expect(byId.gcp).toMatchObject({ available: false, notice: expect.stringMatching(/#2314/) });
    expect(byId.microsoft.notice).toMatch(/#2315/);
    expect(res.body.collections).toEqual([]);
  });

  it(
    "starts a collection as a job: pages saved, imported, complete; no secret anywhere",
    async () => {
      const { app, cases, stateStore, account, secret, jobManager } = await makeApp();
      const res = await request(app)
        .post("/cases/c1/cloud-collect")
        .send({ accountId: account!.id, sources: ["ct"], ...WINDOW });
      expect(res.status).toBe(202);
      expect(res.body.collectionId).toMatch(/^cc-\d{8}t\d{6}-[a-f0-9]{8}$/);
      const c = await settled(app, ["complete"], { jobManager, jobId: res.body.jobId, attempt: 1 });
      expect(c.pages).toBe(2);
      expect(c.checkpoint.imported).toHaveLength(2);
      const state = await stateStore.load("c1");
      expect(state.forensicTimeline.some((e) => /StopLogging/.test(e.description))).toBe(true);
      const folder = join(cases.caseDir("c1"), "evidence", "cloud", res.body.collectionId);
      expect(readdirSync(join(folder, "pages")).sort()).toEqual(["p000001-ct.json", "p000002-ct.json"]);
      const manifest = readFileSync(join(folder, "manifest.jsonl"), "utf8");
      expect(manifest).not.toContain(secret);
      expect(JSON.stringify(c)).not.toContain(secret);
      expect(logged.join("\n")).not.toContain(secret);
      expect(logged.filter((l) => l.includes("cloud-account-collect"))).toHaveLength(1);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it("refuses bad input, unknown sources, and a provider that is not available", async () => {
    const { app, account } = await makeApp();
    const post = (body: object) => request(app).post("/cases/c1/cloud-collect").send(body);
    expect((await post({ sources: ["ct"], ...WINDOW })).status).toBe(400);
    expect(
      (await post({ accountId: account!.id, sources: ["ct"], start: WINDOW.end, end: WINDOW.start })).status,
    ).toBe(400);
    expect((await post({ accountId: account!.id, sources: ["nope"], ...WINDOW })).status).toBe(400);
    expect((await post({ accountId: "missing", sources: ["ct"], ...WINDOW })).status).toBe(404);
    const bare = await makeApp({ providers: false });
    const res = await request(bare.app)
      .post("/cases/c1/cloud-collect")
      .send({ accountId: bare.account!.id, sources: ["ct"], ...WINDOW });
    expect(res.status).toBe(501);
    expect(res.body.error).toMatch(/not available in this version yet \(#2313\)/);
    expect(logged.some((l) => l.includes("cloud-account-collect"))).toBe(false); // no credential opened
  });

  it(
    "a failed collection resumes only through its own route, which opens the credential again",
    async () => {
      const { app, account, provider, state, jobManager } = await makeApp({ failPage: 0 });
      const res = await request(app)
        .post("/cases/c1/cloud-collect")
        .send({ accountId: account!.id, sources: ["ct"], ...WINDOW });
      const watch = { jobManager, jobId: res.body.jobId, attempt: 1 };
      const failed = await settled(app, ["failed"], watch);
      expect(failed.checkpoint.missing[0].reason).toMatch(/AccessDenied/);
      const job = await pollFor("the collect job failing", async () => {
        const j = jobManager.get(res.body.jobId);
        return j?.status === "failed" ? j : null;
      });
      expect(job.failure?.retryable).toBe(true);
      const generic = await request(app).post(`/api/jobs/${res.body.jobId}/resume`);
      expect(generic.status).toBe(409);
      expect(generic.body.error).toMatch(/Cloud collection panel/);
      delete state.failPage;
      provider.open = () => {
        provider.opened++;
        return fakeSession({ pages: 2 });
      };
      const resumed = await request(app).post(`/cases/c1/cloud-collect/${res.body.collectionId}/resume`);
      expect(resumed.status).toBe(202);
      expect(resumed.body.jobId).toBe(res.body.jobId);
      const done = await settled(app, ["complete"], { ...watch, attempt: 2 });
      expect(done.checkpoint.imported).toHaveLength(2);
      expect(provider.opened).toBe(2);
      expect(logged.filter((l) => l.includes("cloud-account-collect"))).toHaveLength(2);
      const again = await request(app).post(`/cases/c1/cloud-collect/${res.body.collectionId}/resume`);
      expect(again.status).toBe(409);
    },
    POLL_TIMEOUT_MS * 4,
  );

  it("is refused on the public demo", async () => {
    const { app } = await makeApp({ demo: true });
    expect((await request(app).get("/cases/c1/cloud-collect")).status).toBe(403);
    expect((await request(app).post("/cases/c1/cloud-collect").send({})).status).toBe(403);
  });
});
