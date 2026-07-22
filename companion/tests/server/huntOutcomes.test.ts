import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import type { Express } from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { HuntOutcomeStore } from "../../src/analysis/huntOutcomeStore.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";
import { HuntRunSnapshotStore } from "../../src/analysis/huntRunSnapshotStore.js";
import { recordDeploy, vqlFingerprint } from "../../src/analysis/huntOutcomes.js";
import { MockProvider } from "../../src/providers/provider.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { VelociraptorClient, type VqlRunner, type VelociraptorApiConfig } from "../../src/integrations/velociraptor/velociraptorApi.js";

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml", binary: "velociraptor", timeoutMs: 5000, maxRows: 1000, maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

// Mock velociraptor binary: launchHunt's program contains `hunt(...artifacts='...')` → return a hunt id;
// hunt_results(...) → one generic row so the collect imports an event (a "hit"). Everything else empty.
const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("hunt(") && p.includes("artifacts=")) return { rows: [{ Hunt: { HuntId: "H.DEPLOY1", state: "RUNNING" } }], raw: "" };
  if (p.includes("hunt_results(")) return { rows: [{ Message: "suspicious thing", Timestamp: "2026-06-01T10:00:00Z" }], raw: "" };
  return { rows: [], raw: "" };
};

async function makeApp(opts: { provider?: MockProvider; runner?: VqlRunner; withVelo?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-huntoutcomes-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const provider = opts.provider;
  const pipeline = buildRuntimePipeline({
    provider, synthesisProvider: provider, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const huntOutcomeStore = new HuntOutcomeStore(store);
  const huntRunSnapshotStore = new HuntRunSnapshotStore(store);
  const app = createApp(store, {
    pipeline, stateStore,
    importMetaStore: new ImportMetaStore(store),
    veloHuntStore: new VeloHuntStore(store),
    huntOutcomeStore,
    huntRunSnapshotStore,
    aiConfigured: Boolean(provider),
    ...(opts.withVelo === false ? {} : { velociraptorClient: new VelociraptorClient(veloCfg, opts.runner ?? runner) }),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: provider ? "mock" : null });
  return { app, stateStore, store, huntOutcomeStore };
}

describe("hunting feedback loop — routes (#157)", () => {
  it("deploy-hunt (fleet) launches a hunt and records a pending outcome", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/cases/c1/velociraptor/deploy-hunt")
      .send({ vql: "SELECT * FROM pslist()", title: "Hunt rogue processes", source: "fleet", mitreTechniques: ["T1059"] });
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe("hunt");
    expect(res.body.huntId).toBe("H.DEPLOY1");

    const profile = (await request(app).get("/cases/c1/hunt-outcomes")).body;
    expect(profile).toMatchObject({ total: 1, hit: 0, missed: 0, pending: 1 });
    expect(profile.hunts[0]).toMatchObject({ title: "Hunt rogue processes", source: "fleet", status: "deployed", huntId: "H.DEPLOY1" });
    expect(profile.hunts[0].vqlPreview).toContain("pslist");

    // It is also registered as a collectible hunt job (so "Collect now" works).
    const jobs = (await request(app).get("/cases/c1/velociraptor/hunt-jobs")).body;
    expect(jobs.some((j: { huntId: string }) => j.huntId === "H.DEPLOY1")).toBe(true);
  });

  it("collecting a deployed hunt fills its outcome as a hit", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql: "SELECT * FROM pslist()", title: "ps hunt", source: "fleet" });
    expect((await request(app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.DEPLOY1" })).status).toBe(202);

    const hunt = await pollFor<{ status: string; foundEvidence?: boolean }>(
      "the deployed hunt to reach status=collected",
      async () => {
        const h = (await request(app).get("/cases/c1/hunt-outcomes")).body.hunts[0];
        return h && h.status === "collected" ? h : undefined;
      },
    );
    expect(hunt.status).toBe("collected");
    expect(hunt.foundEvidence).toBe(true);
    const profile = (await request(app).get("/cases/c1/hunt-outcomes")).body;
    expect(profile).toMatchObject({ hit: 1, pending: 0 });
    expect(profile.hunts[0].resultRows).toBe(1);          // the row the hunt returned is surfaced
    expect(profile.hunts[0].resultSummary).toContain("result");
  }, POLL_TIMEOUT_MS * 2);   // one poll budget, doubled to leave room for setup + assertions

  it("hunt-rows returns a tracked hunt's result rows on demand, 404s for an unknown hunt", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql: "SELECT * FROM pslist()", title: "ps hunt", source: "fleet" });
    const ok = await request(app).post("/cases/c1/velociraptor/hunt-rows").send({ huntId: "H.DEPLOY1" });
    expect(ok.status).toBe(200);
    expect(ok.body.rows).toHaveLength(1);
    const missing = await request(app).post("/cases/c1/velociraptor/hunt-rows").send({ huntId: "H.NOPE" });
    expect(missing.status).toBe(404);
  });

  it("deploy-hunt validates vql/title and collection-mode hostname", async () => {
    const { app } = await makeApp();
    expect((await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ title: "no vql" })).status).toBe(400);
    expect((await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql: "SELECT 1" })).status).toBe(400);
    expect((await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql: "SELECT 1", title: "t", mode: "collection" })).status).toBe(400);
  });

  it("deploy-hunt is 501 when Velociraptor is not configured", async () => {
    const { app } = await makeApp({ withVelo: false });
    const res = await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql: "SELECT 1", title: "t" });
    expect(res.status).toBe(501);
  });

  it("GET hunt-outcomes returns an empty profile for a fresh case", async () => {
    const { app } = await makeApp();
    expect((await request(app).get("/cases/c1/hunt-outcomes")).body).toEqual({ total: 0, hit: 0, missed: 0, pending: 0, hunts: [], pivotProductivity: [] });
  });

  it("suggest-hunts excludes a VQL that was already deployed", async () => {
    const vql = "SELECT FullPath FROM glob(globs='C:/inetpub/wwwroot/**/*.aspx')";
    const canned = JSON.stringify({ suggestions: [
      { title: "Hunt ASPX webshells", rationale: "spread", vql, severity: "High", mitreTechniques: ["T1505.003"], relatedFindingIds: ["f1"] },
    ] });
    const { app, stateStore, huntOutcomeStore } = await makeApp({ provider: new MockProvider("mock", canned) });

    const s = emptyState("c1");
    s.findings.push({ id: "f1", severity: "Critical", title: "Webshell", description: "ASPX webshell",
      relatedIocs: [], mitreTechniques: ["T1505.003"], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });
    await stateStore.save(s);

    // Without any prior deploy the suggestion comes through.
    expect((await request(app).post("/cases/c1/velociraptor/suggest-hunts").send({})).body.suggestions).toHaveLength(1);

    // Record the same VQL as already deployed → it must be filtered out next time.
    await huntOutcomeStore.save("c1", recordDeploy([], { source: "fleet", title: "Hunt ASPX webshells", vql, huntId: "H.OLD", deployedAt: "2026-06-20T00:00:00.000Z" }));
    const after = await request(app).post("/cases/c1/velociraptor/suggest-hunts").send({});
    expect(after.body.suggestions).toEqual([]);
    expect(vqlFingerprint(vql)).toBeTruthy();
  });
});

// #80: run-to-run hunt diffing — re-deploying the SAME VQL fingerprint (a recurring/scheduled hunt)
// must show what's new/gone vs its OWN previous run, not just the cumulative case delta.
describe("run-to-run hunt diffing (#80)", () => {
  async function waitForCollected(app: Express, huntId: string) {
    return pollFor<Array<Record<string, unknown>>>(`hunt ${huntId} to be collected`, async () => {
      const profile = (await request(app).get("/cases/c1/hunt-outcomes")).body;
      const h = (profile.hunts ?? []).find((x: { huntId?: string }) => x.huntId === huntId);
      return h && h.status === "collected" ? (profile.hunts as Array<Record<string, unknown>>) : undefined;
    });
  }

  it("diffs a re-run against its own previous run's rows/hosts, not the whole case", async () => {
    let huntSeq = 0;
    const rowsByHunt: Record<string, unknown[]> = {
      "H.RUN1": [{ Fqdn: "host-a", Message: "m1" }],
      "H.RUN2": [{ Fqdn: "host-a", Message: "m1" }, { Fqdn: "host-b", Message: "m2" }],
    };
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("hunt(") && p.includes("artifacts=")) {
        huntSeq += 1;
        return { rows: [{ Hunt: { HuntId: `H.RUN${huntSeq}`, state: "RUNNING" } }], raw: "" };
      }
      if (p.includes("hunt_results(")) {
        const m = p.match(/hunt_id='([^']+)'/);
        return { rows: (m && rowsByHunt[m[1]]) || [], raw: "" };
      }
      return { rows: [], raw: "" };
    };
    const { app } = await makeApp({ runner });
    const vql = "SELECT * FROM pslist()";

    // First deploy + collect: nothing to diff against yet.
    await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql, title: "recurring hunt", source: "fleet" });
    expect((await request(app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.RUN1" })).status).toBe(202);
    let hunts = await waitForCollected(app, "H.RUN1");
    expect(hunts.find((h) => h.huntId === "H.RUN1")?.runDiff).toMatchObject({ isFirstRun: true });

    // Re-deploy the SAME vql (a fresh huntId — a genuine re-run) + collect: diff vs H.RUN1's snapshot.
    await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql, title: "recurring hunt", source: "fleet" });
    expect((await request(app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.RUN2" })).status).toBe(202);
    hunts = await waitForCollected(app, "H.RUN2");
    expect(hunts.find((h) => h.huntId === "H.RUN2")?.runDiff).toMatchObject({
      isFirstRun: false, addedRows: 1, removedRows: 0, addedHosts: ["host-b"],
    });
    // TWO sequential waitForCollected polls, so the test timeout must clear 2x the poll budget.
  }, POLL_TIMEOUT_MS * 3);

  it("advances the baseline on same-huntId re-collects so a later re-run doesn't re-report stragglers", async () => {
    // Fleet hunt results trickle in: an analyst clicks "Collect" several times on the SAME huntId as
    // clients check in. The stored baseline must track the LATEST full result set of the run, not stay
    // frozen at the first (partial) collect — otherwise rows that arrived in the 2nd/3rd collect are
    // falsely reported as "new" when the hunt is later re-deployed under a fresh huntId.
    let huntSeq = 0;
    // Rows returned for the current H.RUN1 collect — mutated between collect requests to simulate
    // stragglers checking in. H.RUN2 (the re-deploy) returns the SAME complete set as H.RUN1 ended with.
    const completeRows = [
      { Fqdn: "host-a", Message: "m1" },
      { Fqdn: "host-b", Message: "m2" },
      { Fqdn: "host-c", Message: "m3" },
    ];
    let run1Rows: unknown[] = [completeRows[0]];
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("hunt(") && p.includes("artifacts=")) {
        huntSeq += 1;
        return { rows: [{ Hunt: { HuntId: `H.RUN${huntSeq}`, state: "RUNNING" } }], raw: "" };
      }
      if (p.includes("hunt_results(")) {
        const m = p.match(/hunt_id='([^']+)'/);
        const id = m && m[1];
        if (id === "H.RUN1") return { rows: run1Rows, raw: "" };
        if (id === "H.RUN2") return { rows: completeRows, raw: "" };
        return { rows: [], raw: "" };
      }
      return { rows: [], raw: "" };
    };
    const { app } = await makeApp({ runner });
    const vql = "SELECT * FROM pslist()";

    // Poll until the outcome's resultRows reflects a collect that returned `rows` rows — the only visible
    // signal that a same-huntId re-collect (which never changes status away from "collected") completed.
    async function waitForResultRows(huntId: string, rows: number) {
      const seen: unknown[] = [];
      await pollFor(
        () =>
          `hunt ${huntId} to report ${rows} result rows ` +
          `(observed resultRows: ${JSON.stringify([...new Set(seen.map(String))])})`,
        async () => {
          const profile = (await request(app).get("/cases/c1/hunt-outcomes")).body;
          const h = (profile.hunts ?? []).find((x: { huntId?: string }) => x.huntId === huntId);
          seen.push(h?.resultRows);
          return h && h.resultRows === rows ? true : undefined;
        },
      );
    }

    // First deploy + first (partial) collect — one host so far.
    await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql, title: "recurring hunt", source: "fleet" });
    expect((await request(app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.RUN1" })).status).toBe(202);
    await waitForResultRows("H.RUN1", 1);

    // Two more collects on the SAME huntId as stragglers check in (2 hosts, then 3). These must update
    // the baseline but NOT surface a run-diff of their own.
    run1Rows = [completeRows[0], completeRows[1]];
    expect((await request(app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.RUN1" })).status).toBe(202);
    await waitForResultRows("H.RUN1", 2);

    run1Rows = [...completeRows];
    expect((await request(app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.RUN1" })).status).toBe(202);
    await waitForResultRows("H.RUN1", 3);

    // Re-deploy the SAME vql under a fresh huntId (a genuine re-run) whose result set equals H.RUN1's
    // COMPLETE final set. Because the baseline advanced on every collect, nothing is new: had the
    // baseline stayed frozen at the first partial collect (1 host), host-b and host-c would be falsely
    // reported as added here.
    await request(app).post("/cases/c1/velociraptor/deploy-hunt").send({ vql, title: "recurring hunt", source: "fleet" });
    expect((await request(app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.RUN2" })).status).toBe(202);
    const hunts = await waitForCollected(app, "H.RUN2");
    expect(hunts.find((h) => h.huntId === "H.RUN2")?.runDiff).toMatchObject({
      isFirstRun: false, addedRows: 0, removedRows: 0, addedHosts: [], removedHosts: [],
    });
    // FOUR sequential polls (3x waitForResultRows + 1x waitForCollected). At the old 30s this test
    // could not survive its own worst case — 4 x 10s of polling — which is how it came to fail ~50%
    // of runs under load. The timeout now clears the full poll budget with headroom (issue #173).
  }, POLL_TIMEOUT_MS * 5);
});
