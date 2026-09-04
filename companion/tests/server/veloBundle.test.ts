import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

// A mock runner standing in for the velociraptor binary — branches on the orchestration VQL the
// client emits. The Pstree hunt returns one process row; other artifacts return nothing (not checked
// in yet). The upload VQL (hunt_flows/uploads/read_file) returns nothing here (covered by its own test).
const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("artifact_definitions()")) {
    return {
      rows: [
        { name: "Windows.System.Pslist", description: "Running processes", type: "CLIENT" },
        { name: "Generic.System.Pstree", description: "Process tree", type: "CLIENT" },
      ],
      raw: "",
    };
  }
  if (p.includes("hunt(") && p.includes("artifacts=[")) {
    return { rows: [{ Hunt: { HuntId: "H.TEST1", state: "RUNNING" } }], raw: "" };
  }
  if (p.includes("hunt_results(")) {
    if (p.includes("Pstree"))
      return {
        rows: [
          {
            Name: "powershell.exe",
            Pid: 1234,
            CommandLine: "powershell -enc AAAA",
            Timestamp: "2026-06-01T10:00:00Z",
          },
        ],
        raw: "",
      };
    return { rows: [], raw: "" };
  }
  return { rows: [], raw: "" };
};

async function makeApp(runnerOverride: VqlRunner = runner, cfg: Partial<VelociraptorApiConfig> = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velobundle-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const artifactBundleStore = new ArtifactBundleStore(join(dirname(root), "bundles"));
  const veloHuntStore = new VeloHuntStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore,
    velociraptorClient: new VelociraptorClient({ ...veloCfg, ...cfg }, runnerOverride),
    artifactBundleStore,
    veloHuntStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, store };
}

/**
 * Wait for the case's hunt job to reach a TERMINAL status (issue #408).
 *
 * `error` counts as terminal so a genuine import failure still reports as
 * `expected 'error' to be 'imported'` at the caller's assertion. The six loops this replaces
 * spelled a private 100x20ms deadline instead, and on expiry fell through to that same assertion
 * reporting `expected 'collecting' to be 'imported'` — a wait that ran out, wearing the costume of
 * a state-machine defect. The description closure names the last status actually observed, so a
 * real hang says what the job was stuck on.
 */
async function pollHuntJob<T extends { status: string }>(target: Parameters<typeof request>[0]): Promise<T> {
  let last = "no job at all";
  return pollFor<T>(
    () => `the hunt job to reach a terminal status, last saw "${last}"`,
    async () => {
      const job = (await request(target).get("/cases/c1/velociraptor/hunt-jobs")).body[0] as T | undefined;
      if (!job) return undefined;
      last = job.status;
      return job.status === "imported" || job.status === "error" ? job : undefined;
    },
  );
}

describe("Velociraptor triage bundles — routes", () => {
  let app: Awaited<ReturnType<typeof makeApp>>["app"];
  let stateStore: Awaited<ReturnType<typeof makeApp>>["stateStore"];

  beforeEach(async () => {
    const made = await makeApp();
    app = made.app;
    stateStore = made.stateStore;
  });

  it("GET /velociraptor/artifacts lists the server's CLIENT artifacts", async () => {
    const res = await request(app).get("/velociraptor/artifacts");
    expect(res.status).toBe(200);
    expect(res.body.artifacts.map((a: { name: string }) => a.name)).toContain("Windows.System.Pslist");
  });

  it("bundle CRUD: create, list, and delete a custom bundle", async () => {
    const create = await request(app)
      .post("/bundles")
      .send({ name: "My Triage", artifacts: ["Windows.System.Pslist"] });
    expect(create.status).toBe(201);
    expect(create.body.builtIn).toBe(false);

    const list = await request(app).get("/bundles");
    expect(list.body.some((b: { name: string }) => b.name === "My Triage")).toBe(true);
    expect(list.body.some((b: { id: string }) => b.id === "best-practice")).toBe(true);

    expect((await request(app).delete(`/bundles/${create.body.id}`)).status).toBe(204);
    expect((await request(app).delete("/bundles/nope-xyz")).status).toBe(404); // unknown custom id
  });

  it("built-in bundles are editable in place and resettable to the default", async () => {
    const edit = await request(app)
      .post("/bundles")
      .send({
        id: "best-practice",
        name: "Best Practice (mine)",
        artifacts: ["Windows.System.Pslist", "Windows.Network.Netstat"],
      });
    expect(edit.status).toBe(201);
    expect(edit.body.builtIn).toBe(true);
    expect(edit.body.customized).toBe(true);

    let ft = (await request(app).get("/bundles")).body.find((b: { id: string }) => b.id === "best-practice");
    expect(ft.name).toBe("Best Practice (mine)");
    expect(ft.customized).toBe(true);

    expect((await request(app).delete("/bundles/best-practice")).status).toBe(204); // reset to default
    ft = (await request(app).get("/bundles")).body.find((b: { id: string }) => b.id === "best-practice");
    expect(ft.name).toBe("Best Practice");
    expect(ft.customized).toBe(false);
  });

  it("POST /bundles round-trips every bundle field — editing a built-in must not wipe superTimelineOnly, timeout, params or filters", async () => {
    // Regression: the route used to destructure only {id,name,description,artifacts,defaultWaitMinutes},
    // so editing "Super-Timeline Triage" through the dashboard silently cleared superTimelineOnly and its
    // raw MFT/USN flood would start landing in the FORENSIC timeline.
    const save = await request(app)
      .post("/bundles")
      .send({
        id: "super-timeline-triage",
        name: "Super-Timeline Triage",
        artifacts: ["Windows.NTFS.MFT"],
        superTimelineOnly: true,
        timeoutSeconds: 6000,
        expirySeconds: 86400,
        params: { "Windows.NTFS.MFT": { DateAfter: "2026-01-01T00:00:00Z" } },
        filters: { "Windows.NTFS.MFT": "NOT OSPath =~ 'pagefile'" },
      });
    expect(save.status).toBe(201);

    const got = (await request(app).get("/bundles")).body.find(
      (b: { id: string }) => b.id === "super-timeline-triage",
    );
    expect(got.superTimelineOnly).toBe(true);
    expect(got.timeoutSeconds).toBe(6000);
    expect(got.expirySeconds).toBe(86400);
    expect(got.params).toEqual({ "Windows.NTFS.MFT": { DateAfter: "2026-01-01T00:00:00Z" } });
    expect(got.filters).toEqual({ "Windows.NTFS.MFT": "NOT OSPath =~ 'pagefile'" });

    expect((await request(app).delete("/bundles/super-timeline-triage")).status).toBe(204); // reset to default
  });

  // The program reaches the CLI as argv, which Linux caps at 128 KiB PER ARGUMENT — in bytes. An
  // oversized body could never run and used to surface only as an E2BIG spawn failure (#825,
  // #828); the routes now refuse it with a 400 before the client is touched, and they measure
  // UTF-8 bytes, because a character count under-reads a multibyte query by up to three times.
  describe("VQL size limit on /velociraptor/run, /hunt and /collect-host", () => {
    const ROUTES = (vql: string) =>
      [
        ["/velociraptor/run", { vql }],
        ["/velociraptor/hunt", { vql, description: "size test" }],
        ["/velociraptor/collect-host", { vql, hostname: "WS-1" }],
      ] as const;

    it("refuses an ASCII body past the byte limit with a 400 and never invokes the client", async () => {
      const calls: string[][] = [];
      const { app: spyApp } = await makeApp(async (statements) => {
        calls.push(statements);
        return { rows: [], raw: "" };
      });
      for (const [path, body] of ROUTES("SELECT 1 FROM scope() -- " + "x".repeat(100_001))) {
        const res = await request(spyApp).post(path).send(body);
        expect(res.status, path).toBe(400);
        expect(res.body.error).toMatch(/vql is too long/);
      }
      expect(calls).toHaveLength(0);
    });

    it("refuses a multibyte body whose character count is under the limit but whose bytes are not", async () => {
      const calls: string[][] = [];
      const { app: spyApp } = await makeApp(async (statements) => {
        calls.push(statements);
        return { rows: [], raw: "" };
      });
      const vql = "SELECT '" + "€".repeat(40_000) + "' AS s FROM scope()"; // ~40k chars, ~120k bytes
      expect(vql.length).toBeLessThan(100_000);
      for (const [path, body] of ROUTES(vql)) {
        const res = await request(spyApp).post(path).send(body);
        expect(res.status, path).toBe(400);
        expect(res.body.error).toMatch(/vql is too long/);
      }
      expect(calls).toHaveLength(0);
    });

    it("accepts a large ASCII body under the byte limit and hands it to the client", async () => {
      const calls: string[][] = [];
      const { app: spyApp } = await makeApp(async (statements) => {
        calls.push(statements);
        return { rows: [], raw: "" };
      });
      const vql = "SELECT 1 FROM scope() -- " + "x".repeat(90_000);
      const res = await request(spyApp).post("/velociraptor/run").send({ vql });
      expect(res.status).toBe(200);
      expect(calls).toHaveLength(1);
    });
  });

  it("POST /bundles refuses a WHERE filter that could smuggle a statement, as a 400", async () => {
    const res = await request(app)
      .post("/bundles")
      .send({
        name: "Smuggle",
        artifacts: ["Windows.NTFS.MFT"],
        filters: { "Windows.NTFS.MFT": "1=1) LIMIT 1; SELECT * FROM execve(argv=['id']) WHERE (1=1" },
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid WHERE filter for Windows\.NTFS\.MFT/);
  });

  it("POST /bundles rejects a bundle with no artifacts", async () => {
    const res = await request(app).post("/bundles").send({ name: "Empty", artifacts: [] });
    expect(res.status).toBe(400);
  });

  it("run-bundle launches a hunt and persists a running job with a collect time", async () => {
    const run = await request(app)
      .post("/cases/c1/velociraptor/run-bundle")
      .send({ bundleId: "best-practice", waitMinutes: 30 });
    expect(run.status).toBe(202);
    expect(run.body.huntId).toBe("H.TEST1");
    expect(run.body.guiUrl).toContain("H.TEST1");
    expect(typeof run.body.collectAt).toBe("string");

    const jobs = (await request(app).get("/cases/c1/velociraptor/hunt-jobs")).body;
    expect(jobs).toHaveLength(1);
    const job = jobs[0];
    expect(job.status).toBe("running");
    expect(job.huntId).toBe("H.TEST1");
    expect(job.artifacts).toContain("Generic.System.Pstree");
  });

  // The 5-hour dead end this closes: on a server with no egress, ONE tool it has never downloaded fails
  // the whole hunt while Velociraptor compiles it, and the API returns a bare NULL. The analyst saw
  // "no bundle hunt id" and three generic guesses, none of which named an artifact or a tool.
  const toolRunner = (hunt: unknown): VqlRunner => {
    return async (statements) => {
      const p = statements[0];
      if (p.includes("artifact_definitions()"))
        return {
          rows: [
            {
              name: "Windows.System.Pslist",
              description: "Running processes",
              type: "CLIENT",
              tools: [{ name: "FileYaraWindows", url: "https://github.com/x/full_windows.yar.gz" }],
            },
          ],
          raw: "",
        };
      if (p.includes("inventory()"))
        // No hash: the server has never fetched this one, though the URL itself looks fine.
        return {
          rows: [{ name: "FileYaraWindows", url: "https://github.com/x/full_windows.yar.gz" }],
          raw: "",
        };
      if (p.includes("hunt(") && p.includes("artifacts=[")) return { rows: [{ Hunt: hunt }], raw: "" };
      return { rows: [], raw: "" };
    };
  };

  it("run-bundle names the un-downloaded tools when the hunt refuses to launch", async () => {
    const made = await makeApp(toolRunner(null));
    const bundle = await request(made.app)
      .post("/bundles")
      .send({ name: "Yara sweep", artifacts: ["Windows.System.Pslist"] });
    const run = await request(made.app)
      .post("/cases/c1/velociraptor/run-bundle")
      .send({ bundleId: bundle.body.id, waitMinutes: 30 });
    expect(run.status).toBe(502);
    expect(run.body.error).toContain("no bundle hunt id");
    expect(run.body.error).toContain("FileYaraWindows"); // the tool
    expect(run.body.error).toContain("Windows.System.Pslist"); // the artifact that needs it
    expect(run.body.error).toContain("Server Artifacts"); // where to fix it
  });

  it("run-bundle reports the un-downloaded tools on a successful launch too", async () => {
    const made = await makeApp(toolRunner({ HuntId: "H.TOOL1", state: "RUNNING" }));
    const bundle = await request(made.app)
      .post("/bundles")
      .send({ name: "Yara sweep", artifacts: ["Windows.System.Pslist"] });
    const run = await request(made.app)
      .post("/cases/c1/velociraptor/run-bundle")
      .send({ bundleId: bundle.body.id, waitMinutes: 30 });
    expect(run.status).toBe(202);
    expect(run.body.artifacts).toEqual(["Windows.System.Pslist"]); // warned about, never dropped
    expect(run.body.unheldTools).toEqual([
      {
        tool: "FileYaraWindows",
        url: "https://github.com/x/full_windows.yar.gz",
        artifacts: ["Windows.System.Pslist"],
      },
    ]);
  });

  it("supports MULTIPLE concurrent hunts — a second run keeps the first", async () => {
    // two runs whose mock returns distinct hunt ids
    let n = 0;
    const multiRunner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("hunt(") && p.includes("artifacts=[")) {
        n += 1;
        return { rows: [{ Hunt: { HuntId: `H.MULTI${n}`, state: "RUNNING" } }], raw: "" };
      }
      if (p.includes("hunt_results(")) return { rows: [], raw: "" };
      return { rows: [], raw: "" };
    };
    const made = await makeApp(multiRunner);
    await request(made.app)
      .post("/cases/c1/velociraptor/run-bundle")
      .send({ bundleId: "best-practice", waitMinutes: 30 });
    await request(made.app)
      .post("/cases/c1/velociraptor/run-bundle")
      .send({ bundleId: "best-practice", waitMinutes: 30 });
    const jobs = (await request(made.app).get("/cases/c1/velociraptor/hunt-jobs")).body;
    const ids = jobs.map((j: { huntId: string }) => j.huntId);
    expect(ids).toContain("H.MULTI1");
    expect(ids).toContain("H.MULTI2");
    expect(jobs.every((j: { status: string }) => j.status === "running")).toBe(true);
  });

  it(
    "collect imports the hunt results into the timeline and marks the job imported",
    async () => {
      await request(app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      const col = await request(app).post("/cases/c1/velociraptor/collect");
      expect(col.status).toBe(202);

      const job = await pollHuntJob<{ status: string }>(app);
      expect(job.status).toBe("imported");

      // The Pstree rows the mock hunt returned became forensic-timeline events.
      const state = await stateStore.load("c1");
      expect(state.forensicTimeline.length).toBeGreaterThan(0);
    },
    POLL_TIMEOUT_MS * 2,
  ); // one poll budget, doubled to leave room for setup + assertions

  it(
    "stamps veloUrl on the FORENSIC timeline events a bundle collect produces, not just super-only imports (#7 regression)",
    async () => {
      // Bug: importVeloHuntResults computed the hunt's GUI deep-link only inside the superTimelineOnly
      // branch and never passed it to pipeline.importVelociraptor on the normal (forensic) branch — so a
      // plain triage-bundle collection (e.g. Best Practice) never carried a veloUrl and the forensic
      // timeline's "↗ Velociraptor" row link never rendered.
      await request(app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      await request(app).post("/cases/c1/velociraptor/collect");
      const job = await pollHuntJob<{ status: string }>(app);
      expect(job.status).toBe("imported");
      const state = await stateStore.load("c1");
      expect(state.forensicTimeline.length).toBeGreaterThan(0);
      expect(
        state.forensicTimeline.every(
          (e) => e.veloUrl === "https://velo.example/app/index.html?org_id=root#/hunts/H.TEST1",
        ),
      ).toBe(true);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "ingests an uploaded JSON report (THOR) from the hunt even when result rows are empty",
    async () => {
      const thorLine = JSON.stringify({
        time: "2025-03-14T21:18:18Z",
        hostname: "WIN11",
        level: "Alert",
        module: "Filescan",
        message: "Malware file found",
        file: "C:\\Tools\\mimikatz.exe",
        sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
      });
      const upRunner: VqlRunner = async (statements) => {
        const p = statements[0];
        if (p.includes("hunt(") && p.includes("artifacts=["))
          return { rows: [{ Hunt: { HuntId: "H.UP9", state: "RUNNING" } }], raw: "" };
        if (p.includes("hunt_results(")) return { rows: [], raw: "" }; // no result rows — only the upload matters
        if (p.includes("hunt_flows(") || p.includes("read_file("))
          return {
            rows: [{ ClientId: "C.1", Path: "thor.json", Name: "thor.json", Content: thorLine }],
            raw: "",
          };
        return { rows: [], raw: "" };
      };
      const made = await makeApp(upRunner);
      await request(made.app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      expect((await request(made.app).post("/cases/c1/velociraptor/collect")).status).toBe(202);

      const job = await pollHuntJob<{ status: string }>(made.app);
      expect(job.status).toBe("imported");
      // The uploaded THOR JSON was detected + imported into the timeline (rows were empty).
      const state = await made.stateStore.load("c1");
      expect(state.forensicTimeline.length).toBeGreaterThan(0);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "collect records skipped (failed) and empty (no findings) artifacts on the job — so a bundle where most artifacts fail isn't silently indistinguishable from one where they simply found nothing",
    async () => {
      const mixedRunner: VqlRunner = async (statements) => {
        const p = statements[0];
        if (p.includes("artifact_definitions()")) {
          // All three bundle artifacts exist on the server (so the run-bundle pre-flight passes them
          // through); the DetectRaptor one still FAILS at collect time (too-large fetch) below — the
          // distinction this test asserts is collect-time skipped-vs-empty, not launch-time unknown.
          return {
            rows: [
              { name: "Windows.System.Pslist", description: "Running processes", type: "CLIENT" },
              { name: "Generic.System.Pstree", description: "Process tree", type: "CLIENT" },
              {
                name: "DetectRaptor.Windows.Detection.Amcache",
                description: "Amcache detections",
                type: "CLIENT",
              },
            ],
            raw: "",
          };
        }
        if (p.includes("hunt(") && p.includes("artifacts=["))
          return { rows: [{ Hunt: { HuntId: "H.MIX1", state: "RUNNING" } }], raw: "" };
        if (p.includes("hunt_results(")) {
          if (p.includes("Pstree"))
            return {
              rows: [
                {
                  Name: "powershell.exe",
                  Pid: 1234,
                  CommandLine: "powershell -enc AAAA",
                  Timestamp: "2026-06-01T10:00:00Z",
                },
              ],
              raw: "",
            };
          if (p.includes("Windows.Detection.Amcache") || p.includes("DetectRaptor"))
            throw new Error("output exceeded 1048576 bytes");
          return { rows: [], raw: "" };
        }
        return { rows: [], raw: "" };
      };
      const made = await makeApp(mixedRunner);
      // Edit the built-in bundle in place so it includes an artifact our mock throws on, alongside
      // one that returns rows and one that returns nothing — exercising all three outcomes at once.
      await request(made.app)
        .post("/bundles")
        .send({
          id: "best-practice",
          name: "Best Practice",
          artifacts: [
            "Generic.System.Pstree",
            "Windows.System.Pslist",
            "DetectRaptor.Windows.Detection.Amcache",
          ],
        });
      await request(made.app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      expect((await request(made.app).post("/cases/c1/velociraptor/collect")).status).toBe(202);

      const job = await pollHuntJob<{
        status: string;
        skippedArtifacts?: { name: string; error: string }[];
        emptyArtifacts?: string[];
      }>(made.app);
      expect(job.status).toBe("imported");
      expect(job.skippedArtifacts).toEqual([
        { name: "DetectRaptor.Windows.Detection.Amcache", error: "output exceeded 1048576 bytes" },
      ]);
      expect(job.emptyArtifacts).toEqual(["Windows.System.Pslist"]);
    },
    POLL_TIMEOUT_MS * 2,
  );

  // The THIRD collect outcome. A read that hits the row cap imports real rows and reports success, so
  // it is indistinguishable from a complete collect — which is how a THOR scan's 40 warnings went
  // missing while the case showed a green import. Recorded on the job beside skipped/empty.
  it(
    "collect records an artifact whose read hit the row cap, so a PARTIAL collect isn't reported as a complete one",
    async () => {
      const cappedRunner: VqlRunner = async (statements) => {
        const p = statements[0];
        if (p.includes("artifact_definitions()"))
          return {
            rows: [{ name: "Generic.System.Pstree", description: "Process tree", type: "CLIENT" }],
            raw: "",
          };
        if (p.includes("hunt(") && p.includes("artifacts="))
          return { rows: [{ Hunt: { HuntId: "H.CAP1", state: "RUNNING" } }], raw: "" };
        if (p.includes("hunt_results(") && p.includes("Pstree")) {
          // One row MORE than the configured cap — exactly what a real over-cap read returns, since the
          // VQL asks for cap+1 so the client can tell "full" from "there was more".
          const rows = Array.from({ length: 3 }, (_, i) => ({
            Name: `p${i}.exe`,
            Timestamp: "2026-06-01T10:00:00Z",
          }));
          return { rows, raw: "" };
        }
        return { rows: [], raw: "" };
      };
      // collectMaxRows 2, so the 3 rows above trip the cap and 2 survive.
      const made = await makeApp(cappedRunner, { collectMaxRows: 2 });
      await request(made.app)
        .post("/bundles")
        .send({ id: "best-practice", name: "Best Practice", artifacts: ["Generic.System.Pstree"] });
      await request(made.app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      expect((await request(made.app).post("/cases/c1/velociraptor/collect")).status).toBe(202);

      const job = await pollHuntJob<{
        status: string;
        truncatedArtifacts?: { name: string; kept: number; total: number }[];
      }>(made.app);
      expect(job.status).toBe("imported");
      expect(job.truncatedArtifacts).toEqual([{ name: "Generic.System.Pstree", kept: 2, total: 3 }]);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it("run-bundle is 501 when Velociraptor is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-velobundle-noclient-"));
    const store = new CaseStore(root);
    const bare = createApp(store, {}); // no velociraptorClient / pipeline
    // The case has to be REAL for this to be a test about the 501: the case-exists gate on
    // /cases/:id/velociraptor now answers 404 first, and would have made this pass for the wrong reason.
    await request(bare).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(bare)
      .post("/cases/c1/velociraptor/run-bundle")
      .send({ bundleId: "best-practice" });
    expect(res.status).toBe(501);
  });
});

describe("Velociraptor hunt status polling — routes", () => {
  it(
    "poll-status detects STOPPED and triggers an immediate collect",
    async () => {
      const runner: VqlRunner = async (statements) => {
        const p = statements[0];
        if (p.includes("hunt(") && p.includes("artifacts=["))
          return { rows: [{ Hunt: { HuntId: "H.STOP1", state: "RUNNING" } }], raw: "" };
        if (p.includes("FROM hunts()")) return { rows: [{ state: "STOPPED" }], raw: "" };
        if (p.includes("hunt_results("))
          return { rows: [{ Name: "cmd.exe", Timestamp: "2026-07-01T10:00:00Z" }], raw: "" };
        return { rows: [], raw: "" };
      };
      const made = await makeApp(runner);
      await request(made.app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });

      const poll = await request(made.app).post("/cases/c1/velociraptor/hunt-jobs/H.STOP1/poll-status");
      expect(poll.status).toBe(200);

      // The poll triggered importVeloHuntResults in the background (fire-and-forget) — wait for it.
      const job = await pollHuntJob<{ status: string }>(made.app);
      expect(job.status).toBe("imported");
    },
    POLL_TIMEOUT_MS * 2,
  );

  // Deleting a hunt from the Velociraptor GUI does not make it disappear from hunts() (confirmed
  // against a live server) — it just reports STOPPED, same as a hunt that finished naturally. The only
  // usable signal is the hunt's own `expires`: STOPPED well before it means an analyst intervened.
  // Exercised via the plain /collect route (not poll-status) since that's also the path a manual
  // "Collect now" click and the fixed-delay auto-collect timer take — the check must fire there too.
  it(
    "collect flags a hunt reported STOPPED well before its own expiry as stoppedEarly",
    async () => {
      const farFutureExpiresMicros = (Date.now() + 60 * 60 * 1000) * 1000; // 1h from now, in microseconds
      const runner: VqlRunner = async (statements) => {
        const p = statements[0];
        if (p.includes("hunt(") && p.includes("artifacts=["))
          return { rows: [{ Hunt: { HuntId: "H.EARLY1", state: "RUNNING" } }], raw: "" };
        if (p.includes("FROM hunts()"))
          return { rows: [{ state: "STOPPED", expires: farFutureExpiresMicros }], raw: "" };
        if (p.includes("hunt_results(")) return { rows: [], raw: "" };
        return { rows: [], raw: "" };
      };
      const made = await makeApp(runner);
      await request(made.app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      expect((await request(made.app).post("/cases/c1/velociraptor/collect")).status).toBe(202);

      const job = await pollHuntJob<{ status: string; stoppedEarly?: boolean; addedEvents?: number }>(
        made.app,
      );
      expect(job.status).toBe("imported");
      expect(job.stoppedEarly).toBe(true);
      expect(job.addedEvents ?? 0).toBe(0);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it("poll-status marks the job deleted when Velociraptor has no record of the hunt", async () => {
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("hunt(") && p.includes("artifacts=["))
        return { rows: [{ Hunt: { HuntId: "H.DEL2", state: "RUNNING" } }], raw: "" };
      if (p.includes("FROM hunts()")) return { rows: [], raw: "" }; // hunt not found — deleted
      return { rows: [], raw: "" };
    };
    const made = await makeApp(runner);
    await request(made.app)
      .post("/cases/c1/velociraptor/run-bundle")
      .send({ bundleId: "best-practice", waitMinutes: 30 });

    const poll = await request(made.app).post("/cases/c1/velociraptor/hunt-jobs/H.DEL2/poll-status");
    expect(poll.status).toBe(200);
    expect(poll.body.status).toBe("deleted");

    const jobs = (await request(made.app).get("/cases/c1/velociraptor/hunt-jobs")).body;
    expect(jobs[0].status).toBe("deleted");
  });

  it("poll-status marks the job unreachable when the Velociraptor query throws, without flipping it to deleted", async () => {
    const runner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("hunt(") && p.includes("artifacts=["))
        return { rows: [{ Hunt: { HuntId: "H.UNR2", state: "RUNNING" } }], raw: "" };
      if (p.includes("FROM hunts()")) throw new Error("velociraptor process spawn failed");
      return { rows: [], raw: "" };
    };
    const made = await makeApp(runner);
    await request(made.app)
      .post("/cases/c1/velociraptor/run-bundle")
      .send({ bundleId: "best-practice", waitMinutes: 30 });

    const poll = await request(made.app).post("/cases/c1/velociraptor/hunt-jobs/H.UNR2/poll-status");
    expect(poll.status).toBe(200);
    expect(poll.body.status).toBe("unreachable");
  });

  it("poll-status is a 404 for an unknown hunt id", async () => {
    const made = await makeApp();
    const poll = await request(made.app).post("/cases/c1/velociraptor/hunt-jobs/H.NOPE/poll-status");
    expect(poll.status).toBe(404);
  });

  it("poll-status is 501 when Velociraptor is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-velobundle-noclient2-"));
    const store = new CaseStore(root);
    const bare = createApp(store, {});
    // The case has to be REAL for this to be a test about the 501: the case-exists gate on
    // /cases/:id/velociraptor now answers 404 first, and would have made this pass for the
    // wrong reason.
    await request(bare).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(bare).post("/cases/c1/velociraptor/hunt-jobs/H.X/poll-status");
    expect(res.status).toBe(501);
  });

  // ── The case-exists gate on /cases/:id/velociraptor/* ──────────────────────────────────────
  //
  // The dashboard's case picker is PRE-FILLED from localStorage on a bare /dashboard without
  // connecting, so "the field has a value" was never evidence that the case exists — and an
  // analyst could type any id into it. Nothing downstream checked: the id-shape gate passes a
  // well-formed unknown id and the lock gate passes a case with no meta, so run-bundle launched
  // a real hunt on real endpoints for a case that was never created.
  describe("refuses a case that does not exist, before anything is launched", () => {
    it("404s run-bundle and never launches the hunt", async () => {
      const launched: string[] = [];
      const spy: VqlRunner = async (...args) => {
        const [statements] = args;
        if (statements[0].includes("hunt(") && statements[0].includes("artifacts=["))
          launched.push(statements[0]);
        return runner(...args);
      };
      const made = await makeApp(spy);

      const res = await request(made.app)
        .post("/cases/never-created/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });

      expect(res.status).toBe(404);
      expect(res.body.error).toContain("never-created");
      // The point of the gate: no hunt reached Velociraptor. A 404 AFTER a launch would leave an
      // untracked hunt running on live endpoints.
      expect(launched).toEqual([]);
    });

    it("404s the rest of the per-case surface too — collect, import-external, deploy-hunt, hunt-jobs", async () => {
      const made = await makeApp();
      const gone = "never-created";
      expect(
        (await request(made.app).post(`/cases/${gone}/velociraptor/collect`).send({ huntId: "H.X" })).status,
      ).toBe(404);
      expect(
        (await request(made.app).post(`/cases/${gone}/velociraptor/import-external`).send({ ref: "H.X" }))
          .status,
      ).toBe(404);
      expect(
        (
          await request(made.app)
            .post(`/cases/${gone}/velociraptor/deploy-hunt`)
            .send({ vql: "SELECT 1 FROM scope()", title: "t" })
        ).status,
      ).toBe(404);
      expect((await request(made.app).get(`/cases/${gone}/velociraptor/hunt-jobs`)).status).toBe(404);
    });

    it("still lets a real case through", async () => {
      const made = await makeApp();
      const res = await request(made.app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      expect(res.status).toBe(202);
    });
  });
});
