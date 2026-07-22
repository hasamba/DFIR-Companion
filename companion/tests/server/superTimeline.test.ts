import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { join as pathJoin, dirname } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImporterStore } from "../../src/analysis/importerStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { EXAMPLE_IMPORTER_SPEC } from "../../src/analysis/importerSpec.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { VelociraptorClient, type VqlRunner, type VelociraptorApiConfig } from "../../src/integrations/velociraptor/velociraptorApi.js";

// Harness mirrors tests/server/importerRoutes.test.ts (a real CaseStore + StateStore + a deterministic
// runtime pipeline with NO AI provider, plus an ImporterStore so the EXAMPLE_IMPORTER_SPEC routes the
// import) and adds a SuperTimelineStore — the piece under test. The import path exercised is the
// unified Import button (POST /cases/:id/import), the primary "normal import".
async function harness(opts: { withStore?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-supertl-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const importerStore = new ImporterStore(join(root, "importers"));
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const superStore = opts.withStore === false ? undefined : new SuperTimelineStore(store);
  const app = createApp(store, {
    pipeline, stateStore, importerStore, tagsStore: new TagsStore(store),
    ...(superStore ? { superTimelineStore: superStore } : {}),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, superStore };
}

const MDE_CSV =
  "Timestamp,DeviceName,ActionType,FileName,Severity,SHA256,RemoteIP\n" +
  "2026-06-10T12:00:00Z,HOST01,ProcessCreated,evil.exe,High,abc123,9.9.9.9";

describe("super-timeline dual-write", () => {
  it("returns 501 when the super-timeline store is not configured", async () => {
    const { app } = await harness({ withStore: false });
    expect((await request(app).get("/cases/c1/super-timeline")).status).toBe(501);
  });

  it("a normal import's added events also appear in the super-timeline", async () => {
    const { app } = await harness();
    await request(app).post("/importers").send({ spec: EXAMPLE_IMPORTER_SPEC });

    const imp = await request(app).post("/cases/c1/import").send({ text: MDE_CSV, filename: "advanced-hunting.csv" });
    expect(imp.status).toBe(202);
    expect(imp.body.kind).toBe("mde-advanced-hunting");

    // The import runs async (persist → dispatch → diff → super-timeline append). Poll the super-timeline
    // until the dual-written events land — the load-bearing assertion of this task.
    let total = 0;
    let res = await request(app).get("/cases/c1/super-timeline");
    for (let i = 0; i < 60 && total === 0; i++) {
      res = await request(app).get("/cases/c1/super-timeline");
      total = res.body.total ?? 0;
      if (total === 0) await new Promise((r) => setTimeout(r, 25));
    }
    expect(res.status).toBe(200);
    expect(res.body.total).toBeGreaterThan(0);
    // The basic read route returns the querySuper shape (facets included).
    expect(Array.isArray(res.body.events)).toBe(true);
    expect(Array.isArray(res.body.origins)).toBe(true);
    expect(Array.isArray(res.body.labelsAvailable)).toBe(true);
  });
});

// ── superTimelineOnly bundle routing (Task 5) ───────────────────────────────────────────────────
// A bundle flagged superTimelineOnly (the built-in super-timeline-triage) collects its raw host
// artifacts (MFT/USN/…) into the super-timeline ONLY — they must NOT flood the forensic timeline or
// IOC list. Mirrors dwellWindows.test.ts's mock-runner + real ArtifactBundleStore/VeloHuntStore
// harness, adding the SuperTimelineStore under test. The mock runner returns one MFT-like row for the
// hunt_results() fetch so parseVelociraptorJson maps ≥1 event.
const superVeloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml", binary: "velociraptor", timeoutMs: 5000, maxRows: 1000, maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

const superBundleRunner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("hunt(") && p.includes("artifacts=[")) return { rows: [{ Hunt: { HuntId: "H.SUPER1", state: "RUNNING" } }], raw: "" };
  // Only the MFT artifact returns rows; every other artifact in the bundle reads empty.
  if (p.includes("hunt_results(") && p.includes("Windows.NTFS.MFT")) {
    return { rows: [{ OSPath: "C:\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" }], raw: "" };
  }
  if (p.includes("hunt_results(")) return { rows: [], raw: "" };
  return { rows: [], raw: "" };   // uploads read etc.
};

async function makeSuperBundleApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-super-bundle-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore,
    velociraptorClient: new VelociraptorClient(superVeloCfg, superBundleRunner),
    artifactBundleStore: new ArtifactBundleStore(pathJoin(dirname(root), "bundles")),
    veloHuntStore: new VeloHuntStore(store),
    superTimelineStore: new SuperTimelineStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

// A super-only runner that ALSO returns an uploaded JSON report (THOR/Hayabusa put their triage data in
// an uploaded file, read via the hunt_flows/uploads VQL — a distinct program from hunt_results). The
// upload payload is an importable SIEM record that WOULD produce a forensic event if dispatched; the
// super-only guard must skip it, so the forensic timeline stays empty. Proves the ST5 invariant now
// covers the upload path (step 2), not just result rows (step 1).
const SUPER_UPLOAD_JSON = JSON.stringify([
  { "@timestamp": "2026-06-02T00:00:00Z", EventID: 4688, Channel: "Security", Computer: "HOST01",
    EventData: { NewProcessName: "C:\\Windows\\System32\\cmd.exe", CommandLine: "cmd.exe /c whoami" } },
]);

const superUploadRunner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("hunt(") && p.includes("artifacts=[")) return { rows: [{ Hunt: { HuntId: "H.SUPER1", state: "RUNNING" } }], raw: "" };
  // The uploads read (hunt_flows → uploads) returns ONE uploaded JSON report.
  if (p.includes("hunt_flows(")) return { rows: [{ Name: "thor.json", ClientId: "C.1", Content: SUPER_UPLOAD_JSON }], raw: "" };
  if (p.includes("hunt_results(") && p.includes("Windows.NTFS.MFT")) {
    return { rows: [{ OSPath: "C:\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" }], raw: "" };
  }
  if (p.includes("hunt_results(")) return { rows: [], raw: "" };
  return { rows: [], raw: "" };
};

async function makeSuperUploadApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-super-upload-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore,
    velociraptorClient: new VelociraptorClient(superVeloCfg, superUploadRunner),
    artifactBundleStore: new ArtifactBundleStore(pathJoin(dirname(root), "bundles")),
    veloHuntStore: new VeloHuntStore(store),
    superTimelineStore: new SuperTimelineStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

// ── Full query + label routes (Task 6) ──────────────────────────────────────────────────────────
// Seed the super-timeline directly through the wired store so time-range/label assertions are
// deterministic (no dependence on an importer's timestamps).
async function makeQueryApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-super-query-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, superTimelineStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await superTimelineStore.append("c1", [
    { id: "e-early", timestamp: "2026-05-01T00:00:00Z", description: "early event", severity: "Low", sources: ["ToolA"] },
    { id: "e-mid", timestamp: "2026-06-01T12:00:00Z", description: "in-range event", severity: "High", sources: ["ToolB"] },
    { id: "e-late", timestamp: "2026-07-01T00:00:00Z", description: "late event", severity: "Low", sources: ["ToolA"] },
  ]);
  return { app };
}

describe("super-timeline query + label routes", () => {
  it("GET super-timeline honors from/to/origins/offset/limit and returns facets", async () => {
    const { app } = await makeQueryApp();
    const r = await request(app).get(`/cases/c1/super-timeline?from=2026-06-01T00:00:00Z&to=2026-06-02T00:00:00Z`);
    expect(r.status).toBe(200);
    expect(r.body).toHaveProperty("events");
    expect(r.body).toHaveProperty("total");
    expect(r.body).toHaveProperty("origins");
    expect(r.body).toHaveProperty("labelsAvailable");
    // Only the mid event falls in the sub-range.
    expect(r.body.events.map((e: { id: string }) => e.id)).toEqual(["e-mid"]);
    expect(r.body.total).toBe(1);

    // origins filter keeps only ToolA events; limit/offset paginate the matched set.
    const byOrigin = await request(app).get(`/cases/c1/super-timeline?origins=ToolA`);
    expect(byOrigin.body.total).toBe(2);
    const paged = await request(app).get(`/cases/c1/super-timeline?origins=ToolA&offset=1&limit=1`);
    expect(paged.body.total).toBe(2);
    expect(paged.body.events.length).toBe(1);
  });

  // The dashboard's main filter bar (search box + Exclude chips) narrows the super-timeline too, not
  // just the forensic timeline — wired via ?q= and ?excludeText=.
  it("q= narrows to events matching the main filter's free-text search", async () => {
    const { app } = await makeQueryApp();
    const r = await request(app).get(`/cases/c1/super-timeline?q=in-range`);
    expect(r.body.events.map((e: { id: string }) => e.id)).toEqual(["e-mid"]);
    expect(r.body.total).toBe(1);
  });

  it("excludeText= hides events matching any exclude term", async () => {
    const { app } = await makeQueryApp();
    const r = await request(app).get(`/cases/c1/super-timeline?excludeText=early,late`);
    expect(r.body.events.map((e: { id: string }) => e.id)).toEqual(["e-mid"]);
  });

  it("POST label sets labels that then filter the query", async () => {
    const { app } = await makeQueryApp();
    const listed = await request(app).get(`/cases/c1/super-timeline`);
    expect(listed.body.events.length).toBeGreaterThan(0);
    const id = listed.body.events[0].id;
    const lbl = await request(app).post(`/cases/c1/super-timeline/label`).send({ eventId: id, labels: ["key-evidence"] });
    expect(lbl.status).toBe(200);
    expect(lbl.body).toEqual({ eventId: id, labels: ["key-evidence"] });
    const filtered = await request(app).get(`/cases/c1/super-timeline?labels=key-evidence`);
    expect(filtered.body.events.map((e: { id: string }) => e.id)).toContain(id);
    expect(filtered.body.labelsAvailable).toContain("key-evidence");
  });

  it("POST label 400s without an eventId", async () => {
    const { app } = await makeQueryApp();
    const res = await request(app).post(`/cases/c1/super-timeline/label`).send({ labels: ["x"] });
    expect(res.status).toBe(400);
  });

  it("GET super-timeline 501s when the store is not configured", async () => {
    const { app } = await harness({ withStore: false });
    expect((await request(app).get("/cases/c1/super-timeline/label")).status).toBe(404); // no route match on GET
    expect((await request(app).post("/cases/c1/super-timeline/label").send({ eventId: "x" })).status).toBe(501);
  });
});

// ── Tag-driven Labels filter (unify super-timeline labelling with analyst tags) ──────────────────
// The super-timeline's Labels filter + labelsAvailable facet now come from the case's analyst TAGS
// (targetType "event"), not the legacy per-event label sidecar. Wire a TagsStore, tag a super event
// via the tags API, then GET ...?labels=<tag> and assert it filters + the facet lists the tag.
async function makeTaggedApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-super-tags-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const tagsStore = new TagsStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, superTimelineStore, tagsStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await superTimelineStore.append("c1", [
    { id: "e-tagme", timestamp: "2026-06-01T12:00:00Z", description: "event to tag", severity: "High", sources: ["ToolB"] },
    { id: "e-other", timestamp: "2026-06-02T12:00:00Z", description: "untagged event", severity: "Low", sources: ["ToolA"] },
  ]);
  return { app };
}

describe("super-timeline Tags filter (unified with analyst tags)", () => {
  it("tagging an event surfaces it via labels=<tag> and lists the tag in labelsAvailable", async () => {
    const { app } = await makeTaggedApp();
    // Tag the super event through the tags API (targetType "event").
    const tagRes = await request(app).post("/cases/c1/tags").send({ targetType: "event", targetId: "e-tagme", label: "key-evidence" });
    expect(tagRes.status).toBe(201);

    // The facet now lists the tag (before any label filter is applied).
    const all = await request(app).get("/cases/c1/super-timeline");
    expect(all.body.labelsAvailable).toContain("key-evidence");

    // Filtering by the tag returns ONLY the tagged event.
    const filtered = await request(app).get("/cases/c1/super-timeline?labels=key-evidence");
    expect(filtered.body.events.map((e: { id: string }) => e.id)).toEqual(["e-tagme"]);
    expect(filtered.body.total).toBe(1);

    // A non-existent tag matches nothing.
    const none = await request(app).get("/cases/c1/super-timeline?labels=no-such-tag");
    expect(none.body.total).toBe(0);
  });

  it("tagged=1 keeps only events carrying at least one tag", async () => {
    const { app } = await makeTaggedApp();
    // Before any tagging, tagged=1 returns nothing.
    const empty = await request(app).get("/cases/c1/super-timeline?tagged=1");
    expect(empty.body.total).toBe(0);

    await request(app).post("/cases/c1/tags").send({ targetType: "event", targetId: "e-tagme", label: "key-evidence" });
    const tagged = await request(app).get("/cases/c1/super-timeline?tagged=1");
    expect(tagged.body.events.map((e: { id: string }) => e.id)).toEqual(["e-tagme"]);
    expect(tagged.body.total).toBe(1);
  });
});

// ── Promote super events into the forensic timeline (Task 7) ─────────────────────────────────────
// "Promote" copies selected super-timeline events UP into the forensic timeline (where AI synthesis
// runs). Seed super events through the wired store, then promote by id. Idempotent: mergeDelta dedups
// forensic events by id, so a double-promote is a no-op. The runtime pipeline here has NO AI provider,
// so re-synthesis no-ops — the promote must still succeed and save state (like every state-mutating route).
async function makePromoteApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-super-promote-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, superTimelineStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await superTimelineStore.append("c1", [
    { id: "e-promote", timestamp: "2026-06-01T12:00:00Z", description: "raw MFT event", severity: "High", sources: ["ToolB"] },
  ]);
  return { app, stateStore };
}

describe("super-timeline promote route", () => {
  it("promote copies a super event into the forensic timeline (idempotent)", async () => {
    const { app, stateStore } = await makePromoteApp();
    const listed = await request(app).get(`/cases/c1/super-timeline`);
    expect(listed.body.events.length).toBeGreaterThan(0);
    const id = listed.body.events[0].id;
    // Not yet promoted: GET marks the row unpromoted so the UI has no false-positive badge.
    expect(listed.body.events.find((e: { id: string }) => e.id === id).promoted).toBe(false);

    const res = await request(app).post(`/cases/c1/super-timeline/promote`).send({ eventIds: [id] });
    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);

    const state1 = await stateStore.load("c1");
    expect(state1.forensicTimeline.some((e) => e.id === id)).toBe(true);

    // The row now carries a persistent "promoted" flag (survives reload/paging), which is what lets
    // the UI show a lasting "✓ Promoted" mark instead of only a one-time toast.
    const afterPromote = await request(app).get(`/cases/c1/super-timeline`);
    expect(afterPromote.body.events.find((e: { id: string }) => e.id === id).promoted).toBe(true);

    // idempotent: promoting again does not duplicate
    await request(app).post(`/cases/c1/super-timeline/promote`).send({ eventIds: [id] });
    const state2 = await stateStore.load("c1");
    expect(state2.forensicTimeline.filter((e) => e.id === id)).toHaveLength(1);
  });

  it("promote 400s without eventIds and 404s when none match", async () => {
    const { app } = await makePromoteApp();
    const bad = await request(app).post(`/cases/c1/super-timeline/promote`).send({});
    expect(bad.status).toBe(400);
    const none = await request(app).post(`/cases/c1/super-timeline/promote`).send({ eventIds: ["does-not-exist"] });
    expect(none.status).toBe(404);
  });

  it("promote 501s when the super-timeline store is not configured", async () => {
    const { app } = await harness({ withStore: false });
    const res = await request(app).post(`/cases/c1/super-timeline/promote`).send({ eventIds: ["x"] });
    expect(res.status).toBe(501);
  });
});

describe("superTimelineOnly bundle routing", () => {
  it("a superTimelineOnly bundle collects into the super-timeline only, not the forensic timeline", async () => {
    const { app, stateStore } = await makeSuperBundleApp();
    const forensicBefore = (await stateStore.load("c1")).forensicTimeline.length;

    const run = await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "super-timeline-triage" });
    expect(run.status).toBe(202);

    const collect = await request(app).post("/cases/c1/velociraptor/collect").send({});
    expect(collect.status).toBe(202);

    // The collect runs in the background (huntResultsByArtifact → parse → super-timeline append).
    // Poll the super-timeline until the raw rows land.
    let superRes = await request(app).get("/cases/c1/super-timeline");
    for (let i = 0; i < 80 && (superRes.body.total ?? 0) === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      superRes = await request(app).get("/cases/c1/super-timeline");
    }
    expect(superRes.status).toBe(200);
    expect(superRes.body.total).toBeGreaterThan(0);   // raw MFT row landed in the super-timeline

    const forensicAfter = (await stateStore.load("c1")).forensicTimeline.length;
    expect(forensicAfter).toBe(forensicBefore);       // forensic timeline untouched by the super-only bundle
  });

  it("a super-only bundle does NOT ingest uploaded reports into the forensic timeline", async () => {
    const { app, stateStore } = await makeSuperUploadApp();
    const forensicBefore = (await stateStore.load("c1")).forensicTimeline.length;

    const run = await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "super-timeline-triage" });
    expect(run.status).toBe(202);
    const collect = await request(app).post("/cases/c1/velociraptor/collect").send({});
    expect(collect.status).toBe(202);

    // Drive the background collect to completion off the hunt job's terminal status (the MFT row lands in
    // the super-timeline). Only THEN can we assert the forensic timeline is still empty — proving the
    // uploaded thor.json was skipped, not dispatched into the forensic timeline.
    let status: string | undefined;
    for (let i = 0; i < 120 && status !== "imported"; i++) {
      const jobs = await request(app).get("/cases/c1/velociraptor/hunt-jobs");
      status = (jobs.body as Array<{ status?: string }>)[0]?.status;
      if (status === "error") throw new Error("velo hunt collect errored");
      if (status !== "imported") await new Promise((r) => setTimeout(r, 25));
    }
    expect(status).toBe("imported");

    const superRes = await request(app).get("/cases/c1/super-timeline");
    expect(superRes.body.total).toBeGreaterThan(0);   // the raw MFT row still routed to the super-timeline

    const forensicAfter = (await stateStore.load("c1")).forensicTimeline.length;
    expect(forensicAfter).toBe(forensicBefore);       // the uploaded thor.json did NOT leak into forensic
  });

  it("re-collecting the same super-only hunt is idempotent (no duplicate events)", async () => {
    const { app } = await makeSuperBundleApp();

    const run = await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "super-timeline-triage" });
    expect(run.status).toBe(202);

    // The collect route (POST /velociraptor/collect) fires importVeloHuntResults in the BACKGROUND and
    // returns 202 before it finishes — polling the super-timeline for a total is a race under parallel
    // load. Instead drive each collect to COMPLETION deterministically off the hunt job's own status:
    // the import sets status `collecting` → `imported` (and stamps a fresh `importedAt`) when the
    // super-timeline append has fully landed. `collectUntilImported` waits for that terminal state.
    // (It also re-POSTs the collect, which was load-bearing before #195 — a collect landing on a hunt
    // that was still finishing used to be dropped outright. It is now coalesced, so the re-POST is
    // belt-and-braces against a slow import cycle rather than a workaround for a lost request.)
    async function jobStatus(): Promise<{ status?: string; importedAt?: string }> {
      const jobs = await request(app).get("/cases/c1/velociraptor/hunt-jobs");
      const job = (jobs.body as Array<{ status?: string; importedAt?: string }>)[0] ?? {};
      return { status: job.status, importedAt: job.importedAt };
    }
    // Wait until the job reaches a terminal `imported` state with an `importedAt` newer than `prevImportedAt`
    // (so a re-collect is observed as its OWN completed cycle, not the previous one). Re-fires the collect
    // if it didn't take, then polls. Never a fixed sleep on the super-timeline — a stable status condition.
    async function collectUntilImported(prevImportedAt?: string): Promise<void> {
      for (let attempt = 0; attempt < 40; attempt++) {
        expect((await request(app).post("/cases/c1/velociraptor/collect").send({})).status).toBe(202);
        for (let i = 0; i < 80; i++) {
          const { status, importedAt } = await jobStatus();
          if (status === "imported" && importedAt && importedAt !== prevImportedAt) return;
          if (status === "error") throw new Error("velo hunt collect errored");
          await new Promise((r) => setTimeout(r, 25));
        }
      }
      throw new Error("velo hunt collect never reached imported state");
    }

    // First collect → wait for it to fully import; the row must have landed in the super-timeline.
    await collectUntilImported();
    const firstImportedAt = (await jobStatus()).importedAt;
    const first = await request(app).get("/cases/c1/super-timeline");
    const totalAfterFirst = first.body.total ?? 0;
    expect(totalAfterFirst).toBeGreaterThan(0);

    // Second collect of the SAME hunt (Collect now / auto-collect firing) re-parses the SAME rows. Wait
    // for its OWN import cycle to complete (a newer importedAt), then assert the super-timeline total is
    // unchanged — hunt-scoped ids let dedupeAppend drop the repeats (with the old sequence-based ids this
    // doubled). No race: we assert only after the re-collect has deterministically settled.
    await collectUntilImported(firstImportedAt);
    const second = await request(app).get("/cases/c1/super-timeline");
    expect(second.body.total).toBe(totalAfterFirst);   // NOT doubled — idempotent re-collect
  });
});

// ── Bundle artifact validation against the server catalog ────────────────────────────────────────
// Velociraptor's hunt() rejects the ENTIRE hunt if any named artifact doesn't exist on the server, so
// the run-bundle route pre-flights the bundle against listClientArtifacts() and launches only the valid
// subset (reporting the rest as skippedArtifacts). A mock client lets us control the catalog + capture
// exactly which artifacts launchArtifactHunt() was invoked with.
interface CapturingVeloClient {
  listClientArtifacts(type?: "client" | "client_event"): Promise<Array<{ name: string; description: string }>>;
  launchArtifactHunt(artifacts: string[], desc: string, ...rest: unknown[]): Promise<{ huntId: string; guiUrl: string; artifacts: string[] }>;
}

async function makeCatalogApp(catalog: string[], bundleArtifacts: string[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-catalog-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const bundleStore = new ArtifactBundleStore(pathJoin(dirname(root), "bundles"));
  await bundleStore.save({ id: "custom-catalog-test", name: "Catalog Test", description: "d", superTimelineOnly: false, artifacts: bundleArtifacts });

  const launchCalls: string[][] = [];
  const client: CapturingVeloClient = {
    async listClientArtifacts() {
      return catalog.map((name) => ({ name, description: "" }));
    },
    async launchArtifactHunt(artifacts) {
      launchCalls.push(artifacts);
      return { huntId: "H.CATALOG1", guiUrl: "https://velo.example/hunt", artifacts };
    },
  };

  const app = createApp(store, {
    pipeline, stateStore,
    // The route only touches listClientArtifacts + launchArtifactHunt on the client for this path.
    velociraptorClient: client as unknown as Parameters<typeof createApp>[1]["velociraptorClient"],
    artifactBundleStore: bundleStore,
    veloHuntStore: new VeloHuntStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, launchCalls };
}

describe("run-bundle validates artifacts against the server catalog", () => {
  it("filters the bundle to the artifacts the server actually has and reports the skipped ones", async () => {
    const { app, launchCalls } = await makeCatalogApp(
      ["Windows.NTFS.MFT"],
      ["Windows.NTFS.MFT", "Windows.Bogus.DoesNotExist"],
    );
    const run = await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "custom-catalog-test" });
    expect(run.status).toBe(202);
    // launchArtifactHunt was called with ONLY the valid artifact.
    expect(launchCalls).toEqual([["Windows.NTFS.MFT"]]);
    expect(run.body.unknownArtifacts).toContain("Windows.Bogus.DoesNotExist");
  });

  it("returns 400 (and never launches) when NONE of the bundle's artifacts exist on the server", async () => {
    const { app, launchCalls } = await makeCatalogApp(
      ["Windows.NTFS.MFT"],
      ["Windows.Bogus.One", "Windows.Bogus.Two"],
    );
    const run = await request(app).post("/cases/c1/velociraptor/run-bundle").send({ bundleId: "custom-catalog-test" });
    expect(run.status).toBe(400);
    expect(run.body.error).toContain("Windows.Bogus.One");
    expect(launchCalls).toEqual([]);   // hunt never launched
  });
});

// ── starred=1 server-side filter (stars = the reserved "starred" analyst tag) ────────────────────
describe("super-timeline starred filter (server-side)", () => {
  const sev = (id: string, ts: string, description: string) => ({
    id, timestamp: ts, description, severity: "Info" as const,
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
  });

  it("keeps only events tagged 'starred' and hides the label from the facet", async () => {
    const { app, superStore } = await harness();
    await superStore!.append("c1", [
      sev("sv1", "2026-06-01T09:00:00Z", "benign row"),
      sev("sv2", "2026-06-01T10:00:00Z", "suspicious row"),
    ]);
    const t = await request(app).post("/cases/c1/tags")
      .send({ targetType: "event", targetId: "sv2", label: "starred", author: "an" });
    expect(t.status).toBe(201);

    const r = await request(app).get("/cases/c1/super-timeline?starred=1");
    expect(r.status).toBe(200);
    expect(r.body.events.map((e: { id: string }) => e.id)).toEqual(["sv2"]);
    expect(r.body.total).toBe(1);
    expect(r.body.labelsAvailable).not.toContain("starred");

    // Without the param both rows return (the filter is opt-in).
    const all = await request(app).get("/cases/c1/super-timeline");
    expect(all.body.total).toBe(2);
  });
});
