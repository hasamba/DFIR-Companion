import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { hashManifestValue } from "../../src/analysis/analysisRunHash.js";
import { investigationFingerprintOfCase, STATE_HASH_ID } from "../../src/analysis/analysisRunSnapshot.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { buildRuntimePipeline, createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #1891: an import replay settles like a live import — super-timeline write, content tagger, then
// demote (CLAUDE.md §7: merge-all → tagger → demote). It used to demote straight after the merge,
// so a rule-promoted Info row was demoted away and kept rows never reached the super-timeline.

const RULES = `spooler:
  any:
    - { field: message, contains: ['Spooler'] }
  tags: ['spooler']
  severity: High
`;

// Two Info rows (two hosts, so the importer does not fold them into one event): one a rule raises
// to High (kept), one no rule touches (demoted).
const SIEM = JSON.stringify([
  {
    "@timestamp": "2026-07-01T11:00:00.000Z",
    log_name: "System",
    computer_name: "S1-HOST",
    event_id: 7036,
    level: "Information",
    message: "The Print Spooler service entered the running state.",
  },
  {
    "@timestamp": "2026-07-01T11:05:00.000Z",
    log_name: "System",
    computer_name: "S2-HOST",
    event_id: 7036,
    level: "Information",
    message: "The Windows Update service entered the running state.",
  },
]);

const ARTIFACT = "imports/0001_siem.json";

let root: string;

afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
});

async function harness() {
  root = await mkdtemp(join(tmpdir(), "dfir-replay-settle-"));
  const cases = new CaseStore(root);
  const stateStore = new StateStore(cases);
  const superTimelineStore = new SuperTimelineStore(cases);
  const runStore = new AnalysisRunStore(cases, { appVersion: "0.33.0" });
  await writeFile(join(root, "rules.yaml"), RULES);
  const taggerStore = new TaggerStore(join(root, "user.yaml"), [join(root, "rules.yaml")]);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store: cases,
    analysisRunStore: runStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const importLock = new ImportLock();
  const app = createApp(cases, {
    importLock,
    pipeline,
    stateStore,
    superTimelineStore,
    tagsStore: new TagsStore(cases),
    taggerStore,
    forensicGateControlStore: new ForensicGateControlStore(cases),
    analysisRunStore: runStore,
    appVersion: "0.33.0",
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await mkdir(join(cases.caseDir("c1"), "imports"), { recursive: true });
  await writeFile(join(cases.caseDir("c1"), ARTIFACT), SIEM);
  await runStore.record("c1", {
    id: "siem-import",
    kind: "import",
    startedAt: "2026-07-31T10:00:00.000Z",
    finishedAt: "2026-07-31T10:00:01.000Z",
    versions: {
      importer: "siem/builtin-v1",
      schema: "investigation-state/v1",
      rules: hashManifestValue((await taggerStore.readActive()).text),
    },
    input: {
      artifacts: [{ path: ARTIFACT, sha256: createHash("sha256").update(SIEM).digest("hex") }],
      eventIds: [],
      entityIds: [],
    },
    configuration: {},
    output: { entityIds: [], hashes: [], claims: [] },
  });
  return { app, stateStore, superTimelineStore, runStore, importLock };
}

async function superEvents(store: SuperTimelineStore): Promise<ForensicEvent[]> {
  const out: ForensicEvent[] = [];
  for await (const batch of store.eventBatches("c1")) out.push(...batch);
  return out;
}

const mentions = (events: ForensicEvent[], text: string) =>
  events.filter((e) => JSON.stringify(e).includes(text));

describe("import replay settles like a live import (#1891)", () => {
  it("runs the tagger before demote and dual-writes the kept rows to the super-timeline", async () => {
    const { app, stateStore, superTimelineStore } = await harness();
    const replay = await request(app).post("/cases/c1/analysis-runs/siem-import/replay");
    expect(replay.status).toBe(200);

    const forensic = (await stateStore.load("c1")).forensicTimeline;
    // The rule-promoted row stays in the forensic timeline, graded up; the plain Info row is demoted.
    const spooler = mentions(forensic, "Print Spooler");
    expect(spooler).toHaveLength(1);
    expect(spooler[0].severity).toBe("High");
    expect(mentions(forensic, "Windows Update")).toHaveLength(0);

    // Both rows are in the super-timeline: the kept one by the dual-write, the demoted one by demote.
    const superRows = await superEvents(superTimelineStore);
    expect(mentions(superRows, "Print Spooler")).toHaveLength(1);
    expect(mentions(superRows, "Windows Update")).toHaveLength(1);
  });

  it("records a changed-only child run fingerprinted from the case after the settle", async () => {
    const { app, stateStore, runStore } = await harness();
    expect((await request(app).post("/cases/c1/analysis-runs/siem-import/replay")).status).toBe(200);
    const child = (await runStore.list("c1")).find((r) => r.parentRunId === "siem-import");
    expect(child).toBeDefined();
    const after = await investigationFingerprintOfCase(stateStore, "c1");
    expect(child?.output.hashes).toEqual([{ id: STATE_HASH_ID, sha256: after.sha256 }]);
    const kept = (await stateStore.load("c1")).forensicTimeline.map((e) => e.id);
    expect(kept).toHaveLength(1);
    expect(child?.output.entityIds).toEqual(expect.arrayContaining(kept));
  });

  it("fails before dispatch when the import baseline cannot be captured", async () => {
    const { app, stateStore, runStore } = await harness();
    stateStore.captureImportBaseline = async () => {
      throw new Error("baseline unavailable");
    };
    const replay = await request(app).post("/cases/c1/analysis-runs/siem-import/replay");
    expect(replay.status).toBe(500);
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);
    expect((await runStore.list("c1")).filter((r) => r.parentRunId === "siem-import")).toHaveLength(0);
  });

  it("refuses, changing nothing, when the rules change while the replay waits for the case", async () => {
    const { app, stateStore, runStore, importLock } = await harness();
    const release = await importLock.acquire("c1");
    const replay = request(app)
      .post("/cases/c1/analysis-runs/siem-import/replay")
      .then((r) => r);
    await new Promise((resolve) => setTimeout(resolve, 300));
    // An analyst edits the rules while another import holds the case (user rules win over defaults).
    await writeFile(join(root, "user.yaml"), RULES.replace("severity: High", "severity: Medium"));
    release();
    const response = await replay;
    expect(response.status).toBe(500);
    expect(response.body.error).toContain("rules changed");
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);
    expect((await runStore.list("c1")).filter((r) => r.parentRunId === "siem-import")).toHaveLength(0);
  });
});
