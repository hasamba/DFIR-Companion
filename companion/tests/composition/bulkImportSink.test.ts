import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { buildBulkImportSink } from "../../src/composition/bulkImportSink.js";
import { settleForensicImport } from "../../src/routes/importSettle.js";

// The batched Velociraptor import wired to the REAL stores (#1439): sqlite state store, sqlite
// super-timeline, the tagger's ruleset and tag writer, the case gate. This is the seam the OOM went
// through, run end to end on a synthetic MFT map small enough for a test and forced onto the bulk
// path by DFIR_IMPORT_BULK_MIN_MB=0.

const IMPORTED_AT = "2026-09-20T07:00:00.000Z";
const PROMOTED_PATH = "\\\\.\\C:\\Windows\\Temp\\dropper.ps1";

// YAML single quotes keep backslashes literal: this is the one-backslash Windows path the row carries.
const RULES = `temp-ps1:
  any:
    - { field: path, contains: ['\\Windows\\Temp\\'] }
  tags: ['temp-script']
  mitre: ['T1059.001']
  severity: High
`;

function name(n: number): string {
  return n.toString(26).replace(/[0-9]/g, (d) => "qrstuvwxyz"[Number(d)]);
}

function mftRow(n: number, path = `\\\\.\\C:\\Users\\u\\${name(n)}.txt`) {
  const t = new Date(Date.UTC(2026, 0, 1, 0, 0, n)).toISOString();
  return {
    EntryNumber: n,
    InUse: true,
    OSPath: path,
    FileName: path.slice(path.lastIndexOf("\\") + 1),
    FileSize: 10,
    IsDir: false,
    Created0x10: t,
    LastModified0x10: t,
    LastRecordChange0x10: t,
    LastAccess0x10: t,
  };
}

let dir: string;
let cases: CaseStore;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let tagsStore: TagsStore;
let taggerStore: TaggerStore;
let gateStore: ForensicGateControlStore;
let logs: string[];

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-bulk-sink-"));
  cases = new CaseStore(dir);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  tagsStore = new TagsStore(cases, superStore);
  gateStore = new ForensicGateControlStore(cases);
  const def = join(dir, "default.yaml");
  await writeFile(def, RULES);
  taggerStore = new TaggerStore(join(dir, "user.yaml"), [def]);
  logs = [];
  delete process.env.TAGGER_AUTO;
  delete process.env.TAGGER_SCOPE;
  delete process.env.DFIR_FORENSIC_MIN_SEVERITY;
});

afterEach(async () => {
  delete process.env.TAGGER_AUTO;
  delete process.env.TAGGER_SCOPE;
  delete process.env.DFIR_FORENSIC_MIN_SEVERITY;
  await rm(dir, { recursive: true, force: true });
});

function sinkWith(env: NodeJS.ProcessEnv) {
  return buildBulkImportSink({
    stateStore,
    superTimelineStore: superStore,
    taggerStore,
    tagsStore,
    forensicGateControlStore: gateStore,
    log: (m) => logs.push(m),
    env: { ...process.env, ...env },
  });
}

function pipelineWith(sink: ReturnType<typeof sinkWith>) {
  return new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore,
    superTimelineStore: superStore,
    bulkImportSink: sink,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

describe("buildBulkImportSink", () => {
  it("is not wired without a super-timeline store", () => {
    expect(buildBulkImportSink({ stateStore, log: () => {} })).toBeUndefined();
  });

  it("reads the gate from the case override, then the env, then Low", async () => {
    const sink = sinkWith({})!;
    expect(await sink.forensicMinSeverity("c1")).toBe("Low");
    const withEnv = sinkWith({ DFIR_FORENSIC_MIN_SEVERITY: "High" })!;
    expect(await withEnv.forensicMinSeverity("c1")).toBe("High");
    await gateStore.set("c1", { minSeverity: "Medium" });
    expect(await withEnv.forensicMinSeverity("c1")).toBe("Medium");
  });

  it("opens no tagger when TAGGER_AUTO is off, and a real one otherwise", async () => {
    expect(await sinkWith({ TAGGER_AUTO: "false" })!.openTagger("c1", "forensic")).toBeNull();
    const tagger = await sinkWith({})!.openTagger("c1", "forensic");
    expect(tagger).not.toBeNull();
    expect(tagger!.rulesHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("importVelociraptor on the bulk path with real stores", () => {
  it("keeps only tagger-promoted rows in the forensic table, everything in the super-timeline, and survives settle", async () => {
    const sink = sinkWith({ DFIR_IMPORT_BULK_MIN_MB: "0", DFIR_IMPORT_BATCH_ROWS: "25" })!;
    const pipeline = pipelineWith(sink);
    const rows = Array.from({ length: 60 }, (_, i) => mftRow(i + 1));
    rows[40] = mftRow(41, PROMOTED_PATH);
    const text = JSON.stringify({ "Windows.NTFS.MFT": rows });

    const stateBefore = await stateStore.load("c1");
    const state = await pipeline.importVelociraptor("c1", text, {
      label: "0018_velo-flow_Windows.NTFS.MFT.json",
      idPrefix: "18",
      importedAt: IMPORTED_AT,
    });

    // The forensic table holds the one row the deterministic tagger raised out of Info — and only it.
    expect(state.forensicTimeline).toHaveLength(1);
    expect(state.forensicTimeline[0].path).toBe(PROMOTED_PATH);
    expect(state.forensicTimeline[0].severity).toBe("High");
    expect(state.forensicTimeline[0].mitreTechniques).toContain("T1059.001");
    expect(state.forensicTimeline[0].id).toBe("18e41");
    // The raw record is complete.
    const superRows = await superStore.query("c1", { limit: 1000 });
    expect(superRows.total).toBe(60);
    // The tag landed keyed by event id, so it lights up in both timelines.
    const tags = await tagsStore.load("c1");
    expect(tags.some((t) => t.targetId === "18e41" && t.label === "temp-script")).toBe(true);
    // The timeline note says which path ran and what it kept.
    const note = state.timeline.at(-1)?.description ?? "";
    expect(note).toMatch(
      /bulk path: 3 batch\(es\) of 25 rows\): 60 event\(s\) from 60 row\(s\); 1 kept in the forensic timeline, 60 in the super-timeline/,
    );
    // One log line per batch, written after the batch's rows were stored.
    expect(logs.filter((l) => /batch \d+ rows/.test(l))).toHaveLength(3);
    expect(logs.find((l) => /batch 2 rows 26–50/.test(l))).toMatch(/forensic \+1, super \+25/);

    // The settle seam that every import route runs afterwards must find nothing to demote and
    // report "+1 event": the bulk path did its work in the seam's order.
    let demoteCalls = 0;
    const settled = await settleForensicImport(
      {
        stateStore,
        superTimelineStore: superStore,
        autoTagImported: async () => {},
        demoteForensicForCase: async (caseId) => {
          demoteCalls++;
          return stateStore.load(caseId);
        },
      },
      "c1",
      stateBefore,
    );
    expect(settled.timelineDiff.added).toHaveLength(1);
    expect(settled.superTimelineAddedCount).toBe(0); // dedup by id — the batches already dual-wrote
    expect(demoteCalls).toBe(1);
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(1);
    expect((await superStore.query("c1", { limit: 1000 })).total).toBe(60);
  });

  it("stays on the whole-file path under the threshold", async () => {
    const sink = sinkWith({ DFIR_IMPORT_BULK_MIN_MB: "1" })!; // 1 MB; the fixture is a few KB
    const pipeline = pipelineWith(sink);
    const rows = Array.from({ length: 10 }, (_, i) => mftRow(i + 1));
    await pipeline.importVelociraptor("c1", JSON.stringify({ "Windows.NTFS.MFT": rows }), {
      label: "0001_small.json",
      idPrefix: "1",
      importedAt: IMPORTED_AT,
    });
    expect(logs.some((l) => l.includes("bulk path"))).toBe(false);
    // Whole-file behaviour: every row is merged into the forensic timeline for settle to demote later.
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(10);
  });
});
