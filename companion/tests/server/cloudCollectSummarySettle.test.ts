import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { RouteContext } from "../../src/routes/context.js";
import { caseCollectImporter } from "../../src/routes/cloudCollectImporter.js";
import type { CollectionSummaryRequest } from "../../src/integrations/cloudCollect/collectSummary.js";
import { isLineageRow, lineageIssuance, lineageUse } from "../helpers/awsLineageRecords.js";
import { trailRecord } from "../helpers/cloudCollectFakes.js";
import { failSettleAfterStamp } from "../helpers/settleFailure.js";

// #2482 (branch review) — the collection summary is landed and settled by the production importer.
// A crash after the summary committed but before its settle leaves rows the replay's baseline
// already holds; the settle tags only rows new to the case, so the replay must offer the summary's
// rows to the tagger itself before demote — or a Low lineage a promotion rule raises is demoted
// untagged out of the forensic timeline.

const RULES = `lineage-watch:
  any:
    - { field: description, contains: ['AWS credential lineage'] }
  tags: ['lineage-watch']
  severity: High
`;

let root: string;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let tagsStore: TagsStore;
let pipeline: AnalysisPipeline;
let ctx: RouteContext;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "collect-summary-settle-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  tagsStore = new TagsStore(cases);
  await writeFile(join(root, "rules.yaml"), RULES);
  const taggerStore = new TaggerStore(join(root, "user.yaml"), [join(root, "rules.yaml")]);
  const gate = new ForensicGateControlStore(cases);
  await gate.set("c1", { minSeverity: "Medium" }); // a Low row leaves the forensic timeline
  const lock = new StateLock();
  pipeline = new AnalysisPipeline({
    stateStore,
    superTimelineStore: superStore,
    cloudRecordStore: new CloudRecordStore(cases),
    stateLock: lock,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const runStateExclusive = <T>(c: string, fn: () => Promise<T>) => lock.runExclusive(c, fn);
  const options = {
    stateStore,
    superTimelineStore: superStore,
    forensicGateControlStore: gate,
    taggerStore,
    tagsStore,
    pipeline,
  } as unknown as AppOptions;
  const demote = createImportDemote({ options, runStateExclusive });
  ctx = {
    options,
    importLock: new ImportLock(),
    runStateExclusive,
    demoteForensic: demote.demoteForensic,
    demoteForensicForCase: demote.demoteForensicForCase,
    serverLogger: { info: () => {}, warn: () => {}, debug: () => {}, error: () => {} },
  } as unknown as RouteContext;
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(root, { recursive: true, force: true });
});

async function request(): Promise<CollectionSummaryRequest> {
  const path = join(root, "p000001-ct.json");
  // One issuance and one same-source use: a Low lineage.
  await writeFile(path, JSON.stringify({ Records: [lineageIssuance(0), lineageUse(2)] }));
  return {
    kind: "aws",
    collectionId: "cc-settle",
    pages: [{ path, records: 2 }],
    label: "evidence/cloud/cc-settle/summary-aws",
    idPrefix: "ccsettlesaws",
    importedAt: "2026-10-02T00:00:00Z",
  };
}

describe("collection summary settle on replay (#2482)", () => {
  it("a crash after the summary committed, before its settle: the replay tags the Low lineage before demote", async () => {
    const req = await request();
    // The dead attempt: the summary's rows committed, then the process died — no settle ran.
    const dead = await pipeline.importCloudCollectionSummary("c1", req.kind, req.pages, {
      collectionId: req.collectionId,
      label: req.label,
      idPrefix: req.idPrefix,
      importedAt: req.importedAt,
    });
    expect(dead.state.forensicTimeline.filter(isLineageRow).map((e) => e.severity)).toEqual(["Low"]);

    const importer = caseCollectImporter(ctx);
    await importer.withImportSection("c1", () => importer.importSummary("c1", req));

    const rows = (await stateStore.load("c1")).forensicTimeline.filter(isLineageRow);
    expect(rows.map((e) => e.severity)).toEqual(["High"]);
    expect(rows[0].id).toBe(dead.ids[0]);
    const superRows = (await superStore.query("c1", { limit: 100 })).events.filter(isLineageRow);
    expect(superRows.map((e) => e.id)).toEqual([dead.ids[0]]);
  });

  it("a first build settles the same way: the rule raises the new Low lineage and it stays", async () => {
    const req = await request();
    const importer = caseCollectImporter(ctx);
    await importer.withImportSection("c1", () => importer.importSummary("c1", req));
    const rows = (await stateStore.load("c1")).forensicTimeline.filter(isLineageRow);
    expect(rows.map((e) => e.severity)).toEqual(["High"]);
  });
});

// #2891 (gap 3): a page or summary whose settle fails still fails the collection, but the rows it
// already merged are stamped, dual-written and tagged first, so the next demote cannot move them
// out untagged (that used to wait for an analyst's Resume).
describe("a failed settle still grades the rows before the collection fails (#2891)", () => {
  it("a summary: the rule raises the Low lineage before demote, and the error surfaces", async () => {
    const req = await request();
    const fired = failSettleAfterStamp(stateStore);
    const importer = caseCollectImporter(ctx);
    await expect(importer.withImportSection("c1", () => importer.importSummary("c1", req))).rejects.toThrow(
      "out of memory",
    );
    expect(fired()).toBe(true);
    const rows = (await stateStore.load("c1")).forensicTimeline.filter(isLineageRow);
    expect(rows.map((e) => e.severity)).toEqual(["High"]);
    const superRows = (await superStore.query("c1", { limit: 100 })).events.filter(isLineageRow);
    expect(superRows.map((e) => e.id)).toEqual([rows[0].id]);
  });

  it("a page: its rows are stamped, dual-written and demoted, and the error surfaces", async () => {
    const path = join(root, "p000001-ct.json");
    await writeFile(path, JSON.stringify({ Records: [1, 2].map((i) => trailRecord(i)) }));
    const label = "evidence/cloud/cc-fail/p000001-ct.json";
    const fired = failSettleAfterStamp(stateStore);
    const importer = caseCollectImporter(ctx);
    const page = {
      kind: "aws" as const,
      path,
      label,
      idPrefix: "ccfailp1",
      importedAt: "2026-10-02T00:00:00Z",
      collectionId: "cc-fail",
    };
    await expect(importer.withImportSection("c1", () => importer.importPage("c1", page))).rejects.toThrow(
      "out of memory",
    );
    expect(fired()).toBe(true);
    const mine = (e: { sourceScreenshots: string[] }) => e.sourceScreenshots.includes(label);
    const superRows = (await superStore.query("c1", { limit: 100 })).events.filter(mine);
    expect(superRows.length).toBeGreaterThan(0); // dual-written: nothing lost to the demote
    // Nothing of the page is left below the case's Medium gate, and what stays carries the stamp.
    const kept = (await stateStore.load("c1")).forensicTimeline.filter(mine);
    expect(kept.every((e) => e.importBatchId && e.severity !== "Info" && e.severity !== "Low")).toBe(true);
  });
});
