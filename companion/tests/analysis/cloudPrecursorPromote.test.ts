// #2563 (user decision 2026-11-11, "join in any order"): the check-first order. A versioning check
// imported before its key's privileged change is Info in its own file, so the settle's demote moves
// it to the super-timeline. When the change arrives, the CloudTrail import looks the check up there
// — by access key, call and time only — and promotes it into the forensic timeline at High with the
// precursor note. Real importers, real settle (dual-write → tagger → demote), real stores; the
// whole-file path at default aggregation and the streamed (gzip) path, as a drop folder imports
// the lab's per-slice files.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { settleForensicImport, type SettleDeps } from "../../src/routes/importSettle.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import { captureImportBaseline, releaseImportBaseline } from "../../src/analysis/importBaseline.js";
import { PRECURSOR_PROMOTE_MAX } from "../../src/analysis/ingest/cloudPrecursorPromote.js";
import { CLOUD_PRECURSOR_MARKER } from "../../src/analysis/cloudPrecursorMerge.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { ATTACK } from "./fixtures/sans504Lab.js";

type Rec = Record<string, unknown>;
const at = (r: Rec): string => String(r.eventTime);
const GRANT_FILE = ATTACK.filter((r) => at(r) < "2021-07-29T13:10:00Z");
const KEY_FILE = ATTACK.filter((r) => at(r) >= "2021-07-29T13:10:00Z" && at(r) < "2021-07-29T13:15:00Z");
const CHECK_FILE = ATTACK.filter((r) => at(r) >= "2021-07-29T14:00:00Z");

let root: string;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let lock: StateLock;
let p: AnalysisPipeline;
let gate: ForensicGateControlStore;
let n = 0;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-precursor-promote-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  gate = new ForensicGateControlStore(cases);
  lock = new StateLock();
  p = new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore,
    superTimelineStore: superStore,
    stateLock: lock,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  n = 0;
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const runExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => lock.runExclusive(caseId, fn);

function deps(): SettleDeps {
  const options = {
    stateStore,
    superTimelineStore: superStore,
    forensicGateControlStore: gate,
  } as unknown as AppOptions;
  const demote = createImportDemote({ options, runStateExclusive: runExclusive });
  return {
    stateStore,
    runStateExclusive: runExclusive,
    superTimelineStore: superStore,
    autoTagImported: async () => {},
    demoteForensic: demote.demoteForensic,
  };
}

/** One CloudTrail file through the whole-file importer and the settle seam. */
async function importFile(records: readonly Rec[], aggregate = true): Promise<void> {
  n++;
  const baseline = await captureImportBaseline(stateStore, "c1");
  try {
    await p.importAws("c1", JSON.stringify({ Records: records }), {
      label: `file-${n}.json`,
      idPrefix: `a${n}`,
      importedAt: `2026-11-11T10:0${n}:00.000Z`,
      ...(aggregate ? {} : { aws: { aggregate: false } }),
    });
    await settleForensicImport(deps(), "c1", baseline, `file-${n}.json`);
  } finally {
    await releaseImportBaseline(stateStore, baseline);
  }
}

/** One CloudTrail file as a gzip, through the streamed importer (the drop folder's path) and the settle. */
async function streamFile(records: readonly Rec[]): Promise<void> {
  n++;
  const path = join(root, `slice-${n}.json.gz`);
  await writeFile(path, gzipSync(JSON.stringify({ Records: records })));
  const baseline = await captureImportBaseline(stateStore, "c1");
  try {
    await p.importCloudFile("c1", "aws", path, {
      label: `slice-${n}.json.gz`,
      idPrefix: `s${n}`,
      importedAt: `2026-11-11T11:0${n}:00.000Z`,
    });
    await settleForensicImport(deps(), "c1", baseline, `slice-${n}.json.gz`);
  } finally {
    await releaseImportBaseline(stateStore, baseline);
  }
}

const forensic = async (): Promise<ForensicEvent[]> => (await stateStore.load("c1")).forensicTimeline;
const checks = async (): Promise<ForensicEvent[]> =>
  (await forensic()).filter((e) => e.canonical?.awsPrecursor?.role === "check");

describe("check first, change later: the check is promoted from the super-timeline (#2563)", () => {
  it("whole-file imports: the demoted check comes back at High with the promotion note", async () => {
    await importFile(CHECK_FILE);
    expect(await checks()).toEqual([]); // Info, demoted: it lives in the super-timeline only
    await importFile(GRANT_FILE);
    const [check] = await checks();
    expect(check.severity).toBe("High");
    expect(check.description).toContain(CLOUD_PRECURSOR_MARKER);
    expect(check.description).toMatch(/promoted from the super-timeline/);
    expect(check.description).toMatch(
      /PutUserPolicy \(granted to the caller itself\) at 2021-07-29T13:06:49Z/,
    );
    // It survives the next import's demote, and the case timeline says what was promoted.
    await importFile(KEY_FILE);
    expect((await checks()).map((e) => e.id)).toEqual([check.id]);
    const notes = (await stateStore.load("c1")).timeline.map((t) => t.description).join("\n");
    expect(notes).toMatch(/1 earlier S3 recovery check\(s\) promoted from the super-timeline to High/);
  });

  it("streamed (gzip) slices, check first: the same promotion", async () => {
    await streamFile(CHECK_FILE);
    expect(await checks()).toEqual([]);
    await streamFile(KEY_FILE);
    const [check] = await checks();
    expect(check?.severity).toBe("High");
    expect(check.description).toMatch(/iam CreateAccessKey at 2021-07-29T13:10:42Z/);
  });

  it("streamed (gzip) slices, change first: the check is raised in either order", async () => {
    await streamFile(GRANT_FILE);
    await streamFile(CHECK_FILE);
    const [check] = await checks();
    expect(check?.severity).toBe("High");
    expect(check.description).toMatch(/PutUserPolicy .* at 2021-07-29T13:06:49Z/);
  });

  it("promotes nothing when the change was made by a different key", async () => {
    await importFile(CHECK_FILE);
    const other = GRANT_FILE.map((r) => ({
      ...r,
      userIdentity: { ...(r.userIdentity as Rec), accessKeyId: "AKIAEXAMPLEOTHERKEY1" },
    }));
    await importFile(other);
    expect(await checks()).toEqual([]);
  });

  it("promotes nothing when the change failed", async () => {
    await importFile(CHECK_FILE);
    await importFile(
      GRANT_FILE.map((r) => (r.eventName === "PutUserPolicy" ? { ...r, errorCode: "AccessDenied" } : r)),
    );
    expect(await checks()).toEqual([]);
  });

  it("promotes nothing from before the change", async () => {
    const early = CHECK_FILE.map((r) => ({ ...r, eventTime: "2021-07-29T12:00:00Z" }));
    await importFile(early);
    await importFile(GRANT_FILE);
    expect(await checks()).toEqual([]);
  });

  it(`promotes at most ${PRECURSOR_PROMOTE_MAX} rows and says how many it left`, async () => {
    const many = Array.from({ length: PRECURSOR_PROMOTE_MAX + 7 }, (_, i) => ({
      ...CHECK_FILE[0],
      eventID: `00000000-2563-4000-8000-${String(i).padStart(12, "0")}`,
      eventTime: `2021-07-29T14:${String(Math.floor(i / 60) + 10).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`,
    }));
    await importFile(many, false); // one row per record, so the cap has rows to cap
    expect(await checks()).toEqual([]);
    await importFile(GRANT_FILE);
    const promoted = await checks();
    expect(promoted).toHaveLength(PRECURSOR_PROMOTE_MAX);
    // The earliest ones, in time order.
    expect(promoted[0].timestamp).toBe("2021-07-29T14:10:00Z");
    const notes = (await stateStore.load("c1")).timeline.map((t) => t.description).join("\n");
    expect(notes).toMatch(new RegExp(`${PRECURSOR_PROMOTE_MAX} earlier S3 recovery check\\(s\\) promoted`));
    expect(notes).toMatch(/7 more not promoted \(cap 50\)/);
  });
});

describe("checks folded across the change still join (#2563)", () => {
  // Default aggregation folds the same key's identical checks into one row that keeps the FIRST
  // time (12:00, before the 13:06 grant) and the last as endTimestamp (14:01, after it).
  const straddling = [
    { ...CHECK_FILE[0], eventID: "00000000-2563-4000-8000-0000000000a1", eventTime: "2021-07-29T12:00:00Z" },
    ...CHECK_FILE,
  ];

  for (const [name, load] of [
    ["whole-file", (r: readonly Rec[]) => importFile(r)],
    ["streamed", (r: readonly Rec[]) => streamFile(r)],
  ] as const) {
    it(`${name}, check first: the folded row is promoted`, async () => {
      await load(straddling);
      await load(GRANT_FILE);
      // Whole-file folds the two (first time 12:00); the stream may keep them apart. Either way the
      // row holding the 14:01 check is promoted and the 12:00-only row, if any, is not.
      const promoted = await checks();
      expect(promoted).toHaveLength(1);
      expect(promoted[0].severity).toBe("High");
      expect(promoted[0].endTimestamp ?? promoted[0].timestamp).toBe("2021-07-29T14:01:48Z");
      if (name === "whole-file") expect(promoted[0].timestamp).toBe("2021-07-29T12:00:00Z");
    });

    it(`${name}, change first: the folded row is raised`, async () => {
      await load(GRANT_FILE);
      await load(straddling);
      const [check] = await checks();
      expect(check?.severity).toBe("High");
    });
  }
});
