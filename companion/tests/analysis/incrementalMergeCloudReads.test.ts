import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { deltaSchema, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { mergeDelta, type WindowContext } from "../../src/analysis/stateMerge.js";
import { mergeIndexStamp, mergeIntoCase } from "../../src/analysis/caseMerge.js";
import { mergeIncrementally } from "../../src/analysis/incrementalMerge.js";
import {
  MERGE_FLAG_LOAD,
  MERGE_FLAG_TRIGGER,
  mergeIndexEntry,
  mergeLoadAlways,
  mergeTrigger,
} from "../../src/analysis/mergeIndex.js";
import { BULK_READ_MARKER, LOGGING_COVERAGE_ID } from "../../src/analysis/cloudBulkRead.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// #2536: a cloud object read row (GetBucketPolicy, GetObject, ListObjects …) used to be a merge
// trigger, so ONE such row above Info sent every later import down the full merge — a drop folder of
// thousands of small CloudTrail files went quadratic. Read rows are now LOAD rows: every merge reads
// all of them. Until #2544 the merge then fell back whenever they formed a bulk-read group, a
// truncation or the object-logging coverage row; it now holds everything the pass reads and places
// what it re-emits (incrementalMergeBulkTail.ts), so those imports stay incremental too. Every test runs the same imports into "full" (load → mergeDelta →
// save) and "inc" (mergeIntoCase) and compares what a load of each returns after every step.

type Ev = Partial<ForensicEvent> & { id: string; timestamp: string };

const ACCOUNT = "123456789012";
const READER = `arn:aws:sts::${ACCOUNT}:assumed-role/app-role/sess-1`;

function event(e: Ev): Record<string, unknown> {
  return {
    description: `AWS CreateAccessKey by ops-${e.id} (iam.amazonaws.com)`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    asset: ACCOUNT,
    sources: ["AWS CloudTrail"],
    ...e,
  };
}

/** A valid CloudTrail-shaped canonical envelope (the AWS importer stamps one per row). */
function cloudTrail(timestamp: string, action: string, principal: string, resource: string, ip?: string) {
  return createCanonicalEvent({
    event: { category: "cloud", type: "api_call", action },
    actor: { kind: "cloud_principal", name: principal },
    cloud: { provider: "aws", accountId: ACCOUNT, resource },
    ...(ip ? { network: { source: { address: ip } } } : {}),
    time: { observed: timestamp, normalized: timestamp },
    evidence: { rawRecords: [{ source: "test-cloudtrail", locator: `${action}:${timestamp}:${resource}` }] },
    producer: { importer: "test-cloudtrail", parserVersion: "1", mappingVersion: "1" },
  } as never);
}

/** A CloudTrail read row as the importer stamps it: canonical envelope, no asset. */
function readRow(id: string, timestamp: string, action: string, resource: string, principal = READER): Ev {
  return {
    id,
    timestamp,
    description: `AWS ${action} (s3.amazonaws.com) by ${principal} from 10.0.1.5`,
    asset: undefined,
    canonical: cloudTrail(timestamp, action, principal, resource, "10.0.1.5"),
  };
}

function delta(events: Ev[]): AnalysisDelta {
  return deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicEvents: events.map(event),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: `import of ${events.length} event(s)`,
    summary: "",
  });
}

let root: string;
let store: StateStore;
let step = 0;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-increads-"));
  const cases = new CaseStore(root);
  for (const caseId of ["full", "inc"])
    await cases.createCase({ caseId, name: caseId, investigator: "i", aiProvider: null });
  store = new StateStore(cases);
  step = 0;
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function windowCtx(): WindowContext {
  step++;
  return {
    windowSequence: -1,
    timestamp: `2026-10-30T10:${String(step).padStart(2, "0")}:00.000Z`,
    sourceScreenshots: [`file-${step}.json`],
  };
}

/** One import into both cases; returns whether the incremental side took the fast path. */
async function importBoth(d: AnalysisDelta): Promise<boolean> {
  const ctx = windowCtx();
  await store.save(mergeDelta(await store.load("full"), d, ctx));
  const out = await mergeIntoCase(store, "inc", d, ctx, (s) => mergeDelta(s, d, ctx));
  return !out.complete;
}

async function expectSame(): Promise<InvestigationState> {
  const full = await store.load("full");
  const inc = await store.load("inc");
  expect({ ...inc, caseId: "x" }).toEqual({ ...full, caseId: "x" });
  return full;
}

const at = (d: number, h = 10, m = 0, s = 0) =>
  `2026-10-${String(d).padStart(2, "0")}T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}Z`;

/** A small CloudTrail file of `n` ordinary management rows. */
function file(prefix: string, d: number, n: number): Ev[] {
  return Array.from({ length: n }, (_, i) => ({ id: `${prefix}e${i + 1}`, timestamp: at(d, 9, i) }));
}

const summaries = (s: InvestigationState) =>
  s.forensicTimeline.filter((e) => (e.description ?? "").includes(BULK_READ_MARKER));

describe("cloud object reads in the merge index (#2536)", () => {
  it("is a LOAD row, not a trigger, even with no asset", () => {
    const row = event(readRow("r1", at(20), "GetBucketPolicy", "corp-data")) as unknown as ForensicEvent;
    const e = { ...row, asset: undefined } as ForensicEvent;
    expect(mergeTrigger(e)).toBeNull();
    expect(mergeLoadAlways(e)).toBe(true);
    const flags = mergeIndexEntry(e).flags;
    expect(flags & MERGE_FLAG_LOAD).toBe(MERGE_FLAG_LOAD);
    expect(flags & MERGE_FLAG_TRIGGER).toBe(0);
  });
});

describe("small cloud imports stay incremental after a read row (#2536)", () => {
  it("one early GetBucketPolicy leaves every later import on the fast path, equal to the full merge", async () => {
    expect(await importBoth(delta(file("f1", 20, 3)))).toBe(false); // an empty case: the full merge indexes it
    await expectSame();
    const withRead = [...file("f2", 20, 2), readRow("f2r", at(20, 11), "GetBucketPolicy", "corp-data")];
    expect(await importBoth(delta(withRead))).toBe(true);
    await expectSame();
    for (let k = 3; k <= 10; k++) {
      expect(await importBoth(delta(file(`f${k}`, 20 + (k % 3), 1 + (k % 5))))).toBe(true);
      const s = await expectSame();
      expect(s.forensicTimeline.some((e) => e.id === "f2r")).toBe(true);
    }
  });

  it("a few more bucket-level reads across files still take the fast path", async () => {
    expect(await importBoth(delta(file("a", 20, 2)))).toBe(false);
    for (let k = 1; k <= 4; k++) {
      const reads = [
        readRow(`r${k}`, at(20, 12, k), k % 2 ? "GetBucketAcl" : "GetBucketPolicy", `bucket-${k}`),
      ];
      expect(await importBoth(delta([...file(`b${k}`, 21, 2), ...reads]))).toBe(true);
      await expectSame();
    }
  });
});

describe("bulk-read findings still fire across files (#2536)", () => {
  it("200 GetObject by one principal over 20 files: one summary, equal to the full merge after every file", async () => {
    expect(await importBoth(delta(file("seed", 20, 2)))).toBe(false);
    let n = 0;
    for (let k = 1; k <= 20; k++) {
      const reads = Array.from({ length: 10 }, () => {
        n++;
        return readRow(
          `g${n}`,
          at(22, 14, Math.floor(n / 4), n % 60),
          "GetObject",
          `corp-data/file-${n}.csv`,
        );
      });
      const fast = await importBoth(delta(reads));
      const s = await expectSame();
      // Before and after the group forms at 50 objects, the import stays incremental (#2544: it used
      // to fall back from then on), and the summary is the full merge's.
      expect(fast).toBe(true);
      if (n >= 50) expect(summaries(s)).toHaveLength(1);
    }
    const next = delta([readRow("late", at(22, 15), "GetObject", "corp-data/late.csv")]);
    const out = await mergeIncrementally(store, "inc", next, windowCtx(), mergeIndexStamp());
    expect(out.ok).toBe(true);
  });

  it("a recurring reader whose AssumeRole row came in an earlier file stays incremental, equal to the full merge", async () => {
    // The assumption is the only corroboration: without it the scheduled principal grades to nothing,
    // with it the group is a summary. It arrives in an earlier file and is not re-sent.
    const assume: Ev = {
      id: "assume",
      timestamp: at(24, 13, 50),
      description: "AWS AssumeRole (sts.amazonaws.com) by alice",
      canonical: cloudTrail(
        at(24, 13, 50),
        "AssumeRole",
        `arn:aws:iam::${ACCOUNT}:user/alice`,
        `arn:aws:iam::${ACCOUNT}:role/app-role`,
      ),
    };
    expect(await importBoth(delta([assume, ...file("seed", 20, 2)]))).toBe(false);
    // Reads on two earlier days make the principal recurring (three distinct days with the bulk day).
    expect(await importBoth(delta([readRow("d1", at(22, 3), "GetObject", "corp-data/nightly.csv")]))).toBe(
      true,
    );
    expect(await importBoth(delta([readRow("d2", at(23, 3), "GetObject", "corp-data/nightly.csv")]))).toBe(
      true,
    );
    await expectSame();
    let n = 0;
    for (let k = 1; k <= 6; k++) {
      const reads = Array.from({ length: 10 }, () => {
        n++;
        return readRow(`b${n}`, at(24, 14, Math.floor(n / 4), n % 60), "GetObject", `corp-data/obj-${n}.csv`);
      });
      const fast = await importBoth(delta(reads));
      const s = await expectSame();
      expect(fast).toBe(true); // the AssumeRole row is a LOAD row since #2544
      if (n >= 50) {
        expect(summaries(s).some((e) => (e.description ?? "").includes("alice"))).toBe(true);
      }
    }
  });

  it("LIST-only reads that form the object-logging coverage row stay incremental, equal to the full merge", async () => {
    expect(await importBoth(delta(file("seed", 20, 2)))).toBe(false);
    expect(await importBoth(delta([readRow("l1", at(21, 8), "ListObjects", "corp-data")]))).toBe(true);
    let s = await expectSame();
    expect(s.forensicTimeline.some((e) => e.id === LOGGING_COVERAGE_ID)).toBe(true);
    expect(await importBoth(delta([readRow("l2", at(21, 9), "ListObjects", "corp-data")]))).toBe(true);
    s = await expectSame();
    expect(s.forensicTimeline.filter((e) => e.id === LOGGING_COVERAGE_ID)).toHaveLength(1);
  });

  it("a delta re-sending a stored summary row by id stays equal to the full merge", async () => {
    expect(await importBoth(delta(file("seed", 20, 2)))).toBe(false);
    const reads = Array.from({ length: 60 }, (_, i) =>
      readRow(`s${i}`, at(22, 15, Math.floor(i / 4), i % 60), "GetObject", `corp-data/s-${i}.csv`),
    );
    await importBoth(delta(reads));
    const stored = summaries(await expectSame());
    expect(stored).toHaveLength(1);
    const again = { ...stored[0], description: stored[0].description } as Ev;
    await importBoth(delta([again, ...file("after", 23, 2)]));
    expect(summaries(await expectSame())).toHaveLength(1);
  });
});
