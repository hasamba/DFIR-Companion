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
import { BULK_TAIL_BASE, placeBulkTail } from "../../src/analysis/incrementalMergeBulkTail.js";
import { NEW_ROW_BASE, type HeldRow } from "../../src/analysis/incrementalMergeRows.js";
import { MERGE_FLAG_LOAD, mergeIndexEntry } from "../../src/analysis/mergeIndex.js";
import {
  BULK_READ_MARKER,
  LOGGING_COVERAGE_ID,
  TRUNCATION_COVERAGE_ID,
} from "../../src/analysis/cloudBulkRead.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import type { MergeStoredRow } from "../../src/analysis/caseSqliteWorkerMerge.js";

// #2544: once the cloud bulk-read pass had output — a group summary, the truncation row or the
// object-logging coverage row — every later import took the full-state merge, because the pass
// re-emits those rows at the END of the timeline and the incremental chain step refused any row that
// moved. The SANS 504 lab (3,872 small CloudTrail files) took the full merge on 3,567 of 3,568
// imports, all for its dated object-logging note. The merge now holds everything the pass reads and
// places the re-emitted rows where the full merge's append puts them. Every test imports the same
// deltas into "full" (load → mergeDelta → save) and "inc" (mergeIntoCase) and compares a load of each
// after every step.

type Ev = Partial<ForensicEvent> & { id: string; timestamp: string };

const ACCOUNT = "123456789012";
const READER = `arn:aws:sts::${ACCOUNT}:assumed-role/app-role/sess-1`;
const OTHER = `arn:aws:sts::${ACCOUNT}:assumed-role/etl-role/sess-9`;

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

function cloudTrail(timestamp: string, action: string, principal: string, resource: string) {
  return createCanonicalEvent({
    event: { category: "cloud", type: "api_call", action },
    actor: { kind: "cloud_principal", name: principal },
    cloud: { provider: "aws", accountId: ACCOUNT, resource },
    network: { source: { address: "10.0.1.5" } },
    time: { observed: timestamp, normalized: timestamp },
    evidence: { rawRecords: [{ source: "test-cloudtrail", locator: `${action}:${timestamp}:${resource}` }] },
    producer: { importer: "test-cloudtrail", parserVersion: "1", mappingVersion: "1" },
  } as never);
}

function awsRow(id: string, timestamp: string, action: string, resource: string, principal = READER): Ev {
  return {
    id,
    timestamp,
    description: `AWS ${action} (s3.amazonaws.com) by ${principal} from 10.0.1.5`,
    asset: undefined,
    canonical: cloudTrail(timestamp, action, principal, resource),
  };
}

const read = (id: string, t: string, n: number, who = READER, severity = "Medium"): Ev => ({
  ...awsRow(id, t, "GetObject", `corp-data/obj-${id}-${n}.csv`, who),
  severity: severity as never,
});
/** An ordinary management row: an AWS row, but no read, no object record and no LOAD row. */
const mgmt = (id: string, t: string): Ev => awsRow(id, t, "GetBucketVersioning", "corp-eng");

function selectorRow(id: string, timestamp: string): Ev {
  const trail = `arn:aws:cloudtrail:us-east-1:${ACCOUNT}:trail/mgmt`;
  const canonical = cloudTrail(timestamp, "PutEventSelectors", "root", trail);
  return {
    id,
    timestamp,
    description: "AWS PutEventSelectors (cloudtrail.amazonaws.com) by root from 10.0.1.5",
    asset: undefined,
    canonical: {
      ...canonical,
      loggingChange: {
        provider: "aws",
        target: "mgmt",
        targetKind: "trail",
        state: "reconfigured",
        facts: [
          { name: "eventSelector[0]", value: "management All; data events: AWS::S3::Object arn:aws:s3" },
        ],
        priorStateInRecord: false,
        effectiveNotEstablished: false,
        denied: false,
      },
    } as never,
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
  root = await mkdtemp(join(tmpdir(), "dfir-incbulktail-"));
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
    timestamp: `2026-10-30T${String(10 + Math.floor(step / 60)).padStart(2, "0")}:${String(step % 60).padStart(2, "0")}:00.000Z`,
    sourceScreenshots: [`file-${step}.json`],
  };
}

/** The importer's demote, as importDemote.ts does it: Info rows deleted by row id, nothing else. */
async function demote(caseId: string): Promise<void> {
  const rows = await store.forensicRowsOutsideSeverities(caseId, ["Low", "Medium", "High", "Critical"]);
  await store.deleteForensicRows(
    caseId,
    rows.filter((r) => r.event.severity === "Info").map((r) => r.rowId),
  );
}

/** One import into both cases (then the demote, when asked); whether "inc" took the fast path. */
async function importBoth(d: AnalysisDelta, opts: { demote?: boolean } = {}): Promise<boolean> {
  const ctx = windowCtx();
  await store.save(mergeDelta(await store.load("full"), d, ctx));
  const out = await mergeIntoCase(store, "inc", d, ctx, (s) => mergeDelta(s, d, ctx));
  if (opts.demote) for (const c of ["full", "inc"]) await demote(c);
  return !out.complete;
}

async function expectSame(): Promise<InvestigationState> {
  const full = await store.load("full");
  const inc = await store.load("inc");
  expect(inc.forensicTimeline.map((e) => e.id)).toEqual(full.forensicTimeline.map((e) => e.id));
  expect({ ...inc, caseId: "x" }).toEqual({ ...full, caseId: "x" });
  return full;
}

/** Why the next import would take the full merge, or null — asked without importing anything. */
async function reasonFor(d: AnalysisDelta): Promise<string | null> {
  const out = await mergeIncrementally(store, "inc", d, windowCtx(), mergeIndexStamp());
  return out.ok ? null : out.reason;
}

const at = (d: number, h = 10, m = 0, s = 0) =>
  `2026-10-${String(d).padStart(2, "0")}T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}Z`;

const summaries = (s: InvestigationState) => s.forensicTimeline.filter((e) => e.id.startsWith("bulkread-"));

/** `n` reads by `who`, from read number `from`, one per 20 seconds from `start` minutes past 14:00. */
function reads(prefix: string, from: number, n: number, who = READER, severity = "Medium", day = 22): Ev[] {
  return Array.from({ length: n }, (_, i) => {
    const k = from + i;
    return read(`${prefix}${k}`, at(day, 14, Math.floor(k / 3), (k % 3) * 20), k, who, severity);
  });
}

describe("the merge index holds what the bulk-read pass reads and replaces (#2544)", () => {
  const entry = (e: Ev) => mergeIndexEntry(event(e) as unknown as ForensicEvent).flags;
  it("role assumptions, object records and the pass's own rows are LOAD rows", () => {
    const assume = {
      ...awsRow("a", at(20), "AssumeRole", `arn:aws:iam::${ACCOUNT}:role/app-role`, "alice"),
      description: "AWS AssumeRole (sts.amazonaws.com) by alice",
    };
    expect(entry(assume) & MERGE_FLAG_LOAD).toBe(MERGE_FLAG_LOAD);
    expect(entry(awsRow("p", at(20), "PutObject", "corp-data/x.csv")) & MERGE_FLAG_LOAD).toBe(
      MERGE_FLAG_LOAD,
    );
    for (const id of ["bulkread-abc123", TRUNCATION_COVERAGE_ID, LOGGING_COVERAGE_ID])
      expect(
        entry({ id, timestamp: at(20), description: `x ${BULK_READ_MARKER} y]` }) & MERGE_FLAG_LOAD,
      ).toBe(MERGE_FLAG_LOAD);
    expect(entry(mgmt("m", at(20))) & MERGE_FLAG_LOAD).toBe(0);
  });
});

describe("placeBulkTail — the bulk-read pass's appended rows (#2544)", () => {
  const ev = (id: string): ForensicEvent => ({ id, timestamp: at(20) }) as ForensicEvent;
  const stored = (rowId: number): MergeStoredRow => ({ rowId, ordinal: rowId, version: 1, payload: "{}" });
  const w = (id: string, pre: number, rowId?: number): HeldRow => ({
    event: ev(id),
    pre,
    ...(rowId !== undefined ? { stored: stored(rowId) } : {}),
  });
  const working = [w("a", 1, 1), w("bulkread-s1", 2, 2), w("b", 3, 3), w("n1", NEW_ROW_BASE)];

  it("keeps every row in place when nothing moved", () => {
    const out = placeBulkTail(
      working,
      working.map((h) => h.event),
    );
    expect(out).toEqual(working);
  });

  it("moves a re-emitted summary to the tail, keeping its stored row; a new one is a new row", () => {
    const out = placeBulkTail(working, ["a", "b", "n1", "bulkread-s1", "bulkread-s2"].map(ev));
    if (typeof out === "string") throw new Error(out);
    expect(out.map((h) => [h.event.id, h.pre, h.stored?.rowId])).toEqual([
      ["a", 1, 1],
      ["b", 3, 3],
      ["n1", NEW_ROW_BASE, undefined],
      ["bulkread-s1", BULK_TAIL_BASE, 2],
      ["bulkread-s2", BULK_TAIL_BASE + 1, undefined],
    ]);
  });

  it("falls back on a removed row that is not the pass's, or one that does not come back", () => {
    expect(placeBulkTail(working, ["a", "bulkread-s1", "n1"].map(ev))).toContain(
      "added, removed or reordered",
    );
    expect(placeBulkTail(working, ["a", "b", "n1"].map(ev))).toContain("removed a stored row");
    expect(placeBulkTail(working, ["a", "bulkread-s1", "b", "n1", "x"].map(ev))).toContain(
      "added, removed or reordered",
    );
  });

  it("falls back when a kept row of the pass could equally be a re-emitted one", () => {
    const tailFirst = [w("a", 1, 1), w("bulkread-s1", 2, 2)];
    expect(placeBulkTail(tailFirst, ["a", "bulkread-s1", "bulkread-s2"].map(ev))).toContain("cannot tell");
  });
});

describe("imports stay incremental after a bulk-read group forms (#2544)", () => {
  it("a growing group: every later small import is incremental and equal to the full merge", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20))]))).toBe(false);
    let n = 0;
    for (let k = 1; k <= 14; k++) {
      const batch = reads("g", n, k <= 6 ? 10 : 3);
      n += batch.length;
      const fast = await importBoth(delta([...batch, mgmt(`m${k}`, at(21, 9, k))]));
      const s = await expectSame();
      expect(fast).toBe(true);
      if (n >= 50) expect(summaries(s)).toHaveLength(1);
    }
    const s = await expectSame();
    expect(summaries(s)[0].count).toBe(n);
  });

  it("rows at exactly the summary's time, stored before and arriving after, keep the full order", async () => {
    const first = at(22, 14);
    expect(await importBoth(delta([mgmt("seed", at(20)), mgmt("tieStored", first)]))).toBe(false);
    expect(await importBoth(delta([...reads("g", 0, 30), mgmt("x1", at(21))]))).toBe(true);
    await expectSame();
    expect(await importBoth(delta([...reads("g", 30, 30), mgmt("tieNew", first)]))).toBe(true);
    let s = await expectSame();
    expect(Date.parse(summaries(s)[0].timestamp)).toBe(Date.parse(first));
    expect(await importBoth(delta([...reads("g", 60, 5), mgmt("tieLater", first)]))).toBe(true);
    s = await expectSame();
    const ids = s.forensicTimeline.map((e) => e.id);
    expect(ids.indexOf(summaries(s)[0].id)).toBeGreaterThan(ids.indexOf("tieLater"));
  });

  it("an AssumeRole arriving in a later file raises a recurring reader's group, incrementally", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20))]))).toBe(false);
    expect(await importBoth(delta([read("d1", at(22, 3), 1), read("d2", at(23, 3), 2)]))).toBe(true);
    // Recurring (three distinct days) and no assumption: the group grades to nothing.
    expect(await importBoth(delta(reads("b", 0, 60, READER, "Medium", 24)))).toBe(true);
    expect(summaries(await expectSame())).toHaveLength(0);
    const assume: Ev = {
      ...awsRow("assume", at(24, 13, 50), "AssumeRole", `arn:aws:iam::${ACCOUNT}:role/app-role`, "alice"),
      description: "AWS AssumeRole (sts.amazonaws.com) by alice",
      canonical: cloudTrail(
        at(24, 13, 50),
        "AssumeRole",
        `arn:aws:iam::${ACCOUNT}:user/alice`,
        `arn:aws:iam::${ACCOUNT}:role/app-role`,
      ),
    };
    expect(await importBoth(delta([assume]))).toBe(true);
    const s = await expectSame();
    expect(summaries(s).some((e) => (e.description ?? "").includes("alice"))).toBe(true);
    expect(await importBoth(delta([mgmt("after", at(25))]))).toBe(true);
    await expectSame();
  });

  it("a second group beside a stored one, and a re-sent summary row, stay incremental", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20))]))).toBe(false);
    expect(await importBoth(delta(reads("g", 0, 60)))).toBe(true);
    const [one] = summaries(await expectSame());
    expect(await importBoth(delta([...reads("o", 0, 60, OTHER), mgmt("m1", at(21))]))).toBe(true);
    expect(summaries(await expectSame())).toHaveLength(2);
    expect(await importBoth(delta([one as Ev, mgmt("m2", at(21, 11))]))).toBe(true);
    expect(summaries(await expectSame())).toHaveLength(2);
  });

  it("Info reads demoted after every import: the summary stays, later imports stay incremental", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20))]), { demote: true })).toBe(false);
    expect(await importBoth(delta(reads("g", 0, 60, READER, "Info")), { demote: true })).toBe(true);
    let s = await expectSame();
    expect(summaries(s)).toHaveLength(1);
    expect(s.forensicTimeline.some((e) => e.id === "g0")).toBe(false);
    for (let k = 1; k <= 5; k++) {
      const fast = await importBoth(
        delta([...reads(`h${k}-`, 0, 4, READER, "Info"), mgmt(`m${k}`, at(21, k))]),
        {
          demote: true,
        },
      );
      expect(fast).toBe(true);
      s = await expectSame();
    }
  });
});

describe("the object-logging coverage row is re-emitted incrementally (#2544)", () => {
  it("LIST-only reads: the 'logging is off' row is replaced on every import, incrementally", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20))]))).toBe(false);
    expect(await importBoth(delta([awsRow("l1", at(21, 8), "ListObjects", "corp-data")]))).toBe(true);
    let s = await expectSame();
    expect(s.forensicTimeline.some((e) => e.id === LOGGING_COVERAGE_ID)).toBe(true);
    for (let k = 2; k <= 5; k++) {
      expect(await importBoth(delta([awsRow(`l${k}`, at(21, 7, k), "ListObjects", "corp-data")]))).toBe(true);
      s = await expectSame();
      expect(s.forensicTimeline.filter((e) => e.id === LOGGING_COVERAGE_ID)).toHaveLength(1);
    }
  });

  it("the dated note (the SANS 504 shape) follows the earliest AWS row, arriving or demoted", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20, 9))]))).toBe(false);
    expect(await importBoth(delta([selectorRow("sel", at(23, 12)), mgmt("m1", at(21))]))).toBe(true);
    let s = await expectSame();
    const note = () => s.forensicTimeline.find((e) => e.id === LOGGING_COVERAGE_ID);
    expect(note()?.timestamp).toBe(at(20, 9));
    for (let k = 2; k <= 6; k++) {
      expect(await importBoth(delta([mgmt(`m${k}`, at(21, k)), mgmt(`n${k}`, at(22, k))]))).toBe(true);
      s = await expectSame();
    }
    // An earlier AWS row arrives: the note's time moves to it.
    expect(await importBoth(delta([mgmt("early", at(19, 5))]))).toBe(true);
    s = await expectSame();
    expect(note()?.timestamp).toBe(at(19, 5));
    // An Info row even earlier, demoted after the import: the full merge saw it at merge time.
    expect(
      await importBoth(delta([{ ...mgmt("info", at(18, 5)), severity: "Info" }]), { demote: true }),
    ).toBe(true);
    s = await expectSame();
    expect(note()?.timestamp).toBe(at(18, 5));
    // The next merge no longer has that row: the note moves back, on both paths.
    expect(await importBoth(delta([mgmt("m9", at(22, 9))]))).toBe(true);
    s = await expectSame();
    expect(note()?.timestamp).toBe(at(19, 5));
  });

  it("an object write stored before the selector change arrives: no note, on both paths", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20, 9))]))).toBe(false);
    expect(
      await importBoth(delta([awsRow("put", at(21, 3), "PutObject", "corp-data/x.csv"), mgmt("m", at(21))])),
    ).toBe(true);
    await expectSame();
    expect(await importBoth(delta([selectorRow("sel", at(23, 12))]))).toBe(true);
    const s = await expectSame();
    expect(s.forensicTimeline.some((e) => e.id === LOGGING_COVERAGE_ID)).toBe(false);
  });

  it("the reason string no longer names the bulk-read pass for a plain later import", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20, 9))]))).toBe(false);
    expect(await importBoth(delta([selectorRow("sel", at(23, 12)), ...reads("g", 0, 0)]))).toBe(true);
    expect(await reasonFor(delta([mgmt("later", at(22))]))).toBeNull();
  });
});

describe("transitions the full merge leaves a stored summary behind on (#2544, plan review)", () => {
  it("an earlier read moves the group's start: a new id, the old summary kept, both paths alike", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20))]))).toBe(false);
    expect(await importBoth(delta(reads("g", 3, 60)))).toBe(true);
    const [before] = summaries(await expectSame());
    expect(await importBoth(delta([read("early", at(22, 13, 59, 40), 0), mgmt("m", at(21))]))).toBe(true);
    const s = await expectSame();
    expect(summaries(s).map((e) => e.id)).toContain(before.id);
    expect(summaries(s).length).toBeGreaterThanOrEqual(1);
  });

  it("a third reading day makes the reader recurring: its verdict goes, the stored summary stays", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20))]))).toBe(false);
    expect(await importBoth(delta(reads("g", 0, 60, READER, "Medium", 24)))).toBe(true);
    expect(summaries(await expectSame())).toHaveLength(1);
    expect(await importBoth(delta([read("d1", at(22, 3), 1)]))).toBe(true);
    await expectSame();
    expect(await importBoth(delta([read("d2", at(23, 3), 2), mgmt("m", at(21))]))).toBe(true);
    expect(summaries(await expectSame())).toHaveLength(1);
  });

  it("the metadata coverage row and a summary at the same instant keep the full merge's order", async () => {
    // The group's first read is the earliest cloud record, so both rows sit at its time.
    expect(await importBoth(delta(reads("g", 0, 60)))).toBe(false);
    for (let k = 1; k <= 3; k++) {
      expect(await importBoth(delta([...reads(`h${k}-`, 0, 2), mgmt(`m${k}`, at(23, k))]))).toBe(true);
      const s = await expectSame();
      const ids = s.forensicTimeline.map((e) => e.id);
      expect(ids).toContain("cloud-metadata-coverage");
      expect(ids.indexOf(summaries(s)[0].id)).toBeGreaterThan(ids.indexOf("cloud-metadata-coverage"));
    }
  });
});

describe("the dated note's start, held exactly (#2544, plan review)", () => {
  const note = (s: InvestigationState) => s.forensicTimeline.find((e) => e.id === LOGGING_COVERAGE_ID);

  it("equal instants spelled two ways: the first row in timeline order gives the string", async () => {
    expect(await importBoth(delta([mgmt("a", "2026-10-19T05:00:00.000Z")]))).toBe(false);
    expect(await importBoth(delta([selectorRow("sel", at(23, 12)), mgmt("b", "2026-10-19T05:00:00Z")]))).toBe(
      true,
    );
    let s = await expectSame();
    expect(note(s)?.timestamp).toBe("2026-10-19T05:00:00.000Z");
    expect(await importBoth(delta([mgmt("c", at(22))]))).toBe(true);
    s = await expectSame();
    expect(note(s)?.timestamp).toBe("2026-10-19T05:00:00.000Z");
  });

  it("the earliest AWS row re-sent with a later time, and a guessed-year row clamped forward", async () => {
    const guessed: Ev = { ...mgmt("guess", "2025-10-18T05:00:00Z"), yearInferred: true };
    expect(await importBoth(delta([mgmt("seed", at(20, 9)), ...file(6)]))).toBe(false);
    expect(await importBoth(delta([selectorRow("sel", at(23, 12)), guessed]))).toBe(true);
    let s = await expectSame();
    expect(await importBoth(delta([{ ...mgmt("seed", at(21, 9)) }]))).toBe(true);
    s = await expectSame();
    expect(await importBoth(delta([mgmt("z", at(24))]))).toBe(true);
    s = await expectSame();
    expect(note(s)).toBeDefined();
  });

  function file(n: number): Ev[] {
    return Array.from({ length: n }, (_, i) => mgmt(`f${i}`, at(21, 10, i)));
  }
});

describe("the AWS flow passes still take the full merge beside a summary (#2544)", () => {
  const PRIVATE_IP = "172.31.16.139";
  const canon = (id: string, ts: string, o: Record<string, unknown>) =>
    createCanonicalEvent({
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "test", locator: id }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
      ...o,
    } as never);
  const compute = (id: string, ts: string): Ev => ({
    id,
    timestamp: ts,
    asset: undefined,
    description: "AWS compute lifecycle i-0aaa1111bbbb",
    canonical: canon(id, ts, {
      event: { category: "cloud", type: "compute-lifecycle" },
      cloud: { provider: "aws", accountId: ACCOUNT, region: "us-east-1", resource: "i-0aaa1111bbbb" },
      awsCompute: {
        instanceId: "i-0aaa1111bbbb",
        account: ACCOUNT,
        region: "us-east-1",
        launch: {
          time: ts,
          locators: [id],
          by: "ops",
          groups: [],
          privateAddress: PRIVATE_IP,
          startupConfig: "not-in-record",
        },
        lifecycle: [],
        lifecycleBeyond: 0,
        rules: [],
        rulesBeyond: 0,
        addresses: [],
        remote: [],
        remoteBeyond: 0,
        attempts: { denied: 0, failed: 0 },
        facts: [],
        terminated: false,
        notCited: 0,
        coverage: { records: 1, first: ts, last: ts },
        basis:
          "records of this upload only; joined through the instance id; what ran on the instance and its network egress are not in CloudTrail",
      },
    }),
  });
  const flow = (id: string, ts: string): Ev => ({
    id,
    timestamp: ts,
    asset: undefined,
    severity: "Low",
    description: `AWS VPC flow ${PRIVATE_IP} -> 203.0.113.10 ACCEPT`,
    sources: ["AWS VPC Flow Logs"],
    srcIp: PRIVATE_IP,
    dstIp: "203.0.113.10",
    canonical: canon(id, ts, {
      event: { category: "network", type: "flow", action: "accept" },
      network: { source: { address: PRIVATE_IP }, destination: { address: "203.0.113.10" } },
      cloud: { provider: "aws", accountId: ACCOUNT },
    }),
  });

  it("a summary, a launch and a flow: the import falls back on launch and flow, equal to the full merge", async () => {
    expect(await importBoth(delta([mgmt("seed", at(20))]))).toBe(false);
    expect(await importBoth(delta([...reads("g", 0, 60), compute("C1", at(21, 8))]))).toBe(true);
    await expectSame();
    expect(await importBoth(delta([flow("F1", at(22, 15))]))).toBe(false);
    await expectSame();
    // The attributed flow now carries the attribution note, itself a trigger: still the full merge.
    expect(await reasonFor(delta([mgmt("later", at(23))]))).toMatch(
      /AWS compute record and VPC flow|correlation/,
    );
  });
});
