import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { deltaSchema, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { mergeDelta, type WindowContext } from "../../src/analysis/stateMerge.js";
import { mergeIntoCase } from "../../src/analysis/caseMerge.js";
import { MERGE_FLAG_LOAD, MERGE_FLAG_TRIGGER, mergeIndexEntry } from "../../src/analysis/mergeIndex.js";
import { LOGGING_COVERAGE_ID } from "../../src/analysis/cloudBulkRead.js";
import { COVERAGE_SOURCE, isCoverageNote } from "../../src/analysis/coverageEventTime.js";
import { demoteBelowSeverity } from "../../src/analysis/forensicGate.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// #2564: the time-aware object-logging note (#2542) depends on a CloudTrail selector-change row
// (PutEventSelectors selecting AWS::S3::Object). That row was neither a trigger nor a LOAD row, so
// once stored, a later import never re-read it: the incremental merge took the fast path and left the
// note at its stored place and start time, while the full merge re-emitted it. A selector row that
// selects S3 object activity is now a LOAD row, so the merge sees the note is due. It then fell back;
// since #2544 it re-emits the note on the incremental path (incrementalMergeBulkTail.ts) and falls
// back only to withdraw a contradicted note.
// Every test runs the same imports into "full" (load → mergeDelta → save) and "inc" (mergeIntoCase)
// and compares what a load of each returns after every step.

type Ev = Partial<ForensicEvent> & { id: string; timestamp: string };

const ACCOUNT = "123456789012";
const READER = `arn:aws:sts::${ACCOUNT}:assumed-role/app-role/sess-1`;
const T = "2026-10-20T23:53:36Z";

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

/** A PutEventSelectors row; `value` is the resulting selector the importer records. */
function selectorRow(
  id: string,
  value = "management All; data events: AWS::S3::Object arn:aws:s3",
  timestamp = T,
): Ev {
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
        facts: [{ name: "eventSelector[0]", value }],
        priorStateInRecord: false,
        effectiveNotEstablished: false,
        denied: false,
      },
    } as never,
  };
}

const mgmtRow = (id: string, t: string) => awsRow(id, t, "GetBucketVersioning", "example-eng");
const objectRow = (id: string, t: string) => awsRow(id, t, "GetObject", "example-log/AWSLogs/x.json.gz");

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
  root = await mkdtemp(join(tmpdir(), "dfir-incobjlog-"));
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

/** One import into both cases, then a check that a load of each returns the same state. */
async function importBoth(events: Ev[]): Promise<InvestigationState> {
  const d = delta(events);
  const ctx = windowCtx();
  await store.save(mergeDelta(await store.load("full"), d, ctx));
  await mergeIntoCase(store, "inc", d, ctx, (s) => mergeDelta(s, d, ctx));
  const full = await store.load("full");
  const inc = await store.load("inc");
  expect({ ...inc, caseId: "x" }).toEqual({ ...full, caseId: "x" });
  return full;
}

const at = (d: number, h: number, m = 0) =>
  `2026-10-${String(d).padStart(2, "0")}T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:00Z`;
const notes = (s: InvestigationState) => s.forensicTimeline.filter((e) => e.id === LOGGING_COVERAGE_ID);

describe("incremental merge — the time-aware object-logging note (#2564)", () => {
  it("selector first, later object reads after T: the note is equal on both sides", async () => {
    await importBoth([mgmtRow("m1", at(20, 13)), selectorRow("sel")]);
    const s = await importBoth([objectRow("o1", at(21, 16)), objectRow("o2", at(21, 16, 1))]);
    expect(notes(s)).toHaveLength(1);
    expect(notes(s)[0].description).toContain("Cloud object logging begins at 2026-10-20T23:53:36Z");
  });

  it("a later import with an earlier non-object AWS record moves the note's start on both sides", async () => {
    await importBoth([mgmtRow("m1", at(20, 13)), selectorRow("sel")]);
    const s = await importBoth([mgmtRow("m0", at(19, 8))]);
    expect(notes(s).map((e) => e.timestamp)).toEqual([at(19, 8)]);
  });

  it("an unrelated later import keeps both sides equal", async () => {
    await importBoth([mgmtRow("m1", at(20, 13)), selectorRow("sel")]);
    const s = await importBoth([mgmtRow("m2", at(22, 9))]);
    expect(notes(s)).toHaveLength(1);
  });

  it("object reads first, selector later: the note appears and both sides are equal", async () => {
    await importBoth([mgmtRow("m1", at(20, 13)), objectRow("o1", at(21, 16))]);
    const s = await importBoth([selectorRow("sel")]);
    expect(notes(s)).toHaveLength(1);
  });

  it("an object read before T in a later import withdraws the note on both sides", async () => {
    // #2564 part B: the note says no object records exist before T; one now does, so it must go.
    const first = await importBoth([mgmtRow("m1", at(20, 13)), selectorRow("sel")]);
    expect(notes(first)).toHaveLength(1);
    const s = await importBoth([objectRow("o1", at(20, 14))]);
    expect(notes(s)).toEqual([]);
    const after = await importBoth([mgmtRow("m2", at(22, 9))]);
    expect(notes(after)).toEqual([]);
  });

  it("the same records imported together produce no note", async () => {
    const s = await importBoth([mgmtRow("m1", at(20, 13)), selectorRow("sel"), objectRow("o1", at(20, 14))]);
    expect(notes(s)).toEqual([]);
  });

  it("an object read after T in a later import keeps the note", async () => {
    await importBoth([mgmtRow("m1", at(20, 13)), selectorRow("sel")]);
    const s = await importBoth([objectRow("o1", at(21, 14))]);
    expect(notes(s)).toHaveLength(1);
    expect(notes(s)[0].description).toContain("Cloud object logging begins at");
  });

  it("the note keeps its id and stays exempt from the severity gate", async () => {
    await importBoth([mgmtRow("m1", at(20, 13)), selectorRow("sel")]);
    const s = await importBoth([mgmtRow("m2", at(22, 9))]);
    const inc = notes(await store.load("inc"));
    expect(inc.map((e) => e.id)).toEqual([LOGGING_COVERAGE_ID]);
    for (const note of [...notes(s), ...inc]) {
      expect(isCoverageNote(note)).toBe(true);
      expect(demoteBelowSeverity([note], "High").kept.map((e) => e.id)).toEqual([LOGGING_COVERAGE_ID]);
    }
  });
});

describe("mergeIndexEntry — selector-change rows (#2564)", () => {
  const entry = (e: Ev) => mergeIndexEntry(event(e) as unknown as ForensicEvent);

  it("a selector change that selects S3 object activity is a LOAD row, not a trigger", () => {
    const { flags } = entry(selectorRow("sel"));
    expect(flags & MERGE_FLAG_LOAD).toBe(MERGE_FLAG_LOAD);
    expect(flags & MERGE_FLAG_TRIGGER).toBe(0);
  });

  it("the stored object-logging note is a LOAD row, so the merge can withdraw it", () => {
    const note: Ev = {
      id: LOGGING_COVERAGE_ID,
      timestamp: at(20, 13),
      description: `Cloud object logging begins at 2026-10-20T23:53:36Z [cloud bulk read: no object-level records before it.]`,
      asset: undefined,
      sources: [COVERAGE_SOURCE],
    };
    const { flags } = entry(note);
    expect(flags & MERGE_FLAG_LOAD).toBe(MERGE_FLAG_LOAD);
    expect(flags & MERGE_FLAG_TRIGGER).toBe(0);
  });

  it("a selector change without S3 object selectors is neither", () => {
    const { flags } = entry(selectorRow("sel", "management All; no data events"));
    expect(flags & (MERGE_FLAG_LOAD | MERGE_FLAG_TRIGGER)).toBe(0);
  });
});
