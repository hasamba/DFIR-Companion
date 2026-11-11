// #2563: the S3 ransomware-precursor join across separate CloudTrail uploads, in the merge chain.
// The SANS 504 lab fixture is split into three uploads at the real five-minute slice boundaries
// (grant ≤ 13:10, new key 13:10–13:15, versioning check 14:01). Each import goes into "full"
// (load → mergeDelta → save) and "inc" (mergeIntoCase); a load of each must be equal after every
// step, with the default demote (Info out) simulated between imports on both.
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
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import {
  CLOUD_PRECURSOR_MARKER,
  raiseCasePrecursors,
  raisePrecursorCheck,
} from "../../src/analysis/cloudPrecursorMerge.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import { ATTACK, ATTACKER_KEY, RESPONDER } from "./fixtures/sans504Lab.js";

type Rec = Record<string, unknown>;
const at = (r: Rec): string => String(r.eventTime);
const GRANT_FILE = ATTACK.filter((r) => at(r) < "2021-07-29T13:10:00Z");
const KEY_FILE = ATTACK.filter((r) => at(r) >= "2021-07-29T13:10:00Z" && at(r) < "2021-07-29T13:15:00Z");
const CHECK_FILE = [...ATTACK.filter((r) => at(r) >= "2021-07-29T14:00:00Z")];
const ROOT_CHECK = RESPONDER.filter((r) => r.eventName === "GetBucketVersioning");

let root: string;
let store: StateStore;
let step = 0;
/** Whether the last import took the incremental path (not the full-merge fallback). */
let lastIncremental = false;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-precursor-merge-"));
  const cases = new CaseStore(root);
  for (const caseId of ["full", "inc"])
    await cases.createCase({ caseId, name: caseId, investigator: "i", aiProvider: null });
  store = new StateStore(cases);
  step = 0;
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function upload(records: readonly Rec[]): ForensicEvent[] {
  step++;
  const rows = parseCloudTrail(JSON.stringify({ Records: records }), { aggregate: false }).events;
  return rows.map((e, i) => ({
    ...e,
    id: `f${step}e${i + 1}`,
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
}

function delta(events: ForensicEvent[]): AnalysisDelta {
  return deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicEvents: events,
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: `import of ${events.length} event(s)`,
    summary: "",
  });
}

function windowCtx(): WindowContext {
  return {
    windowSequence: -1,
    timestamp: `2026-11-11T10:${String(step).padStart(2, "0")}:00.000Z`,
    sourceScreenshots: [`file-${step}.json`],
  };
}

/** The default gate's demote: every Info row leaves the forensic timeline. */
async function demote(caseId: string): Promise<void> {
  const info = await store.forensicRowsOutsideSeverities(caseId, ["Critical", "High", "Medium", "Low"]);
  if (info.length)
    await store.deleteForensicRows(
      caseId,
      info.map((r) => r.rowId),
    );
}

/** One upload into both cases, the demote on both, then a check that both read the same. */
async function importBoth(records: readonly Rec[], extra: ForensicEvent[] = []): Promise<InvestigationState> {
  const d = delta([...upload(records), ...extra]);
  const ctx = windowCtx();
  await store.save(mergeDelta(await store.load("full"), d, ctx));
  const { complete } = await mergeIntoCase(store, "inc", d, ctx, (s) => mergeDelta(s, d, ctx));
  lastIncremental = !complete;
  for (const c of ["full", "inc"]) await demote(c);
  const full = await store.load("full");
  const inc = await store.load("inc");
  expect({ ...inc, caseId: "x" }).toEqual({ ...full, caseId: "x" });
  return full;
}

const versioning = (s: InvestigationState, who: RegExp): ForensicEvent[] =>
  s.forensicTimeline.filter(
    (e) => e.canonical?.event.action === "GetBucketVersioning" && who.test(e.description),
  );

describe("the precursor join across uploads, change first (#2563)", () => {
  it("raises the versioning check in a later file to High, saying 'earlier in this case'", async () => {
    await importBoth(GRANT_FILE);
    await importBoth(KEY_FILE);
    const s = await importBoth(CHECK_FILE);
    // The raise rode the incremental path: the stored change rows are LOAD rows, so it held them.
    expect(lastIncremental).toBe(true);
    const [check] = versioning(s, /example-user/);
    expect(check.severity).toBe("High");
    expect(check.description).toContain(
      `${CLOUD_PRECURSOR_MARKER} the same access key made a privileged change earlier in this case`,
    );
    expect(check.description).toMatch(
      /iam PutUserPolicy \(granted to the caller itself\) at 2021-07-29T13:06:49Z/,
    );
  });

  it("joins to CreateAccessKey alone when the grant file is never imported", async () => {
    await importBoth(KEY_FILE);
    const s = await importBoth(CHECK_FILE);
    expect(versioning(s, /example-user/)[0].description).toMatch(
      /iam CreateAccessKey at 2021-07-29T13:10:42Z/,
    );
  });

  it("leaves the responder's root check Info (it is demoted)", async () => {
    await importBoth(GRANT_FILE);
    const s = await importBoth(ROOT_CHECK);
    expect(versioning(s, /\[root\]/)).toEqual([]);
  });

  it("raises nothing when the check's key made no change", async () => {
    await importBoth(GRANT_FILE);
    const other = CHECK_FILE.map((r) => ({
      ...r,
      userIdentity: { ...(r.userIdentity as Rec), accessKeyId: "AKIAEXAMPLEOTHERKEY1" },
    }));
    const s = await importBoth(other);
    expect(versioning(s, /example-user/)).toEqual([]);
  });

  it("raises nothing when the change failed", async () => {
    const failed = GRANT_FILE.map((r) =>
      r.eventName === "PutUserPolicy" ? { ...r, errorCode: "AccessDenied", errorMessage: "denied" } : r,
    );
    await importBoth(failed);
    const s = await importBoth(CHECK_FILE);
    expect(versioning(s, /example-user/)).toEqual([]);
  });
});

describe("the precursor join across uploads, a stored check that survived the demote", () => {
  it("raises a stored Medium (denied) object-lock check when the change arrives later; both merges agree", async () => {
    const lock = CHECK_FILE.map((r) => ({
      ...r,
      eventName: "GetBucketObjectLockConfiguration",
      requestParameters: { bucketName: "example-eng" },
      errorCode: "AccessDenied",
      errorMessage: "Access Denied",
    }));
    const first = await importBoth(lock);
    const stored = first.forensicTimeline.find(
      (e) => e.canonical?.event.action === "GetBucketObjectLockConfiguration",
    );
    expect(stored?.severity).toBe("Medium");
    const lockRow = (s: InvestigationState) =>
      s.forensicTimeline.find((e) => e.canonical?.event.action === "GetBucketObjectLockConfiguration");
    const raised = lockRow(await importBoth(KEY_FILE));
    expect(raised?.severity).toBe("High");
    expect(raised?.description).toMatch(/iam CreateAccessKey at 2021-07-29T13:10:42Z/);
    // An earlier change arriving later leaves the raised row as it is: one note, never two.
    expect(lockRow(await importBoth(GRANT_FILE))).toEqual(raised);
  });
});

describe("the check-first promotion through both merges", () => {
  it("a change import carrying a promoted check reads the same on both sides", async () => {
    // What cloudPrecursorPromote.ts hands the merge: the super-timeline row, already raised.
    const [check] = upload(CHECK_FILE).filter((e) => e.canonical?.awsPrecursor?.role === "check");
    const [grant] = upload(GRANT_FILE).filter((e) => e.canonical?.awsPrecursor?.role === "change");
    const changes = new Map([
      [ATTACKER_KEY.toLowerCase(), { time: Date.parse(grant.timestamp), call: "iam X" }],
    ]);
    const promoted = raisePrecursorCheck({ ...check, id: "super-1" }, changes, "promoted")!;
    expect(promoted.severity).toBe("High");
    const s = await importBoth(GRANT_FILE, [promoted]);
    const rows = s.forensicTimeline.filter((e) => e.id === "super-1");
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toMatch(/promoted from the super-timeline/);
    expect(rows[0].description.split(CLOUD_PRECURSOR_MARKER)).toHaveLength(2);
  });
});

describe("the pass and its merge index", () => {
  const rows = (): ForensicEvent[] => {
    step = 0;
    return upload([...GRANT_FILE, ...CHECK_FILE]).map((e) => ({ ...e }));
  };

  it("leaves the import-time raise as it is (one note, never two)", () => {
    const once = rows();
    const check = once.find((e) => e.canonical?.event.action === "GetBucketVersioning")!;
    expect(check.description).toMatch(/earlier in this upload/);
    const again = raiseCasePrecursors(once);
    expect(again).toEqual(once);
  });

  it("marks change rows and open checks LOAD, never TRIGGER; a raised check is neither", () => {
    const parsed = upload(KEY_FILE);
    const change = parsed.find((e) => e.canonical?.event.action === "CreateAccessKey")!;
    const check = upload(CHECK_FILE).find((e) => e.canonical?.event.action === "GetBucketVersioning")!;
    expect(change.canonical?.authentication?.credentialId).toBe(ATTACKER_KEY);
    for (const e of [change, check]) {
      const flags = mergeIndexEntry(e).flags;
      expect(flags & MERGE_FLAG_LOAD, e.description).toBe(MERGE_FLAG_LOAD);
      expect(flags & MERGE_FLAG_TRIGGER, e.description).toBe(0);
    }
    const [, raised] = raiseCasePrecursors([change, check]);
    expect(raised.severity).toBe("High");
    expect(mergeIndexEntry(raised).flags & (MERGE_FLAG_LOAD | MERGE_FLAG_TRIGGER)).toBe(0);
  });
});
