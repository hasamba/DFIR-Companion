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
  MERGE_FLAG_AWS_FLOW,
  MERGE_FLAG_AWS_LAUNCH,
  MERGE_FLAG_LOAD,
  MERGE_FLAG_TRIGGER,
  mergeIndexEntry,
  mergeLoadAlways,
  mergeTrigger,
} from "../../src/analysis/mergeIndex.js";
import { METADATA_MARKER } from "../../src/analysis/cloudMetadataAccess.js";
import { FLOW_ATTRIBUTION_MARKER } from "../../src/analysis/awsFlowResourceAttribution.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// #2539: three more cloud rows used to be merge triggers — an instance-metadata row, an Azure storage
// key listing and an AWS compute summary — so ONE of them in the forensic timeline sent every later
// import down the full merge. Now the metadata passes are per-row rewrites (no trigger), storage key
// rows are LOAD rows gated on a join forming, and compute/flow rows are counted, gated on both being
// present. Every test runs the same imports into "full" (load → mergeDelta → save) and "inc"
// (mergeIntoCase) and compares what a load of each returns after every step.

type Ev = Partial<ForensicEvent> & { id: string; timestamp: string };

const ACCOUNT = "123456789012";
const ROLE = `arn:aws:sts::${ACCOUNT}:assumed-role/web-role/i-0abc12345678`;
const PRIVATE_IP = "172.31.16.139";
const producer = { importer: "test", parserVersion: "1", mappingVersion: "1" };
const BASIS =
  "records of this upload only; joined through the instance id; what ran on the instance and its network egress are not in CloudTrail";

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

function canon(id: string, ts: string, o: Record<string, unknown>) {
  return createCanonicalEvent({
    time: { observed: ts, normalized: ts },
    evidence: { rawRecords: [{ source: "test", locator: id }] },
    producer,
    ...o,
  } as never);
}

/** A CloudTrail row by an EC2 instance role (the instance-metadata pass's identity half). */
function roleRow(id: string, ts: string, ip: string): Ev {
  return {
    id,
    timestamp: ts,
    description: `AWS DescribeInstances by ${ROLE} from ${ip}`,
    asset: undefined,
    canonical: canon(id, ts, {
      event: { category: "cloud", type: "api_call", action: "DescribeInstances" },
      actor: { kind: "cloud_principal", name: ROLE },
      cloud: { provider: "aws", accountId: ACCOUNT, resource: "ec2" },
      network: { source: { address: ip } },
    }),
  };
}

/** A host process row that reads instance credentials from the metadata service. */
function imdsRow(id: string, ts: string): Ev {
  const cmd = "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role";
  return {
    id,
    timestamp: ts,
    asset: "web01",
    processName: "curl",
    commandLine: cmd,
    description: `Process ${cmd}`,
    sources: ["EDR"],
  };
}

/** An Azure Activity Log storage key listing (control plane, no asset). */
function listing(id: string, ts: string, acct = "stacct", outcome = "success"): Ev {
  return {
    id,
    timestamp: ts,
    asset: undefined,
    description: `Azure listKeys on ${acct}`,
    sources: ["Azure Activity"],
    canonical: canon(id, ts, {
      event: {
        category: "cloud",
        type: "storage-key-list",
        action: "Microsoft.Storage/storageAccounts/listKeys/action",
        outcome,
      },
      cloud: {
        provider: "azure",
        resource: `/subscriptions/s/resourceGroups/g/providers/Microsoft.Storage/storageAccounts/${acct}`,
      },
    }),
  };
}

/** An Azure Storage diagnostic-log read authenticated with an account key (data plane, no asset). */
function keyRead(id: string, ts: string, acct = "stacct"): Ev {
  return {
    id,
    timestamp: ts,
    asset: undefined,
    severity: "Low",
    description: `Azure Storage GetBlob (StorageRead) on ${acct}/c/${id} via account-key`,
    sources: ["Azure Storage Logs"],
    canonical: canon(id, ts, {
      event: { category: "cloud", type: "storage-object-op", action: "get blob", outcome: "success" },
      authentication: { mechanism: "account-key", credentialId: "key1(abc)" },
      cloud: { provider: "azure", resource: `${acct}/c/${id}` },
    }),
  };
}

/** An AWS compute lifecycle summary (awsImport), launching an instance on PRIVATE_IP. */
function compute(id: string, ts: string, inst = "i-0aaa1111bbbb"): Ev {
  return {
    id,
    timestamp: ts,
    asset: undefined,
    description: `AWS compute lifecycle ${inst}`,
    canonical: canon(id, ts, {
      event: { category: "cloud", type: "compute-lifecycle" },
      cloud: { provider: "aws", accountId: ACCOUNT, region: "us-east-1", resource: inst },
      awsCompute: {
        instanceId: inst,
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
        basis: BASIS,
      },
    }),
  };
}

/** An AWS VPC flow row (graded Low by the importer, so it sits in the forensic timeline). */
function flowRow(id: string, ts: string, src = PRIVATE_IP): Ev {
  return {
    id,
    timestamp: ts,
    asset: undefined,
    severity: "Low",
    description: `AWS VPC flow ${src} -> 203.0.113.10 ACCEPT`,
    sources: ["AWS VPC Flow Logs"],
    srcIp: src,
    dstIp: "203.0.113.10",
    canonical: canon(id, ts, {
      event: { category: "network", type: "flow", action: "accept" },
      network: { source: { address: src }, destination: { address: "203.0.113.10" } },
      cloud: { provider: "aws", accountId: ACCOUNT },
    }),
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

const at = (d: number, h = 10, m = 0) =>
  `2026-10-${String(d).padStart(2, "0")}T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:00Z`;

/** A small CloudTrail file of `n` ordinary management rows. */
function file(prefix: string, d: number, n = 2): Ev[] {
  return Array.from({ length: n }, (_, i) => ({ id: `${prefix}e${i + 1}`, timestamp: at(d, 9, i) }));
}

/** The parsed row as the importer would hand it to the merge (canonical schema applied). */
const parsed = (e: Ev): ForensicEvent => (delta([e]).forensicEvents ?? [])[0] as ForensicEvent;

describe("cloud merge triggers — index entries (#2539)", () => {
  it("none of the three rows, nor the metadata note, is a trigger any more", () => {
    for (const e of [
      roleRow("r", at(20), "203.0.113.9"),
      imdsRow("m", at(20)),
      listing("l", at(20)),
      compute("c", at(20)),
      flowRow("f", at(20)),
    ])
      expect(mergeTrigger(parsed(e))).toBeNull();
    expect(
      mergeTrigger(parsed({ id: "n", timestamp: at(20), description: `GET / ${METADATA_MARKER} x]` })),
    ).toBeNull();
  });

  it("storage key listings and account-key ops are LOAD rows, though they carry no asset", () => {
    expect(mergeLoadAlways(parsed(listing("l", at(20))))).toBe(true);
    expect(mergeLoadAlways(parsed(listing("l", at(20), "stacct", "failure")))).toBe(true);
    expect(mergeLoadAlways(parsed(keyRead("k", at(20))))).toBe(true);
    expect(mergeIndexEntry(parsed(listing("l", at(20)))).flags & MERGE_FLAG_LOAD).toBe(MERGE_FLAG_LOAD);
  });

  it("compute summaries and AWS flows are counted, not triggers", () => {
    const c = mergeIndexEntry(parsed(compute("c", at(20)))).flags;
    const f = mergeIndexEntry(parsed(flowRow("f", at(20)))).flags;
    expect(c & MERGE_FLAG_AWS_LAUNCH).toBe(MERGE_FLAG_AWS_LAUNCH);
    expect(c & (MERGE_FLAG_TRIGGER | MERGE_FLAG_AWS_FLOW)).toBe(0);
    expect(f & MERGE_FLAG_AWS_FLOW).toBe(MERGE_FLAG_AWS_FLOW);
    expect(f & (MERGE_FLAG_TRIGGER | MERGE_FLAG_AWS_LAUNCH)).toBe(0);
    expect(
      mergeIndexEntry(parsed(file("x", 20)[0])).flags & (MERGE_FLAG_AWS_LAUNCH | MERGE_FLAG_AWS_FLOW),
    ).toBe(0);
  });
});

describe("cloud merge triggers — incremental equals full (#2539)", () => {
  let root: string;
  let store: StateStore;
  let step = 0;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-inctrig-"));
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

  async function expectSame(): Promise<InvestigationState> {
    const full = await store.load("full");
    const inc = await store.load("inc");
    expect({ ...inc, caseId: "x" }).toEqual({ ...full, caseId: "x" });
    return full;
  }

  /** One import into both cases, then the equality check; returns whether inc took the fast path. */
  async function importBoth(events: Ev[]): Promise<boolean> {
    const d = delta(events);
    const ctx = windowCtx();
    await store.save(mergeDelta(await store.load("full"), d, ctx));
    const out = await mergeIntoCase(store, "inc", d, ctx, (s) => mergeDelta(s, d, ctx));
    await expectSame();
    return !out.complete;
  }

  /** A seed import, then each step; the fast-path flag of every import. */
  async function run(steps: Ev[][]): Promise<boolean[]> {
    const fasts = [await importBoth(file("seed", 20, 3))];
    for (const s of steps) fasts.push(await importBoth(s));
    return fasts;
  }

  /** Why the next merge would fall back (a probe; a fallback writes nothing). */
  async function fallbackReason(events: Ev[]): Promise<string> {
    const out = await mergeIncrementally(store, "inc", delta(events), windowCtx(), mergeIndexStamp());
    expect(out.ok).toBe(false);
    return out.ok ? "" : out.reason;
  }

  const row = (s: InvestigationState, id: string) => s.forensicTimeline.find((e) => e.id === id);
  const later = (n: number, d = 21) => Array.from({ length: n }, (_, k) => file(`b${k}`, d));

  it("instance-metadata rows stay incremental, are marked the same, and a re-send stays equal", async () => {
    const fasts = await run([
      [roleRow("pub", at(20, 11), "203.0.113.9"), roleRow("priv", at(20, 11, 5), "10.0.0.4")],
      [imdsRow("imds", at(20, 12))],
      ...later(3),
      [...file("resend", 22), roleRow("pub", at(20, 11), "203.0.113.9"), imdsRow("imds", at(20, 12))],
      ...later(2, 23),
    ]);
    expect(fasts.slice(1)).toEqual(fasts.slice(1).map(() => true));
    const s = await store.load("full");
    for (const id of ["pub", "imds"]) {
      expect(row(s, id)?.severity).toBe("High");
      expect(row(s, id)?.description?.split(METADATA_MARKER)).toHaveLength(2);
    }
  });

  it("a storage key listing alone keeps every later import incremental", async () => {
    const fasts = await run([[...file("a", 20), listing("L1", at(20, 11))], ...later(5)]);
    expect(fasts.slice(1)).toEqual(fasts.slice(1).map(() => true));
    expect(row(await store.load("full"), "L1")?.canonical?.event.type).toBe("storage-key-list");
  });

  it("a failed listing, reads before a listing and reads on another account form no join", async () => {
    const fasts = await run([
      [keyRead("R0", at(20, 9))],
      [listing("Lfail", at(20, 10), "stacct", "failure")],
      [keyRead("R1", at(20, 10, 30))],
      [listing("L1", at(20, 11))],
      [keyRead("R2", at(20, 12), "other")],
      ...later(2),
    ]);
    expect(fasts.slice(1)).toEqual(fasts.slice(1).map(() => true));
    expect(
      (await store.load("full")).forensicTimeline.some((e) => e.id.startsWith("storage-key-to-read")),
    ).toBe(false);
  });

  it("a listing then account-key reads inside the window fall back from the joining import on", async () => {
    const fasts = await run([
      [listing("L1", at(20, 11))],
      file("b1", 21),
      [keyRead("R1", at(20, 12)), keyRead("R2", at(20, 13))],
      file("b2", 21),
    ]);
    expect(fasts).toEqual([false, true, true, false, false]);
    const s = await store.load("full");
    expect(s.forensicTimeline.filter((e) => e.id.startsWith("storage-key-to-read|stacct|"))).toHaveLength(1);
    expect(await fallbackReason(file("b3", 22))).toContain("storage key");
  });

  it("an AWS compute summary alone keeps every later import incremental", async () => {
    const fasts = await run([[compute("C1", at(20, 8))], ...later(5)]);
    expect(fasts.slice(1)).toEqual(fasts.slice(1).map(() => true));
    expect(row(await store.load("full"), "C1")?.canonical?.awsCompute?.instanceId).toBe("i-0aaa1111bbbb");
  });

  it("AWS flows alone keep every later import incremental", async () => {
    const fasts = await run([[flowRow("F1", at(20, 10))], ...later(3)]);
    expect(fasts.slice(1)).toEqual(fasts.slice(1).map(() => true));
  });

  it("flows first, compute later: the merge falls back and the flow is attributed", async () => {
    const fasts = await run([[flowRow("F1", at(20, 10))], file("b1", 21)]);
    expect(fasts).toEqual([false, true, true]);
    expect(await fallbackReason([compute("C1", at(20, 8))])).toContain("AWS compute record and VPC flow");
    expect(await importBoth([compute("C1", at(20, 8))])).toBe(false);
    expect(await importBoth(file("b2", 21))).toBe(false);
    expect(row(await store.load("full"), "F1")?.description).toContain(FLOW_ATTRIBUTION_MARKER);
  });

  it("compute first, then a flow: the merge falls back and the flow is attributed", async () => {
    const fasts = await run([[compute("C1", at(20, 8))], file("b1", 21)]);
    expect(fasts).toEqual([false, true, true]);
    expect(await fallbackReason([flowRow("F1", at(20, 10))])).toContain("AWS compute record and VPC flow");
    expect(await importBoth([flowRow("F1", at(20, 10))])).toBe(false);
    // The attributed flow carries a trigger note: later unrelated imports keep falling back, equal.
    for (const k of [2, 3, 4]) expect(await importBoth(file(`b${k}`, 22))).toBe(false);
    expect(row(await store.load("full"), "F1")?.description).toContain(FLOW_ATTRIBUTION_MARKER);
  });
});
