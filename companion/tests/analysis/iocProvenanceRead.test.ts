// #1447: /ioc-provenance and /ioc-provenance-chain each stream the whole super-timeline (~75 s on
// a capped case). Two dashboards, or the connect fan-out racing a reload, used to run two scans
// for one answer. The reader coalesces: a request that arrives while the same case's computation
// is in flight shares it. Sequential requests still recompute (the data may have changed).
//
// #1452: a store that exposes `loadOverview` + `iocProvenanceCandidates` (the real StateStore) takes
// the indexed path — the worker's FTS term index hands back only the candidate rows, and the same
// builders run over those. A store without the two methods still streams.
import { describe, it, expect } from "vitest";
import { createIocProvenanceReads } from "../../src/analysis/iocProvenanceRead.js";
import { deriveIocProvenance } from "../../src/analysis/iocProvenance.js";
import { buildIocProvenanceChains } from "../../src/analysis/iocProvenanceChain.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { Finding, ForensicEvent, IOC, InvestigationState } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string; severity: ForensicEvent["severity"] }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

function fakeStores() {
  const scans: string[] = [];
  let release: (() => void) | null = null;
  const gate = new Promise<void>((r) => (release = r));
  const stateStore = {
    load: async (caseId: string): Promise<InvestigationState> => ({
      ...emptyState(caseId),
      iocs: [{ id: "i1", type: "ip", value: "10.9.8.7", firstSeen: "t" }],
      forensicTimeline: [ev({ id: "f1", severity: "High", description: "forensic 10.9.8.7" })],
    }),
  };
  const superTimelineStore = {
    async *eventBatches(caseId: string): AsyncGenerator<ForensicEvent[]> {
      scans.push(caseId);
      await gate; // hold every scan until the test lets it go
      yield [ev({ id: "s1", severity: "Info", description: "super 10.9.8.7", dstIp: "10.9.8.7" })];
    },
  };
  return { stateStore, superTimelineStore, scans, release: () => release!() };
}

describe("createIocProvenanceReads (#1447)", () => {
  it("two concurrent provenance reads for one case share one scan and get the same answer", async () => {
    const { stateStore, superTimelineStore, scans, release } = fakeStores();
    const reads = createIocProvenanceReads({ stateStore, superTimelineStore });
    const a = reads.provenance("C1");
    const b = reads.provenance("C1");
    await new Promise((r) => setImmediate(r));
    expect(scans).toEqual(["C1"]);
    release();
    const [ra, rb] = await Promise.all([a, b]);
    expect(ra).toEqual({ i1: "detection" });
    expect(rb).toBe(ra);
  });

  it("different cases, and the chain read, do not share a scan", async () => {
    const { stateStore, superTimelineStore, scans, release } = fakeStores();
    const reads = createIocProvenanceReads({ stateStore, superTimelineStore });
    const p = Promise.all([reads.provenance("C1"), reads.provenance("C2"), reads.chains("C1")]);
    await new Promise((r) => setImmediate(r));
    expect(scans.sort()).toEqual(["C1", "C1", "C2"]);
    release();
    const [, , chains] = await p;
    expect(chains.i1.extraction.map((e) => e.eventId)).toEqual(["f1", "s1"]);
  });

  it("a sequential read after the first settled scans again — the data may have changed", async () => {
    const { stateStore, superTimelineStore, scans, release } = fakeStores();
    const reads = createIocProvenanceReads({ stateStore, superTimelineStore });
    release();
    await reads.provenance("C1");
    await reads.provenance("C1");
    expect(scans).toEqual(["C1", "C1"]);
  });

  it("a failed computation clears the slot so the next read retries instead of sharing the error", async () => {
    let calls = 0;
    const stateStore = {
      load: async (caseId: string) => {
        calls += 1;
        if (calls === 1) throw new Error("sqlite busy");
        return emptyState(caseId);
      },
    };
    const reads = createIocProvenanceReads({ stateStore, superTimelineStore: undefined });
    await expect(reads.provenance("C1")).rejects.toThrow("sqlite busy");
    await expect(reads.provenance("C1")).resolves.toEqual({});
  });

  it("without a super-timeline store it reads the forensic side only", async () => {
    const { stateStore } = fakeStores();
    const reads = createIocProvenanceReads({ stateStore, superTimelineStore: undefined });
    expect(await reads.provenance("C1")).toEqual({ i1: "detection" });
    expect((await reads.chains("C1")).i1.extraction.map((e) => e.eventId)).toEqual(["f1"]);
  });
});

// The indexed path (#1452): the fake records what it was asked for and answers from fixed arrays.
function fakeIndexedStores() {
  const iocs: IOC[] = [
    { id: "i1", type: "ip", value: "  10.9.8.7 ", firstSeen: "t", extractedFrom: ["f1", "s1"] },
    { id: "i2", type: "ip", value: "10.9.8.7", firstSeen: "t" },
    { id: "i3", type: "domain", value: "EVIL.com", firstSeen: "t", extractedFrom: ["s1", "f9"] },
    { id: "i4", type: "other", value: "ab", firstSeen: "t" },
    { id: "i5", type: "hash", value: "DEADBEEF", firstSeen: "t", extractedFrom: [] },
  ];
  const findings: Finding[] = [
    {
      id: "fd1",
      title: "beacon",
      severity: "High",
      description: "",
      evidence: [],
      mitreTechniques: [],
      relatedEventIds: ["f1"],
      relatedIocs: ["i3"],
    } as unknown as Finding,
  ];
  const forensic = [
    ev({ id: "f1", severity: "High", description: "forensic 10.9.8.7 talks to evil.com" }),
    ev({ id: "f2", severity: "Medium", description: "unrelated", sha256: "deadbeef" }),
  ];
  const superEvents = [
    ev({ id: "s1", severity: "Info", description: "super 10.9.8.7", dstIp: "10.9.8.7" }),
    ev({ id: "s2", severity: "Low", description: "dns evil.com" }),
  ];
  const calls = { load: 0, loadOverview: 0, candidates: 0, batches: 0 };
  const asked: { keys: readonly string[]; ids: readonly string[] }[] = [];
  let release: (() => void) | null = null;
  const gate = new Promise<void>((r) => (release = r));
  const overview = (caseId: string): InvestigationState => ({ ...emptyState(caseId), iocs, findings });
  const stateStore = {
    load: async (caseId: string): Promise<InvestigationState> => {
      calls.load += 1;
      return { ...overview(caseId), forensicTimeline: forensic };
    },
    loadOverview: async (caseId: string): Promise<InvestigationState> => {
      calls.loadOverview += 1;
      return overview(caseId);
    },
    iocProvenanceCandidates: async (_caseId: string, keys: readonly string[], ids: readonly string[]) => {
      calls.candidates += 1;
      asked.push({ keys, ids });
      await gate;
      return { forensic, super: superEvents, candidates: forensic.length + superEvents.length };
    },
  };
  const superTimelineStore = {
    async *eventBatches(_caseId: string): AsyncGenerator<ForensicEvent[]> {
      calls.batches += 1;
      yield superEvents;
    },
  };
  const all = [...forensic, ...superEvents];
  return { stateStore, superTimelineStore, iocs, findings, all, calls, asked, release: () => release!() };
}

describe("createIocProvenanceReads — indexed path (#1452)", () => {
  it("asks the store for trimmed, lowercased, deduped keys of 3+ chars and the union of extractedFrom", async () => {
    const f = fakeIndexedStores();
    const reads = createIocProvenanceReads({
      stateStore: f.stateStore,
      superTimelineStore: f.superTimelineStore,
    });
    f.release();
    await reads.provenance("C1");
    expect(f.asked).toHaveLength(1);
    expect(f.asked[0].keys).toEqual(["10.9.8.7", "evil.com", "deadbeef"]);
    expect(f.asked[0].ids).toEqual(["f1", "s1", "f9"]);
  });

  it("provenance over the candidates equals the whole-array derivation over forensic ++ super", async () => {
    const f = fakeIndexedStores();
    const reads = createIocProvenanceReads({
      stateStore: f.stateStore,
      superTimelineStore: f.superTimelineStore,
    });
    f.release();
    const got = await reads.provenance("C1");
    expect(got).toEqual(deriveIocProvenance(f.iocs, f.all));
    expect(got).toEqual({
      i1: "detection",
      i2: "detection",
      i3: "detection",
      i4: "telemetry",
      i5: "detection",
    });
  });

  it("chains over the candidates equal the whole-array builder over forensic ++ super, in that order", async () => {
    const f = fakeIndexedStores();
    const reads = createIocProvenanceReads({
      stateStore: f.stateStore,
      superTimelineStore: f.superTimelineStore,
    });
    f.release();
    const got = await reads.chains("C1");
    expect(got).toEqual(buildIocProvenanceChains(f.iocs, f.all, f.findings));
    expect(got.i2.extraction.map((e) => e.eventId)).toEqual(["f1", "s1"]);
    // Authoritative links win over description tokens: s1 is linked, f9 does not exist.
    expect(got.i3.extraction.map((e) => e.eventId)).toEqual(["s1"]);
  });

  it("never streams the super-timeline and never loads the full state on the indexed path", async () => {
    const f = fakeIndexedStores();
    const reads = createIocProvenanceReads({
      stateStore: f.stateStore,
      superTimelineStore: f.superTimelineStore,
    });
    f.release();
    await Promise.all([reads.provenance("C1"), reads.chains("C1")]);
    expect(f.calls).toEqual({ load: 0, loadOverview: 2, candidates: 2, batches: 0 });
  });

  it("two concurrent provenance reads for one case share one candidate lookup", async () => {
    const f = fakeIndexedStores();
    const reads = createIocProvenanceReads({
      stateStore: f.stateStore,
      superTimelineStore: f.superTimelineStore,
    });
    const a = reads.provenance("C1");
    const b = reads.provenance("C1");
    await new Promise((r) => setImmediate(r));
    expect(f.calls.candidates).toBe(1);
    f.release();
    const [ra, rb] = await Promise.all([a, b]);
    expect(rb).toBe(ra);
    expect(f.calls.candidates).toBe(1);
  });

  it("a store with loadOverview but no iocProvenanceCandidates still streams", async () => {
    const f = fakeIndexedStores();
    const { iocProvenanceCandidates: _unused, ...stateStore } = f.stateStore;
    void _unused;
    const reads = createIocProvenanceReads({ stateStore, superTimelineStore: f.superTimelineStore });
    const got = await reads.provenance("C1");
    expect(got).toEqual(deriveIocProvenance(f.iocs, f.all));
    expect(f.calls).toEqual({ load: 1, loadOverview: 0, candidates: 0, batches: 1 });
  });

  it("without a super-timeline store the indexed path still reads both kinds from the one database", async () => {
    const f = fakeIndexedStores();
    const reads = createIocProvenanceReads({ stateStore: f.stateStore, superTimelineStore: undefined });
    f.release();
    expect((await reads.chains("C1")).i2.extraction.map((e) => e.eventId)).toEqual(["f1", "s1"]);
    expect(f.calls.batches).toBe(0);
  });
});
