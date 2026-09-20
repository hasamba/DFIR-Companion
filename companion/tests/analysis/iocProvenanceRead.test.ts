// #1447: /ioc-provenance and /ioc-provenance-chain each stream the whole super-timeline (~75 s on
// a capped case). Two dashboards, or the connect fan-out racing a reload, used to run two scans
// for one answer. The reader coalesces: a request that arrives while the same case's computation
// is in flight shares it. Sequential requests still recompute (the data may have changed).
import { describe, it, expect } from "vitest";
import { createIocProvenanceReads } from "../../src/analysis/iocProvenanceRead.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

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
