import { describe, it, expect } from "vitest";
import type { BulkImportSink } from "../../src/analysis/ingest/velociraptorBulk.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import {
  createSuperShareLedger,
  importSuperOnlyArtifact,
  superTimelineCap,
  superTimelineShares,
} from "../../src/composition/veloSuperShare.js";

// #1982 — one DFIR_SUPERTIMELINE_MAX is shared by every artifact of a super-only hunt. It used to be
// spent first-come in bundle order, so a full MFT (entry 1) used the whole cap and USN got nothing.

describe("superTimelineShares — water-fill by row count", () => {
  it("the triage example: 38 small artifacts get all their rows, MFT and USN split the rest", () => {
    const small = Array.from({ length: 38 }, (_, i) => (i < 36 ? 200 : 400)); // 36×200 + 2×400 = 8,000
    expect(small.reduce((a, b) => a + b, 0)).toBe(8000);
    const rows = [100_000, ...small.slice(0, 21), 100_000, ...small.slice(21)]; // MFT first, USN at 23
    const shares = superTimelineShares(rows, 100_000);
    expect(shares[0]).toBe(46_000); // MFT
    expect(shares[22]).toBe(46_000); // USN
    rows.forEach((r, i) => {
      if (r < 100_000) expect(shares[i]).toBe(r);
    });
    expect(shares.reduce((a, b) => a + b, 0)).toBe(100_000);
  });

  it("no artifact gets more than its need, and the total never passes the cap", () => {
    const rows = [5, 3_000, 17, 0, 90, 12_345, 1];
    for (const cap of [0, 1, 10, 100, 1_000, 10_000, 1_000_000]) {
      const shares = superTimelineShares(rows, cap);
      shares.forEach((s, i) => {
        expect(s).toBeGreaterThanOrEqual(0);
        expect(s).toBeLessThanOrEqual(rows[i]);
      });
      expect(shares.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(cap);
    }
  });

  it("everything fits: each artifact gets exactly its rows", () => {
    expect(superTimelineShares([10, 20, 30], 1_000)).toEqual([10, 20, 30]);
  });
});

describe("superTimelineCap", () => {
  it("reads DFIR_SUPERTIMELINE_MAX and defaults to 100,000", () => {
    expect(superTimelineCap({})).toBe(100_000);
    expect(superTimelineCap({ DFIR_SUPERTIMELINE_MAX: "250" })).toBe(250);
    expect(superTimelineCap({ DFIR_SUPERTIMELINE_MAX: "nope" })).toBe(100_000);
  });
});

describe("createSuperShareLedger — the per-artifact limit in loop order", () => {
  it("an artifact read FIRST cannot eat the shares reserved for the artifacts after it", () => {
    const ledger = createSuperShareLedger([100, 100, 10], 100);
    const first = ledger.limit(0);
    expect(first).toBe(45); // 10 for the small one, the rest split in two
    ledger.charge(first);
    const second = ledger.limit(1);
    expect(second).toBe(45);
    ledger.charge(second);
    expect(ledger.limit(2)).toBe(10);
  });

  it("slack an earlier artifact did not use goes to a later one, never past the cap", () => {
    const ledger = createSuperShareLedger([10, 100], 60);
    expect(ledger.limit(0)).toBe(10);
    ledger.charge(4); // the severity floor dropped six
    expect(ledger.limit(1)).toBe(56);
  });
});

// Codex review of #1982: the cut was decided BEFORE mapping, from rows vs the limit. One MFT row maps
// to up to eight events (one per distinct MACB time), so ten rows under a limit of ten lost seventy
// events with no record, and the inventory called the artifact "in the archive only". The record is
// now decided from what the mapping produced versus what was offered to the super-timeline.
describe("importSuperOnlyArtifact — the cut is measured in mapped events, on both paths", () => {
  const MFT = "Windows.NTFS.MFT";
  // Four distinct MACB times per row → four super-timeline events per row.
  const mftRow = (n: number) => {
    const at = (m: number) => new Date(Date.UTC(2026, 0, 1, 0, n, m)).toISOString();
    const path = `\\\\.\\C:\\Users\\u\\${String.fromCharCode(97 + n)}file.txt`;
    return {
      EntryNumber: n,
      InUse: true,
      OSPath: path,
      FileName: path.slice(path.lastIndexOf("\\") + 1),
      FileSize: 10,
      IsDir: false,
      Created0x10: at(1),
      LastModified0x10: at(2),
      LastRecordChange0x10: at(3),
      LastAccess0x10: at(4),
    };
  };
  const json = JSON.stringify({ [MFT]: Array.from({ length: 10 }, (_, i) => mftRow(i)) });
  const base = {
    caseId: "c1",
    huntId: "H.1",
    name: MFT,
    json,
    rows: 10,
    storedName: "velo-hunt_H.1.json",
    importedAt: "2026-01-02T00:00:00.000Z",
    cap: 60,
  };
  const NO_EVICTION = { count: 0, setAside: 0, from: "", to: "" };

  function superStore() {
    const rows: ForensicEvent[] = [];
    const store = {
      rows,
      async appendReporting(_c: string, events: ForensicEvent[]) {
        rows.push(...events);
        return { retained: events.length, evicted: NO_EVICTION };
      },
    };
    return store;
  }

  function bulkSink(rows: ForensicEvent[]): BulkImportSink {
    return {
      minBytes: 0,
      batchRows: 3,
      beginRun: async () => 0,
      rollback: async () => ({ forensic: 0, super: 0, tags: 0 }),
      appendForensic: async () => 0,
      appendSuper: async (_c, events) => {
        rows.push(...events);
        return { retained: events.length, evicted: NO_EVICTION };
      },
      openTagger: async () => null,
      forensicMinSeverity: async () => "Info",
      log: () => {},
    };
  }

  const deps = (store: ReturnType<typeof superStore>, sink?: BulkImportSink) => ({
    superTimelineStore: store as unknown as SuperTimelineStore,
    bulkImportSink: sink,
    autoTagImported: async () => {},
  });

  for (const path of ["parse", "bulk"] as const) {
    it(`${path} path: a limit equal to the row count still records the events the cap cut`, async () => {
      const store = superStore();
      const sink = path === "bulk" ? bulkSink(store.rows) : undefined;
      const r = await importSuperOnlyArtifact(deps(store, sink), { ...base, limit: 10 });
      expect(store.rows).toHaveLength(10);
      expect(r.capped).toBeDefined();
      expect(r.capped!.kept).toBe(10);
      expect(r.capped!.total).toBe(40); // mapped events, not rows
      expect(r.capped!.rows).toBe(10);
      expect(r.offered).toBe(10);
    });

    it(`${path} path: an artifact whose events all fit has no record`, async () => {
      const store = superStore();
      const sink = path === "bulk" ? bulkSink(store.rows) : undefined;
      const r = await importSuperOnlyArtifact(deps(store, sink), { ...base, limit: 40 });
      expect(store.rows).toHaveLength(40);
      expect(r.capped).toBeUndefined();
    });
  }

  it("a share of zero still maps the artifact, so the record names how much was lost", async () => {
    const store = superStore();
    const r = await importSuperOnlyArtifact(deps(store), { ...base, limit: 0 });
    expect(store.rows).toHaveLength(0);
    expect(r.capped).toMatchObject({ kept: 0, total: 40, rows: 10 });
  });
});
