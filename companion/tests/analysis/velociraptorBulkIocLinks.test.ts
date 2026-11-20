import { describe, it, expect, vi, afterEach } from "vitest";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";
import { vrBulkInternals } from "../../src/analysis/velociraptorImport.js";
import { runVelociraptorBulk, type BulkImportSink } from "../../src/analysis/ingest/velociraptorBulk.js";

// #2727 — the bulk driver's per-file IOC sink kept every row's aggKey on each IOC for the whole file,
// so a repeating value (a process image named in every row) made each batch cost more than the last.
// These checks count list lengths, not wall-clock time, so they are deterministic. All data synthetic.

const NO_EVICTION = { count: 0, setAside: 0, from: "", to: "" };
const MAX_EXTRACTED_FROM = 200;
const IMAGE = "C:\\Windows\\System32\\rundll32.exe";

// One Security 4688 process creation; the command line differs per row so each row is its own event,
// while the image (an IOC) repeats in every row.
function procRow(i: number) {
  return {
    EventTime: new Date(Date.UTC(2026, 7, 13) + i * 1000).toISOString(),
    Computer: "WKS-001.lab.example",
    Channel: "Security",
    EventID: 4688,
    EventData: {
      SubjectUserName: "user1",
      SubjectDomainName: "LAB",
      NewProcessId: `0x${(4096 + i).toString(16)}`,
      NewProcessName: IMAGE,
      ParentProcessName: "C:\\Windows\\System32\\explorer.exe",
      CommandLine: `"${IMAGE}" shell32.dll,Control_RunDLL arg${i.toString(26).replace(/\d/g, "x")}`,
    },
    Message: "A new process has been created.",
    Detection: { Name: "T1218.011-Rundll32 Use", EventId: "^(4688)$", Regex: "rundll32.exe", Ignore: "" },
  };
}

function jsonl(rows: object[]): string {
  return rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
}

function keyTotal(sink: Map<string, SiemIoc>): number {
  let n = 0;
  for (const ioc of sink.values()) n += ioc.sourceAggKeys?.length ?? 0;
  return n;
}

function keyMax(sink: Map<string, SiemIoc>): number {
  let n = 0;
  for (const ioc of sink.values()) n = Math.max(n, ioc.sourceAggKeys?.length ?? 0);
  return n;
}

// An in-memory sink; `afterBatch` runs once per batch, after the driver's link bookkeeping for the
// PREVIOUS batch — so it is called with the ctx as it stands going into the next batch's append.
function memorySink(batchRows: number, afterBatch?: () => void): BulkImportSink {
  return {
    minBytes: 0,
    batchRows,
    async beginRun() {
      return 0;
    },
    async rollback() {
      return { forensic: 0, super: 0, tags: 0 };
    },
    async appendForensic(_caseId, events) {
      return events.length;
    },
    async appendSuper(_caseId, events: ForensicEvent[]) {
      afterBatch?.();
      return { retained: events.length, evicted: NO_EVICTION };
    },
    async openTagger() {
      return null;
    },
    async forensicMinSeverity() {
      return "Info";
    },
    log() {},
  };
}

const opts = (label: string) => ({
  label,
  idPrefix: "27",
  importedAt: "2026-11-20T07:00:00.000Z",
  velociraptor: { aggregate: false },
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("runVelociraptorBulk — IOC link lists stay bounded per batch (#2727)", () => {
  it("the total link-list length stays flat across 40 batches of a repeating IOC", async () => {
    const batchRows = 50;
    const spy = vi.spyOn(vrBulkInternals, "newVrCtx");
    const totals: number[] = [];
    const maxes: number[] = [];
    const sink = memorySink(batchRows, () => {
      const ctx = spy.mock.results[0]?.value as ReturnType<typeof vrBulkInternals.newVrCtx>;
      totals.push(keyTotal(ctx.iocSink));
      maxes.push(keyMax(ctx.iocSink));
    });
    const rows = Array.from({ length: 40 * batchRows }, (_, i) => procRow(i + 1));
    const res = await runVelociraptorBulk(
      sink,
      "c1",
      jsonl(rows),
      opts("Windows.Hayabusa.Notebook.json"),
      "super-only",
    );
    expect(res?.batches).toBe(40);
    expect(totals).toHaveLength(40);
    // The repeating image really is linked (else the check below proves nothing).
    expect(res?.iocs.find((c) => c.value.toLowerCase().includes("rundll32"))?.extractedFrom?.length).toBe(
      MAX_EXTRACTED_FROM,
    );
    const iocCount = res!.iocs.length;
    // Within a batch a list grows by at most that batch's rows; between batches it is cut back.
    expect(totals[39]).toBeLessThanOrEqual(totals[4] + iocCount * batchRows);
    expect(Math.max(...maxes)).toBeLessThanOrEqual(MAX_EXTRACTED_FROM + batchRows);
  });

  it("an IOC named in more than 200 rows still links to the first 200 events, in order", async () => {
    const rows = Array.from({ length: 330 }, (_, i) => procRow(i + 1));
    const res = await runVelociraptorBulk(
      memorySink(25),
      "c1",
      jsonl(rows),
      opts("Windows.Hayabusa.Notebook.json"),
      "super-only",
    );
    const image = res?.iocs.find((c) => c.value.toLowerCase().includes("rundll32"));
    // One event per row, ids minted in row order: the first 200 rows' events.
    expect(image?.extractedFrom).toEqual(
      Array.from({ length: MAX_EXTRACTED_FROM }, (_, i) => `27-e${i + 1}`),
    );
  });
});

describe("runVelociraptorBulk — a batch's row mapping lets the event loop run (#2727)", () => {
  it("a setImmediate callback runs between the first and the last row of one 2,500-row batch", async () => {
    let ticks = 0;
    let stop = false;
    const tick = (): void => {
      ticks++;
      if (!stop) setImmediate(tick);
    };
    const ctxSpy = vi.spyOn(vrBulkInternals, "newVrCtx");
    const seen: number[] = [];
    const real = vrBulkInternals.mapRowToEvents;
    vi.spyOn(vrBulkInternals, "mapRowToEvents").mockImplementation((row, ctx) => {
      if (ctx === ctxSpy.mock.results[0]?.value) seen.push(ticks);
      return real(row, ctx);
    });
    const rows = Array.from({ length: 2500 }, (_, i) => procRow(i + 1));
    setImmediate(tick);
    try {
      await runVelociraptorBulk(
        memorySink(5000),
        "c1",
        jsonl(rows),
        opts("Windows.Hayabusa.Notebook.json"),
        "super-only",
      );
    } finally {
      stop = true;
    }
    expect(seen).toHaveLength(2500);
    expect(seen[seen.length - 1]).toBeGreaterThan(seen[0]);
  });
});
