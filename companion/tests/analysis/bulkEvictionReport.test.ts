import { describe, expect, it } from "vitest";
import {
  collectEvictionForRecord,
  evictionLessReoffered,
  type BatchedRunEviction,
} from "../../src/analysis/ingest/bulkEvictionReport.js";
import type { BulkImportSink, BulkRunHandle } from "../../src/analysis/ingest/velociraptorBulk.js";
import type { SuperEviction } from "../../src/analysis/superTimelineStore.js";

// #2831: a hunt collect imports several batched artifacts and settles once. A later artifact's cap
// pass can drop an earlier artifact's graded rows, and the one settle puts every graded row back —
// so the rows the collect really lost are counted once, for the whole collect, before that settle.

const span = { from: "2025-01-01T00:00:00Z", to: "2025-01-02T00:00:00Z" };
const dropped = (count: number, setAside = 0): SuperEviction => ({ count, setAside, ...span });
const handle = (id: string): BulkRunHandle => ({ importBatchId: id, fence: 0, mode: "forensic" });
const run = (id: string, count: number): BatchedRunEviction => ({
  raw: count ? dropped(count) : undefined,
  run: handle(id),
});

type ReportSink = Pick<BulkImportSink, "log" | "superMissingOfRun">;

function sinkWith(missing: Record<string, number>): ReportSink & { logs: string[]; asked: string[] } {
  const logs: string[] = [];
  const asked: string[] = [];
  return {
    logs,
    asked,
    log: (line) => void logs.push(line),
    superMissingOfRun: async (_caseId, r) => {
      asked.push(r.importBatchId);
      return missing[r.importBatchId] ?? 0;
    },
  };
}

describe("collectEvictionForRecord — one put-back measurement per collect (#2831)", () => {
  it("adds the runs' reports up and leaves out the rows the settle puts back", async () => {
    const sink = sinkWith({ a: 3, b: 5 });
    const got = await collectEvictionForRecord(sink, "c1", "hunt H.1", [run("a", 14), run("b", 10)]);
    expect(got).toEqual({ count: 16, setAside: 0, ...span });
    expect(sink.asked).toEqual(["a", "b"]); // each run asked once
  });

  it("subtracts the rows of a run that dropped nothing itself — a later run dropped them", async () => {
    const sink = sinkWith({ a: 4, b: 0 });
    const got = await collectEvictionForRecord(sink, "c1", "hunt H.1", [run("a", 0), run("b", 10)]);
    expect(got.count).toBe(6);
  });

  it("subtracts from every report made before the settle, an uploaded report's included", async () => {
    // The upload's cap pass dropped 8 of artifact a's rows: they are in its report and in a's missing rows.
    const sink = sinkWith({ a: 8 });
    const got = await collectEvictionForRecord(sink, "c1", "hunt H.1", [run("a", 0)], dropped(8));
    expect(got.count).toBe(0);
  });

  it("never goes below zero, and keeps the set-aside share within the count", async () => {
    const sink = sinkWith({ a: 99 });
    expect(await collectEvictionForRecord(sink, "c1", "hunt H.1", [run("a", 5)])).toEqual({
      count: 0,
      setAside: 0,
      from: "",
      to: "",
    });
    const partly = await collectEvictionForRecord(
      sinkWith({ a: 4 }),
      "c1",
      "hunt H.1",
      [{ raw: dropped(5, 3), run: handle("a") }],
      undefined,
    );
    expect(partly).toEqual({ count: 1, setAside: 1, ...span });
  });

  it("reports the whole total, and says so, when the put-back rows cannot be read", async () => {
    const sink = sinkWith({});
    sink.superMissingOfRun = async () => {
      throw new Error("worker gone");
    };
    const got = await collectEvictionForRecord(sink, "c1", "hunt H.1", [run("a", 14), run("b", 10)]);
    expect(got.count).toBe(24);
    expect(sink.logs.some((l) => /worker gone — the import record may count a row twice/.test(l))).toBe(true);
  });

  it("returns the reports as they are with no batched run, no sink, or a sink that cannot tell", async () => {
    const sink = sinkWith({ a: 3 });
    expect(await collectEvictionForRecord(sink, "c1", "hunt H.1", [], dropped(7))).toEqual(dropped(7));
    expect(sink.asked).toEqual([]);
    expect((await collectEvictionForRecord(undefined, "c1", "hunt H.1", [run("a", 9)])).count).toBe(9);
    const blind = { log: () => {} };
    expect((await collectEvictionForRecord(blind, "c1", "hunt H.1", [run("a", 9)])).count).toBe(9);
    expect((await collectEvictionForRecord(sink, "c1", "hunt H.1", [])).count).toBe(0);
  });
});

describe("evictionLessReoffered", () => {
  it("leaves the report untouched when nothing is put back", () => {
    const whole = dropped(5, 1);
    expect(evictionLessReoffered(whole, 0)).toBe(whole);
  });
});
