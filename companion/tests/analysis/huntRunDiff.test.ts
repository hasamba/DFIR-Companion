import { describe, it, expect } from "vitest";
import {
  buildHuntRunSnapshot,
  diffHuntRuns,
  isEmptyHuntRunDiff,
  summarizeHuntRunDiff,
  findHuntRunRecord,
  upsertHuntRunRecord,
  HUNT_RUN_RECORDS_MAX,
  type HuntRunRecord,
} from "../../src/analysis/huntRunDiff.js";

const T0 = "2026-06-21T10:00:00.000Z";
const T1 = "2026-06-21T11:00:00.000Z";

describe("buildHuntRunSnapshot", () => {
  it("collects a stable key per row and extracts hosts from common field names", () => {
    const snap = buildHuntRunSnapshot({
      "Custom.Hunt": [
        { Fqdn: "host-a", Path: "C:/evil.exe" },
        { Hostname: "host-b", Path: "C:/other.exe" },
      ],
    });
    expect(snap.rowKeys).toHaveLength(2);
    expect(snap.hosts.sort()).toEqual(["host-a", "host-b"]);
  });

  it("dedupes identical rows across artifacts", () => {
    const row = { ClientId: "C.123", Path: "C:/evil.exe" };
    const snap = buildHuntRunSnapshot({ A: [row], B: [{ ...row }] });
    expect(snap.rowKeys).toHaveLength(1);
    expect(snap.hosts).toEqual(["C.123"]);
  });

  it("is insensitive to field ORDER within a row (same identity)", () => {
    const a = buildHuntRunSnapshot({ A: [{ x: 1, y: 2 }] });
    const b = buildHuntRunSnapshot({ A: [{ y: 2, x: 1 }] });
    expect(a.rowKeys).toEqual(b.rowKeys);
  });

  it("treats a value change as a different row", () => {
    const a = buildHuntRunSnapshot({ A: [{ x: 1 }] });
    const b = buildHuntRunSnapshot({ A: [{ x: 2 }] });
    expect(a.rowKeys).not.toEqual(b.rowKeys);
  });

  it("caps the number of distinct row keys / hosts retained", () => {
    const rows = Array.from({ length: 20 }, (_, i) => ({ Fqdn: `host-${i}`, i }));
    const snap = buildHuntRunSnapshot({ A: rows }, 5);
    expect(snap.rowKeys).toHaveLength(5);
    expect(snap.hosts).toHaveLength(5);
  });

  it("handles rows with no host field gracefully", () => {
    const snap = buildHuntRunSnapshot({ A: [{ foo: "bar" }] });
    expect(snap.rowKeys).toHaveLength(1);
    expect(snap.hosts).toHaveLength(0);
  });

  it("returns an empty snapshot for no rows", () => {
    expect(buildHuntRunSnapshot({})).toEqual({ rowKeys: [], hosts: [] });
  });
});

describe("diffHuntRuns", () => {
  it("flags a first run (no previous snapshot) and reports nothing as added", () => {
    const cur = buildHuntRunSnapshot({ A: [{ Fqdn: "host-a" }] });
    const diff = diffHuntRuns(undefined, cur);
    expect(diff.isFirstRun).toBe(true);
    expect(diff.addedRows).toBe(1);
    expect(diff.addedHosts).toEqual(["host-a"]);
  });

  it("reports rows/hosts new since the previous run", () => {
    const prev = buildHuntRunSnapshot({ A: [{ Fqdn: "host-a", f: 1 }] });
    const cur = buildHuntRunSnapshot({ A: [{ Fqdn: "host-a", f: 1 }, { Fqdn: "host-b", f: 2 }] });
    const diff = diffHuntRuns(prev, cur);
    expect(diff.isFirstRun).toBe(false);
    expect(diff.addedRows).toBe(1);
    expect(diff.removedRows).toBe(0);
    expect(diff.addedHosts).toEqual(["host-b"]);
    expect(diff.removedHosts).toEqual([]);
  });

  it("reports rows/hosts that dropped out since the previous run", () => {
    const prev = buildHuntRunSnapshot({ A: [{ Fqdn: "host-a" }, { Fqdn: "host-b" }] });
    const cur = buildHuntRunSnapshot({ A: [{ Fqdn: "host-a" }] });
    const diff = diffHuntRuns(prev, cur);
    expect(diff.removedRows).toBe(1);
    expect(diff.removedHosts).toEqual(["host-b"]);
    expect(diff.addedRows).toBe(0);
  });

  it("shows no change when the same run is re-collected (identical rows)", () => {
    const snap = buildHuntRunSnapshot({ A: [{ Fqdn: "host-a", v: 1 }] });
    const diff = diffHuntRuns(snap, snap);
    expect(isEmptyHuntRunDiff(diff)).toBe(true);
  });

  it("a re-run against an empty previous run counts every current row as added", () => {
    const cur = buildHuntRunSnapshot({ A: [{ Fqdn: "host-a" }] });
    const diff = diffHuntRuns({ rowKeys: [], hosts: [] }, cur);
    expect(diff.isFirstRun).toBe(false);
    expect(diff.addedRows).toBe(1);
  });
});

describe("isEmptyHuntRunDiff", () => {
  it("is false for a first run even with no rows (nothing to compare yet, not 'no change')", () => {
    const diff = diffHuntRuns(undefined, { rowKeys: [], hosts: [] });
    expect(isEmptyHuntRunDiff(diff)).toBe(false);
  });
});

describe("summarizeHuntRunDiff", () => {
  it("says so when there's no prior run to compare", () => {
    const diff = diffHuntRuns(undefined, buildHuntRunSnapshot({ A: [{ Fqdn: "host-a" }] }));
    expect(summarizeHuntRunDiff(diff)).toBe("first run — no prior run to compare");
  });

  it("summarizes added rows and new hosts", () => {
    const prev = buildHuntRunSnapshot({ A: [{ Fqdn: "host-a" }] });
    const cur = buildHuntRunSnapshot({ A: [{ Fqdn: "host-a" }, { Fqdn: "host-b" }, { Fqdn: "host-b", extra: 1 }] });
    const diff = diffHuntRuns(prev, cur);
    expect(summarizeHuntRunDiff(diff)).toBe("+2 rows since last run, 1 new host");
  });

  it("reports no change since last run", () => {
    const snap = buildHuntRunSnapshot({ A: [{ Fqdn: "host-a" }] });
    expect(summarizeHuntRunDiff(diffHuntRuns(snap, snap))).toBe("no change since last run");
  });
});

describe("findHuntRunRecord / upsertHuntRunRecord", () => {
  const rec = (fp: string, huntId: string): HuntRunRecord => ({
    vqlFingerprint: fp,
    huntId,
    capturedAt: T0,
    snapshot: { rowKeys: [], hosts: [] },
  });

  it("finds by fingerprint, undefined when absent or blank", () => {
    const records = [rec("fp1", "H.1")];
    expect(findHuntRunRecord(records, "fp1")).toBe(records[0]);
    expect(findHuntRunRecord(records, "fp2")).toBeUndefined();
    expect(findHuntRunRecord(records, "")).toBeUndefined();
  });

  it("upserts by fingerprint (replaces, never duplicates), prepended newest-first", () => {
    let records = upsertHuntRunRecord([], rec("fp1", "H.1"));
    records = upsertHuntRunRecord(records, rec("fp2", "H.2"));
    records = upsertHuntRunRecord(records, { ...rec("fp1", "H.3"), capturedAt: T1 });
    expect(records).toHaveLength(2);
    expect(records[0]).toMatchObject({ vqlFingerprint: "fp1", huntId: "H.3" });
  });

  it("caps history to max (newest kept)", () => {
    let records: HuntRunRecord[] = [];
    for (let i = 0; i < 5; i++) records = upsertHuntRunRecord(records, rec(`fp${i}`, `H.${i}`), 3);
    expect(records).toHaveLength(3);
    expect(records.map((r) => r.vqlFingerprint)).toEqual(["fp4", "fp3", "fp2"]);
  });

  it("does not mutate the input array", () => {
    const input: HuntRunRecord[] = [];
    const out = upsertHuntRunRecord(input, rec("fp1", "H.1"));
    expect(input).toHaveLength(0);
    expect(out).toHaveLength(1);
  });

  it("defaults to HUNT_RUN_RECORDS_MAX when max is invalid", () => {
    const out = upsertHuntRunRecord([], rec("fp1", "H.1"), 0);
    expect(out).toHaveLength(1);
    expect(HUNT_RUN_RECORDS_MAX).toBeGreaterThan(0);
  });
});
