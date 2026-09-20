import { describe, it, expect } from "vitest";
import { openVelociraptorRowStream } from "../../src/analysis/velociraptorRowStream.js";
import { extractRows } from "../../src/analysis/velociraptorImport.js";

// The streaming reader must agree with the whole-parse driver (`extractRows`) on what a row is, for
// every shape it claims to stream — the bulk import path (#1439) is only as trustworthy as that
// agreement. Every fixture is synthetic.

function drain(text: string) {
  const stream = openVelociraptorRowStream(text);
  if (!stream) return null;
  const rows = [...stream.rows];
  return { format: stream.format, rows: rows.map((r) => r.row), offsets: rows.map((r) => r.offset) };
}

const MFT_ROW = {
  EntryNumber: 42,
  OSPath: "\\\\.\\C:\\Windows\\Temp\\x.ps1",
  FileName: "x.ps1",
  Created0x10: "2026-01-02T03:04:05.000Z",
  Nested: { a: [1, 2, { b: '}]"{[' }], quote: 'He said "hi" \\ and left' },
  Unicode: "שלום — ünïcödé ✓",
};

describe("openVelociraptorRowStream", () => {
  it("streams a one-line artifact map and stamps _Source like extractRows", () => {
    const text = JSON.stringify({ "Windows.NTFS.MFT": [MFT_ROW, { ...MFT_ROW, EntryNumber: 43 }] });
    const out = drain(text)!;
    expect(out.format).toBe("artifact-map");
    expect(out.rows).toEqual(extractRows(text).rows);
    expect(out.rows[0]._Source).toBe("Windows.NTFS.MFT");
    expect(out.rows[0].Nested).toEqual(MFT_ROW.Nested);
    expect(out.rows[0].Unicode).toBe(MFT_ROW.Unicode);
  });

  it("keeps a row's own _Source or Artifact instead of stamping", () => {
    const text = JSON.stringify({
      "Windows.NTFS.MFT": [
        { ...MFT_ROW, _Source: "Custom.Src" },
        { ...MFT_ROW, Artifact: "Other" },
      ],
    });
    const out = drain(text)!;
    expect(out.rows).toEqual(extractRows(text).rows);
    expect(out.rows[0]._Source).toBe("Custom.Src");
    expect(out.rows[1]._Source).toBeUndefined();
  });

  it("walks several artifacts in one map, in order, and a pretty-printed map", () => {
    const map = {
      "Windows.NTFS.MFT": [MFT_ROW],
      "Windows.Registry.UserAssist": [{ Name: "a" }, { Name: "b" }],
      "Empty.Artifact": [],
    };
    for (const text of [JSON.stringify(map), JSON.stringify(map, null, 2)]) {
      const out = drain(text)!;
      expect(out.format).toBe("artifact-map");
      expect(out.rows).toEqual(extractRows(text).rows);
      expect(out.rows.map((r) => r._Source)).toEqual([
        "Windows.NTFS.MFT",
        "Windows.Registry.UserAssist",
        "Windows.Registry.UserAssist",
      ]);
    }
  });

  it("streams a bare array, skips non-object elements and unwraps Elastic _source", () => {
    const text = JSON.stringify([MFT_ROW, 7, "x", null, { _source: { Name: "wrapped" } }]);
    const out = drain(text)!;
    expect(out.format).toBe("array");
    expect(out.rows).toEqual(extractRows(text).rows);
    expect(out.rows).toHaveLength(2);
    expect(out.rows[1]).toEqual({ Name: "wrapped" });
  });

  it("streams NDJSON, skipping blank and malformed lines", () => {
    const text = [
      JSON.stringify(MFT_ROW),
      "",
      "{not json",
      JSON.stringify({ _source: { Name: "wrapped" } }),
      "   ",
    ].join("\n");
    const out = drain(text)!;
    expect(out.format).toBe("ndjson");
    expect(out.rows).toEqual(extractRows(text).rows);
    expect(out.rows).toHaveLength(2);
  });

  it("reports a monotone offset that ends at the text length for the last row", () => {
    const text = JSON.stringify({ A: [MFT_ROW, MFT_ROW, MFT_ROW] });
    const out = drain(text)!;
    for (let i = 1; i < out.offsets.length; i++) expect(out.offsets[i]).toBeGreaterThan(out.offsets[i - 1]);
    expect(out.offsets[out.offsets.length - 1]).toBeLessThanOrEqual(text.length);
  });

  it("handles the empty array and the empty map", () => {
    expect(drain("[]")).toEqual({ format: "array", rows: [], offsets: [] });
    expect(drain("{}")).toBeNull(); // not an artifact map — extractRows treats it as a single object too
    expect(drain("   ")).toBeNull();
  });

  it("returns null for shapes it does not stream, so the caller falls back to whole-parse", () => {
    expect(drain("Name,Value\na,1\n")).toBeNull(); // CSV
    expect(drain(JSON.stringify({ data: [MFT_ROW] }))).toBeNull(); // wrapper key
    expect(drain(JSON.stringify({ rows: [MFT_ROW], Other: [MFT_ROW] }))).toBeNull(); // mixed wrapper
    expect(drain(JSON.stringify({ "Windows.NTFS.MFT": { not: "an array" } }))).toBeNull();
    expect(drain(JSON.stringify(MFT_ROW))).toBeNull(); // single object
  });

  it("throws with the row index on a malformed tail instead of silently truncating", () => {
    const good = JSON.stringify({ A: [MFT_ROW, MFT_ROW] });
    const cut = good.slice(0, good.length - 10);
    const stream = openVelociraptorRowStream(cut);
    // The probe rejects a map whose array never closes — no rows are returned at all.
    expect(stream).toBeNull();
    const arr = JSON.stringify([MFT_ROW, MFT_ROW]).slice(0, -5);
    const s2 = openVelociraptorRowStream(arr)!;
    expect(s2.format).toBe("array");
    expect(() => [...s2.rows]).toThrow(/row 2/);
  });
});
