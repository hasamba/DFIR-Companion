// #1969 — a capped Velociraptor read keeps the FIRST rows in read order. When the read was cut short
// and an incident window is known, it is read once more inside that window.
import { describe, expect, it } from "vitest";
import {
  incidentWindow,
  readInIncidentWindow,
  windowWhere,
  type CappedRead,
} from "../../src/integrations/velociraptor/veloWindowReread.js";
import { isContainedWhereExpression } from "../../src/analysis/vqlInput.js";

const USN = "Windows.Forensics.Usn";
const WIN = { start: "2026-09-20T00:00:00.000Z", end: "2026-09-21T00:00:00.000Z" };

function fakeRead(
  plain: CappedRead,
  windowed: CappedRead | Error = { rows: [], truncated: false, total: 0 },
) {
  const calls: (string | undefined)[] = [];
  const read = async (where?: string): Promise<CappedRead> => {
    calls.push(where);
    if (calls.length === 1) return plain;
    if (windowed instanceof Error) throw windowed;
    return windowed;
  };
  return { read, calls };
}

const cut = {
  rows: [{ Timestamp: "2020-01-01T00:00:00Z" }, { Timestamp: "2020-01-02T00:00:00Z" }],
  truncated: true,
  total: 3,
};
const inWindow = { rows: [{ Timestamp: "2026-09-20T05:00:00Z" }], truncated: false, total: 1 };

describe("incidentWindow", () => {
  it("prefers the hunt's own time scope over the case scope window", () => {
    expect(
      incidentWindow({ start: "2026-09-01T00:00:00Z" }, { start: "2025-01-01T00:00:00Z", end: null }),
    ).toEqual({
      start: "2026-09-01T00:00:00.000Z",
    });
  });

  it("falls back to the case scope window", () => {
    expect(incidentWindow(undefined, { start: WIN.start, end: WIN.end })).toEqual(WIN);
    expect(incidentWindow(undefined, { start: null, end: WIN.end })).toEqual({ end: WIN.end });
  });

  it("is undefined with no window, and drops a bound that is not a date", () => {
    expect(incidentWindow(undefined, { start: null, end: null })).toBeUndefined();
    expect(incidentWindow(undefined, null)).toBeUndefined();
    expect(incidentWindow(undefined, { start: "x' OR 1=1", end: null })).toBeUndefined();
  });

  it("is undefined for an artifact the hunt already scoped at the source", () => {
    const ts = { start: WIN.start, scopedArtifactNames: [USN] };
    expect(incidentWindow(ts, null, USN)).toBeUndefined();
    expect(incidentWindow(ts, null, "Windows.NTFS.MFT")).toEqual({ start: WIN.start });
  });
});

describe("windowWhere", () => {
  it("bounds the USN journal on its record time, as one contained expression", () => {
    const w = windowWhere(USN, WIN)!;
    expect(w).toContain("timestamp(epoch=Timestamp) >= timestamp(epoch='2026-09-20T00:00:00.000Z')");
    expect(w).toContain("timestamp(epoch=Timestamp) <= timestamp(epoch='2026-09-21T00:00:00.000Z')");
    expect(isContainedWhereExpression(w)).toBe(true);
  });

  it("tries both MFT column spellings, $FN Created first", () => {
    const w = windowWhere("Windows.NTFS.MFT", { start: WIN.start })!;
    expect(w.indexOf("Created0x30")).toBeLessThan(w.indexOf("Created0x10"));
    expect(w).toContain("FNTimestamps.Created0x30");
    expect(w).not.toContain("<=");
  });

  it("is undefined for an artifact with no known time column", () => {
    expect(windowWhere("Generic.System.Pstree", WIN)).toBeUndefined();
  });
});

describe("readInIncidentWindow", () => {
  it("a cut-short read with a known window is read exactly once more, inside it, and keeps those rows", async () => {
    const { read, calls } = fakeRead(cut, inWindow);
    const res = await readInIncidentWindow(read, USN, undefined, WIN);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toBeUndefined();
    expect(calls[1]).toContain("timestamp(epoch=Timestamp)");
    expect(res.rows).toEqual(inWindow.rows);
    expect(res.window).toEqual(WIN);
  });

  it("keeps the analyst's own filter on the re-read", async () => {
    const { read, calls } = fakeRead(cut, inWindow);
    await readInIncidentWindow(read, USN, "FileName =~ 'x'", WIN);
    expect(calls[0]).toBe("FileName =~ 'x'");
    expect(calls[1]).toMatch(/^\(FileName =~ 'x'\) AND \(/);
  });

  it("no window — no re-read", async () => {
    const { read, calls } = fakeRead(cut, inWindow);
    const res = await readInIncidentWindow(read, USN, undefined, undefined);
    expect(calls).toHaveLength(1);
    expect(res.rows).toEqual(cut.rows);
    expect(res.window).toBeUndefined();
  });

  it("not cut short — no re-read", async () => {
    const { read, calls } = fakeRead({ ...cut, truncated: false }, inWindow);
    await readInIncidentWindow(read, USN, undefined, WIN);
    expect(calls).toHaveLength(1);
  });

  it("an artifact with no time column — no re-read", async () => {
    const { read, calls } = fakeRead(cut, inWindow);
    await readInIncidentWindow(read, "Generic.System.Pstree", undefined, WIN);
    expect(calls).toHaveLength(1);
  });

  it("an empty or failed re-read keeps the plain rows", async () => {
    const empty = fakeRead(cut);
    expect((await readInIncidentWindow(empty.read, USN, undefined, WIN)).rows).toEqual(cut.rows);
    const lines: string[] = [];
    const failed = fakeRead(cut, new Error("boom"));
    const res = await readInIncidentWindow(failed.read, USN, undefined, WIN, (l) => lines.push(l));
    expect(res.rows).toEqual(cut.rows);
    expect(res.window).toBeUndefined();
    expect(lines.join()).toContain("boom");
  });
});
