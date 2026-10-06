// #1969 — a capped Velociraptor read keeps the FIRST rows in read order. When the read was cut short
// and an incident window is known, it is read once more inside that window.
import { describe, expect, it } from "vitest";
import {
  incidentWindow,
  readInIncidentWindow,
  windowWhere,
  WINDOW_TIME_COLUMNS,
  type CappedRead,
} from "../../src/integrations/velociraptor/veloWindowReread.js";
import {
  isContainedWhereExpression,
  MAX_READ_WHERE_LENGTH,
  MAX_WHERE_LENGTH,
} from "../../src/analysis/vqlInput.js";
import {
  VelociraptorClient,
  type VelociraptorApiConfig,
  type VqlRunner,
} from "../../src/integrations/velociraptor/velociraptorApi.js";

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

  // #1983: with NO window a cut-short read is re-read newest-first (veloNewestRead.test.ts); a hunt that
  // applied its window at the source is the case that is read once only.
  it("scoped at the source — no re-read", async () => {
    const { read, calls } = fakeRead(cut, inWindow);
    const res = await readInIncidentWindow(read, USN, undefined, { kind: "scoped" });
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

// Review finding on #1969: the combined `(base) AND window` filter was built and validated OUTSIDE the
// fallback, and validation truncates to the analyst-input cap — a valid near-limit filter plus the
// window clause was cut into an unbalanced expression, threw, and the caller dropped the plain rows.
describe("readInIncidentWindow — a near-limit analyst filter", () => {
  const MFT = "Windows.NTFS.MFT";
  // A valid filter of exactly `n` characters: `(OSPath =~ 'aaa…')`.
  const filterOf = (n: number) => `(OSPath =~ '${"a".repeat(n - 14)}')`;
  const cfg: VelociraptorApiConfig = {
    apiConfigPath: "/tmp/api.config.yaml",
    binary: "velociraptor",
    timeoutMs: 5000,
    maxRows: 2,
    maxOutputBytes: 1 << 20,
  };

  // The real client: its own WHERE validation runs on every read, as in the hunt collect.
  function realRead(windowed: Record<string, unknown>[]) {
    const programs: string[] = [];
    const runner: VqlRunner = async (s) => {
      programs.push(s[0]);
      return { rows: programs.length === 1 ? cut.rows.concat(cut.rows) : windowed, raw: "" };
    };
    const client = new VelociraptorClient(cfg, runner);
    const read = (where?: string) => client.huntResults("H.ABC123", MFT, [], where, true);
    return { read, programs };
  }

  it("a 910-character filter plus an MFT window re-reads with the whole filter and window intact", async () => {
    const base = filterOf(910);
    expect(base).toHaveLength(910);
    const { read, programs } = realRead(inWindow.rows);
    const res = await readInIncidentWindow(read, MFT, base, WIN);
    expect(programs).toHaveLength(2);
    expect(programs[1]).toContain(`(${base}) AND (`);
    expect(programs[1]).toContain("timestamp(epoch='2026-09-21T00:00:00.000Z')");
    expect(res.rows).toEqual(inWindow.rows);
    expect(res.window).toEqual(WIN);
  });

  it("a filter at the analyst cap still re-reads, never throws", async () => {
    const { read } = realRead(inWindow.rows);
    const res = await readInIncidentWindow(read, MFT, filterOf(MAX_WHERE_LENGTH), WIN);
    expect(res.rows).toEqual(inWindow.rows);
  });

  it("a failure while building or running the re-read keeps the plain rows", async () => {
    const lines: string[] = [];
    let n = 0;
    const read = async (where?: string): Promise<CappedRead> => {
      n++;
      if (n === 1) return cut;
      throw new Error(`refused ${String(where).length}`);
    };
    const res = await readInIncidentWindow(read, MFT, filterOf(910), WIN, (l) => lines.push(l));
    expect(res.rows).toEqual(cut.rows);
    expect(res.window).toBeUndefined();
    expect(lines.join()).toContain("kept the plain read");
  });

  it("an injection attempt in the analyst filter is still refused before any read", async () => {
    const { read, calls } = fakeRead(cut, inWindow);
    const smuggle = "1=1) SELECT * FROM info() WHERE (1=1";
    await expect(readInIncidentWindow(read, USN, smuggle, WIN)).rejects.toThrow(/invalid WHERE filter/);
    await expect(readInIncidentWindow(read, USN, "a = 1 -- x", WIN)).rejects.toThrow(/invalid WHERE filter/);
    expect(calls).toHaveLength(0);
  });

  it("the analyst filter keeps its own length cap: a longer one is cut to the cap, as before", async () => {
    const { read, calls } = fakeRead(cut, inWindow);
    const long = `a = 1 OR b = '${"x".repeat(MAX_WHERE_LENGTH)}'`;
    await expect(readInIncidentWindow(read, USN, long, WIN)).rejects.toThrow(/invalid WHERE filter/);
    expect(calls).toHaveLength(0); // cut mid-literal, so unbalanced, so refused — the plain read's own rule
  });

  it("every window clause fits the generated-text budget, so a capped filter plus a window is never cut", () => {
    const lengths = Object.keys(WINDOW_TIME_COLUMNS).map((a) => windowWhere(a, WIN)!.length);
    expect(MAX_WHERE_LENGTH + "() AND ".length + Math.max(...lengths)).toBeLessThanOrEqual(
      MAX_READ_WHERE_LENGTH,
    );
  });
});
