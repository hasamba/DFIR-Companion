// #1983 — a capped Velociraptor read with no incident window keeps the NEWEST rows, by the artifact's
// own time, instead of the first rows in source order.
import { describe, expect, it } from "vitest";
import {
  cappedReadProgram,
  capNewest,
  finishNewest,
  NEWEST_KEY,
  newestKeyExpr,
  newestOrder,
  SORTED_READ_TIMEOUT_FACTOR,
} from "../../src/integrations/velociraptor/veloNewestRead.js";
import {
  readInIncidentWindow,
  readScope,
  type CappedRead,
} from "../../src/integrations/velociraptor/veloWindowReread.js";
import { readHuntArtifactRows } from "../../src/integrations/velociraptor/artifactRefs.js";
import {
  VelociraptorClient,
  type VelociraptorApiConfig,
  type VqlRunner,
} from "../../src/integrations/velociraptor/velociraptorApi.js";

const MFT = "Windows.NTFS.MFT";
const USN = "Windows.Forensics.Usn";
const WIN = { start: "2026-09-20T00:00:00.000Z", end: "2026-09-21T00:00:00.000Z" };
const cfg: VelociraptorApiConfig = {
  apiConfigPath: "/tmp/api.config.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 2,
  maxOutputBytes: 1 << 20,
};
const ms = (iso: string) => Date.parse(iso);
const plainRows = [
  { FileName: "old0", Created0x30: "2020-01-01T00:00:00Z" },
  { FileName: "old1", Created0x30: "2020-01-02T00:00:00Z" },
  { FileName: "old2", Created0x30: "2020-01-03T00:00:00Z" },
];

interface Call {
  program: string;
  timeoutMs: number;
}
// A real client whose runner answers the plain read with `plainRows` and the sorted read with `sorted`.
function client(sorted: Record<string, unknown>[] | Error, stderr = "") {
  const calls: Call[] = [];
  const runner: VqlRunner = async (s, opts) => {
    calls.push({ program: s[0], timeoutMs: opts.timeoutMs });
    if (!s[0].includes("ORDER BY")) return { rows: plainRows.map((r) => ({ ...r })), raw: "" };
    if (sorted instanceof Error) throw sorted;
    return { rows: sorted.map((r) => ({ ...r })), raw: "", stderr };
  };
  return { c: new VelociraptorClient(cfg, runner), calls };
}

describe("the sort key", () => {
  it("reads every column by row lookup, first valid time wins, undated rows get -1", () => {
    const k = newestKeyExpr(["Created0x30", "FNTimestamps.Created0x30"]);
    expect(k).toBe(
      "if(condition=timestamp(epoch=get(member='Created0x30')).UnixMilli > 0, " +
        "then=timestamp(epoch=get(member='Created0x30')).UnixMilli, " +
        "else=if(condition=timestamp(epoch=get(member='FNTimestamps.Created0x30')).UnixMilli > 0, " +
        "then=timestamp(epoch=get(member='FNTimestamps.Created0x30')).UnixMilli, else=-1))",
    );
  });

  it("MFT sorts $FN Created first, then $SI Created", () => {
    const k = newestOrder(MFT)!.key;
    expect(k.indexOf("'Created0x30'")).toBeLessThan(k.indexOf("'Created0x10'"));
    expect(k).toContain("SITimestamps.Created0x10");
    expect(newestOrder("Generic.System.Pstree")).toBeUndefined();
  });

  it("the plain program is unchanged; the sorted one sorts each part before its own LIMIT", () => {
    expect(cappedReadProgram(["src(a)"], "x = 1", 3)).toBe("SELECT * FROM src(a) WHERE (x = 1) LIMIT 3");
    const p = cappedReadProgram(["src(a)", "src(b)"], undefined, 3, newestOrder(USN));
    expect(p).toMatch(/^SELECT \* FROM chain\(q0=\{ SELECT \*, if\(/);
    expect(p.match(new RegExp(`ORDER BY ${NEWEST_KEY} DESC LIMIT 3`, "g"))).toHaveLength(2);
  });

  it("merges by key, undated rows last, then strips the helper column", () => {
    const run = capNewest(
      [
        { a: 1, [NEWEST_KEY]: -1 },
        { a: 2, [NEWEST_KEY]: 5 },
        { a: 3, [NEWEST_KEY]: 9 },
      ],
      2,
    );
    expect(run.truncated).toBe(true);
    const done = finishNewest(run);
    expect(done.rows).toEqual([{ a: 3 }, { a: 2 }]);
    expect(done.newest.keyed).toBe(2);
  });
});

describe("readScope — three states", () => {
  it("no window, a window, or scoped at the source", () => {
    expect(readScope(undefined, null, MFT)).toEqual({ kind: "none" });
    expect(readScope(undefined, WIN, MFT)).toEqual({ kind: "window", window: WIN });
    expect(readScope({ start: WIN.start, scopedArtifactNames: [MFT] }, null, MFT)).toEqual({
      kind: "scoped",
    });
  });
});

describe("readInIncidentWindow — newest first when no window is known", () => {
  const readOf =
    (c: VelociraptorClient, srcs: string[] = []) =>
    (where?: string, order?: unknown) =>
      c.huntArtifactRows("H.ABC123", MFT, srcs, where, true, order as never);

  it("a source-scoped MFT over the cap performs exactly one read", async () => {
    const { c, calls } = client([]);
    const scope = readScope({ start: WIN.start, scopedArtifactNames: [MFT] }, null, MFT);
    const res = await readInIncidentWindow(readOf(c, ["Default"]), MFT, undefined, scope);
    expect(calls).toHaveLength(1);
    expect(res.truncated).toBe(true);
    expect(res.order).toBeUndefined();
  });

  it("a window is known but its re-read fails — the plain rows are kept, never newest-first", async () => {
    let n = 0;
    const read = async (where?: string, order?: unknown): Promise<CappedRead> => {
      n++;
      if (order) throw new Error("must not sort");
      if (n === 1) return { rows: plainRows, truncated: true, total: 3 };
      throw new Error("boom");
    };
    const res = await readInIncidentWindow(read, MFT, undefined, { kind: "window", window: WIN });
    expect(n).toBe(2);
    expect(res.rows).toEqual(plainRows);
    expect(res.order).toBeUndefined();
  });

  it("no window + cut short: one sorted re-read, the newest rows across two parts are kept", async () => {
    // Two named sources → one chain, each part sorted on its own. The second part holds the newest row.
    const part1 = [
      { FileName: "p1-a", [NEWEST_KEY]: ms("2026-03-01T00:00:00Z") },
      { FileName: "p1-b", [NEWEST_KEY]: ms("2026-02-01T00:00:00Z") },
      { FileName: "p1-c", [NEWEST_KEY]: ms("2026-01-01T00:00:00Z") },
    ];
    const part2 = [
      { FileName: "p2-a", [NEWEST_KEY]: ms("2026-09-01T00:00:00Z") },
      { FileName: "p2-b", [NEWEST_KEY]: -1 },
    ];
    const { c, calls } = client([...part1, ...part2]);
    const res = await readInIncidentWindow(readOf(c, ["A", "B"]), MFT, "FileSize > 0", { kind: "none" });
    expect(calls).toHaveLength(2);
    expect(calls[1].program).toContain("WHERE (FileSize > 0) ORDER BY");
    expect(calls[1].timeoutMs).toBe(cfg.timeoutMs * SORTED_READ_TIMEOUT_FACTOR);
    expect(res.rows.map((r) => (r as { FileName: string }).FileName)).toEqual(["p2-a", "p1-a"]);
    expect(res.order).toBe("newest");
    expect(res.newest).toMatchObject({
      earliest: "2026-03-01T00:00:00.000Z",
      latest: "2026-09-01T00:00:00.000Z",
    });
  });

  it("the helper column never reaches the returned rows", async () => {
    const { c } = client([{ FileName: "n", [NEWEST_KEY]: ms("2026-09-01T00:00:00Z") }]);
    const res = await readInIncidentWindow(readOf(c), MFT, undefined, undefined);
    expect(res.order).toBe("newest");
    for (const r of res.rows) expect(Object.keys(r as object)).not.toContain(NEWEST_KEY);
  });

  it("VQL diagnostics on the sorted read keep the plain rows", async () => {
    const lines: string[] = [];
    const stderr = "[INFO] 2026-10-06T00:00:00Z ERROR:Symbol X not found.";
    const { c } = client([{ FileName: "n", [NEWEST_KEY]: 5 }], stderr);
    const res = await readInIncidentWindow(readOf(c), MFT, undefined, undefined, (l) => lines.push(l));
    expect(res.rows).toEqual(plainRows.slice(0, 2));
    expect(res.order).toBeUndefined();
    expect(lines.join()).toContain("Symbol X not found");
  });

  it("a sorted read with no usable keys keeps the plain rows", async () => {
    const { c } = client([{ FileName: "n", [NEWEST_KEY]: -1 }]);
    const res = await readInIncidentWindow(readOf(c), MFT, undefined, undefined);
    expect(res.order).toBeUndefined();
    expect(res.rows).toEqual(plainRows.slice(0, 2));
  });

  it("a timeout on the sorted read keeps the plain rows", async () => {
    const lines: string[] = [];
    const { c } = client(new Error("Velociraptor query timed out after 15000ms"));
    const res = await readInIncidentWindow(readOf(c), MFT, undefined, undefined, (l) => lines.push(l));
    expect(res.rows).toEqual(plainRows.slice(0, 2));
    expect(res.order).toBeUndefined();
    expect(lines.join()).toContain("timed out");
  });

  it("a plain row that already carries the reserved column refuses the sort", async () => {
    const read = async (where?: string, order?: unknown): Promise<CappedRead> => {
      if (order) throw new Error("must not sort");
      return { rows: [{ [NEWEST_KEY]: 1 }], truncated: true, total: 2 };
    };
    const res = await readInIncidentWindow(read, MFT, undefined, undefined);
    expect(res.order).toBeUndefined();
  });

  it("an artifact with no sort column, or a read not cut short, is read once", async () => {
    let n = 0;
    const read = async (): Promise<CappedRead> => {
      n++;
      return { rows: [{}], truncated: n === 1, total: 2 };
    };
    await readInIncidentWindow(read, "Generic.System.Pstree", undefined, undefined);
    expect(n).toBe(1);
    n = 1; // the next read is not cut short
    await readInIncidentWindow(read, USN, undefined, undefined);
    expect(n).toBe(2);
  });
});

describe("readHuntArtifactRows — ordering survives the bare + named merge and the final cap", () => {
  it("merges both reads by key, caps once, strips, and keeps sourcesUnknown", async () => {
    const bare = { rows: [{ n: "bare", [NEWEST_KEY]: 10 }], total: 1, truncated: false };
    const named = {
      rows: [
        { n: "named-new", [NEWEST_KEY]: 30 },
        { n: "named-mid", [NEWEST_KEY]: 20 },
      ],
      total: 2,
      truncated: false,
    };
    const read = async (_a: string, srcs: string[]) => (srcs.length ? named : bare);
    const cat = async () => [{ name: MFT, sources: ["X"], sourcesUnknown: true as const }];
    const res = await readHuntArtifactRows(read, cat, MFT, [], 2, true);
    expect(res.rows).toEqual([{ n: "named-new" }, { n: "named-mid" }]);
    expect(res.truncated).toBe(true);
    expect(res.sourcesUnknown).toBe(true);
    expect(res.newest?.keyed).toBe(2);
  });
});

describe("huntArtifactRows — the newest-first cap runs once, after the bare + named dedup", () => {
  // Codex review of #1983: the named chain was cut to the cap BEFORE the merge dropped rows the bare
  // read repeats, so duplicates filled the cap and a newer distinct row was lost.
  it("overlapping bare and named sources keep the newest DISTINCT rows", async () => {
    const at = (n: string, k: number) => ({ n, [NEWEST_KEY]: k });
    const programs: string[] = [];
    const runner: VqlRunner = async (s) => {
      const p = s[0];
      programs.push(p);
      if (p.includes("artifact_definitions()"))
        return {
          rows: [{ name: MFT, type: "CLIENT", sources: [{ name: "One" }, { name: "Two" }] }],
          raw: "",
        };
      if (p.includes("chain("))
        return { rows: [at("A", 100), at("A", 100), at("B", 90), at("C", 80)], raw: "" };
      return { rows: [at("A", 100), at("D", 50)], raw: "" };
    };
    const res = await new VelociraptorClient(cfg, runner).huntArtifactRows(
      "H.ABC123",
      MFT,
      [],
      undefined,
      true,
      newestOrder(MFT),
    );
    expect(programs.some((p) => p.includes("chain("))).toBe(true);
    expect(res.rows).toEqual([{ n: "A" }, { n: "B" }]);
    expect(res.truncated).toBe(true);
    expect(res.newest).toMatchObject({ keyed: 2 });
  });

  it("a single sorted read is still held to the cap", async () => {
    const runner: VqlRunner = async () => ({
      rows: [3, 1, 2].map((k) => ({ k, [NEWEST_KEY]: k })),
      raw: "",
    });
    const res = await new VelociraptorClient(cfg, runner).huntArtifactRows(
      "H.ABC123",
      MFT,
      ["Default"],
      undefined,
      true,
      newestOrder(MFT),
    );
    expect(res.rows).toEqual([{ k: 3 }, { k: 2 }]);
    expect(res.truncated).toBe(true);
  });
});
