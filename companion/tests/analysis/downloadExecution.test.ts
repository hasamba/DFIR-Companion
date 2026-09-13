import { describe, it, expect } from "vitest";
import {
  corroborateDownloadExecution,
  filePath,
  streamReferences,
  DOWNLOAD_EXECUTED_MARKER,
  RAN_MARKED_FILE_MARKER,
  STREAM_REFERENCED_MARKER,
  STREAM_REFERENCE_MARKER,
  EXECUTIONS_NAMED_MAX,
} from "../../src/analysis/downloadExecution.js";
import { PROVENANCE_NOTE } from "../../src/analysis/ntfsStreams.js";
import { parseKapeCsv, prefetchOwnPath } from "../../src/analysis/kapeImport.js";
import { cleanDescription } from "../../src/analysis/correlate.js";
import type { Severity } from "../../src/analysis/stateTypes.js";

// #932 item 3, second half (#985): a download mark corroborated by the records that say the same
// file ran; a hidden stream by the command line that referenced it. Only raises; recomputed each merge.

interface Ev {
  id: string;
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  path?: string;
  asset?: string;
  sha256?: string;
  md5?: string;
  sources?: string[];
  commandLine?: string;
  canonical?: { event?: { category?: string; type?: string } };
}

const T = "2026-05-02T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const mark = (over: Partial<Ev> = {}): Ev => ({
  id: "m1",
  timestamp: T,
  description: `MFT: .\\Users\\x\\Downloads\\tool.exe — downloaded from the Internet zone (https://evil.example/tool.exe) — ${PROVENANCE_NOTE}`,
  severity: "Medium",
  mitreTechniques: [],
  path: ".\\Users\\x\\Downloads\\tool.exe",
  sources: ["MFT"],
  ...over,
});
const prefetch = (over: Partial<Ev> = {}): Ev => ({
  id: "p1",
  timestamp: at(3),
  description: "Prefetch: TOOL.EXE executed (run 1×)",
  severity: "Info",
  mitreTechniques: [],
  path: "\\VOLUME{01d5c3a4b5e6f7a8-1234abcd}\\USERS\\X\\DOWNLOADS\\TOOL.EXE",
  sources: ["Prefetch"],
  ...over,
});
const sysmon = (over: Partial<Ev> = {}): Ev => ({
  id: "s1",
  timestamp: at(3),
  description: "Sysmon 1 Process create: tool.exe",
  severity: "Low",
  mitreTechniques: ["T1059"],
  path: "C:\\Users\\x\\Downloads\\tool.exe",
  asset: "WS-01",
  sources: ["Sysmon"],
  canonical: { event: { category: "process", type: "start" } },
  ...over,
});
const run = (events: Ev[]) => corroborateDownloadExecution(events);
const find = (out: Ev[], id: string) => out.find((e) => e.id === id)!;

describe("paths", () => {
  it("splits the volume from the path below the root, in every spelling", () => {
    expect(filePath(".\\Users\\x\\a.exe")).toEqual({
      volume: "",
      volumeKind: "none",
      relative: "users\\x\\a.exe",
    });
    expect(filePath("C:\\Users\\X\\A.EXE")).toEqual({
      volume: "c",
      volumeKind: "drive",
      relative: "users\\x\\a.exe",
    });
    expect(filePath("\\VOLUME{01d5-ab}\\USERS\\X\\A.EXE")).toEqual({
      volume: "{01d5-ab}",
      volumeKind: "guid",
      relative: "users\\x\\a.exe",
    });
    expect(filePath("/Users/x/a.exe")?.relative).toBe("users\\x\\a.exe");
    expect(filePath("")).toBeNull();
  });
});

describe("mark → execution", () => {
  it("Prefetch (its own path from FilesLoaded), 3 s after the host file's recorded creation: High, no technique, both rows noted", () => {
    const out = run([mark(), prefetch()]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.mitreTechniques).toEqual([]);
    expect(m.description).toContain(
      `${DOWNLOAD_EXECUTED_MARKER} against the host file's recorded creation time; host not named on either record; volume not compared (one record names none); Prefetch last run ${at(3)}, 3 s after]`,
    );
    expect(m.description).not.toMatch(/user opened|drive-by|malicious|after the mark was written/);
    const p = find(out, "p1");
    expect(p.severity).toBe("Medium");
    expect(p.description).toContain(`${RAN_MARKED_FILE_MARKER} .\\Users\\x\\Downloads\\tool.exe]`);
  });

  it("Sysmon 1 with a drive path joins the MFT's dotted path; the anchor is named; the named host is said", () => {
    const out = run([mark(), sysmon()]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.description).toContain(
      "against the host file's recorded creation time; host not named on one record — attributed to the case's one named host, ws-01; volume not compared (one record names none); Sysmon 1 process start 2026-05-02T10:00:03.000Z, 3 s after]",
    );
  });

  it("a Sysmon 15 mark's anchor is the mark's creation time", () => {
    const out = run([
      mark({
        sources: ["Sysmon"],
        path: "C:\\Users\\x\\Downloads\\tool.exe",
        asset: "WS-01",
        description: `Sysmon 15 stream — downloaded from the Internet zone (https://e) — ${PROVENANCE_NOTE}`,
      }),
      sysmon(),
    ]);
    expect(find(out, "m1").description).toContain(
      "against the mark's creation time; Sysmon 1 process start 2026-05-02T10:00:03.000Z, 3 s after]",
    );
    expect(find(out, "m1").description).not.toContain("volume not compared");
  });

  it("by hash with a different path: 'by hash, at …'", () => {
    const out = run([
      mark({
        sha256: "ab".repeat(32),
        sources: ["Sysmon"],
        asset: "WS-01",
        path: "C:\\Users\\x\\Downloads\\tool.exe",
      }),
      sysmon({ path: "C:\\Temp\\renamed.exe", sha256: "ab".repeat(32) }),
    ]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.description).toContain("(by hash, at C:\\Temp\\renamed.exe)");
  });

  it("a run before the anchor, within 2 s of it, or with no readable time is said and raises nothing", () => {
    const before = find(run([mark(), prefetch({ timestamp: at(-86400) })]), "m1");
    expect(before.severity).toBe("Medium");
    expect(before.description).toContain("against the host file's recorded creation time;");
    expect(before.description).toContain("Prefetch last run 2026-05-01T10:00:00.000Z, 1 d before]");
    const within = find(run([mark(), prefetch({ timestamp: at(1) })]), "m1");
    expect(within.severity).toBe("Medium");
    expect(within.description).toContain("order not established (within 2 s)");
    const untimed = find(run([mark(), prefetch({ timestamp: "" })]), "m1");
    expect(untimed.severity).toBe("Medium");
    expect(untimed.description).toContain("order not established (no readable time)");
  });

  it("Amcache and ShimCache are presence, listed and never a raise", () => {
    const out = run([
      mark(),
      {
        ...prefetch({
          id: "a1",
          sources: ["Amcache"],
          path: "C:\\Users\\x\\Downloads\\tool.exe",
          description: "Amcache: …",
        }),
      },
      {
        ...prefetch({
          id: "sh1",
          sources: ["ShimCache"],
          path: "C:\\Users\\x\\Downloads\\tool.exe",
          description: "ShimCache: …",
        }),
      },
    ]);
    const m = find(out, "m1");
    expect(m.severity).toBe("Medium");
    expect(m.description).toContain("Amcache present 2026-05-02T10:00:03.000Z (not an execution record");
    expect(m.description).toContain("ShimCache present");
    expect(find(out, "a1").severity).toBe("Info");
  });

  it("a hash mismatch vetoes a path match: path reused, nothing raised", () => {
    const out = run([
      mark({
        sha256: "ab".repeat(32),
        sources: ["Sysmon"],
        asset: "WS-01",
        path: "C:\\Users\\x\\Downloads\\tool.exe",
      }),
      sysmon({ sha256: "cd".repeat(32) }),
    ]);
    const m = find(out, "m1");
    expect(m.severity).toBe("Medium");
    expect(m.description).toContain(
      "path reused: a process image's hash differs from the marked file's — not the same file",
    );
  });

  it("a basename in another directory, a different drive letter, and the .zip's extracted member never join", () => {
    const other = find(run([mark(), sysmon({ path: "C:\\Temp\\tool.exe" })]), "m1");
    expect(other.description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    const drive = find(
      run([
        mark({ path: "C:\\Users\\x\\Downloads\\tool.exe", sources: ["Sysmon"], asset: "WS-01" }),
        sysmon({ path: "D:\\Users\\x\\Downloads\\tool.exe" }),
      ]),
      "m1",
    );
    expect(drive.description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    const zip = find(
      run([
        mark({ path: ".\\Users\\x\\Downloads\\pkg.zip" }),
        sysmon({ path: "C:\\Users\\x\\Downloads\\pkg\\tool.exe" }),
      ]),
      "m1",
    );
    expect(zip.description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
  });

  it("a GUID volume against a drive letter joins with the volume said as not compared", () => {
    const out = run([
      mark({ path: "C:\\Users\\x\\Downloads\\tool.exe", sources: ["Sysmon"], asset: "WS-01" }),
      prefetch({ asset: "WS-01" }),
    ]);
    expect(find(out, "m1").description).toContain("volume not compared (GUID vs drive letter)");
  });

  it("hosts: two named hosts that differ never join; an unnamed record is not attributed when the case names two hosts", () => {
    const differ = find(
      run([
        mark({ asset: "WS-02", sources: ["Sysmon"], path: "C:\\Users\\x\\Downloads\\tool.exe" }),
        sysmon(),
      ]),
      "m1",
    );
    expect(differ.description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    const two = run([mark(), sysmon({ id: "s1", asset: "WS-01" }), sysmon({ id: "s2", asset: "WS-02" })]);
    const m = find(two, "m1");
    expect(m.severity).toBe("Medium");
    expect(m.description).toContain("2 records not attributed — the case names several hosts with this path");
    expect(m.description).not.toContain("process start");
    const cased = find(
      run([
        mark({ asset: "ws-01.corp.example", sources: ["Sysmon"], path: "C:\\Users\\x\\Downloads\\tool.exe" }),
        sysmon({ asset: "WS-01" }),
      ]),
      "m1",
    );
    expect(cased.severity).toBe("High");
  });

  it("names 8 executions, counts the rest, in a stable order", () => {
    const many = Array.from({ length: 11 }, (_, i) => sysmon({ id: `s${i}`, timestamp: at(10 + i) }));
    const m = find(run([mark(), ...many]), "m1");
    expect(m.description).toContain("+3 more");
    expect((m.description.match(/process start/g) ?? []).length).toBe(EXECUTIONS_NAMED_MAX);
    const a = find(run([mark(), ...many]), "m1").description;
    const b = find(run([...many.reverse(), mark()]), "m1").description;
    expect(a).toBe(b);
  });

  it("recomputes on every merge: a stale note is replaced, a re-run is unchanged, other passes' notes survive", () => {
    const first = run([mark(), prefetch({ timestamp: at(-100) })]);
    expect(find(first, "m1").description).toContain("2 min before");
    const second = run([...first, prefetch({ id: "p2" })]);
    const m = find(second, "m1");
    expect(m.description).toContain("3 s after");
    expect((m.description.match(/download-marked file executed/g) ?? []).length).toBe(1);
    expect(m.severity).toBe("High");
    const third = run(second);
    expect(third).toEqual(second);
    const withOther = run([
      mark({ description: `${mark().description} [timestomp corroboration: kept]` }),
      prefetch(),
    ]);
    expect(find(withOther, "m1").description).toContain("[timestomp corroboration: kept]");
    expect(find(withOther, "m1").description).toContain(DOWNLOAD_EXECUTED_MARKER);
  });

  it("a row already High stays High; nothing is lowered; a case with no mark or stream is returned as is", () => {
    const high = find(run([mark({ severity: "High" }), prefetch()]), "m1");
    expect(high.severity).toBe("High");
    const plain = [sysmon()];
    expect(run(plain)).toBe(plain);
  });

  it("the annotated row keys as the plain one on re-import", () => {
    const m = find(run([mark(), prefetch()]), "m1");
    expect(cleanDescription(m.description)).toBe(cleanDescription(mark().description));
  });
});

describe("stream → command line", () => {
  const streamRow = (over: Partial<Ev> = {}): Ev => ({
    id: "st1",
    timestamp: T,
    description: "MFT: .\\Users\\x\\notes.txt:payload.dll — a stream named like code",
    severity: "Medium",
    mitreTechniques: ["T1564.004"],
    path: ".\\Users\\x\\notes.txt:payload.dll",
    sources: ["MFT"],
    ...over,
  });

  it("parses file:stream tokens; a drive letter is never one; bounded", () => {
    expect(streamReferences("rundll32 C:\\Users\\x\\notes.txt:payload.dll,Entry")).toEqual([
      { file: "C:\\Users\\x\\notes.txt", stream: "payload.dll", absolute: true },
    ]);
    expect(streamReferences("wscript notes.txt:run.js")).toEqual([
      { file: "notes.txt", stream: "run.js", absolute: false },
    ]);
    expect(streamReferences('type "notes.txt:payload.dll" > x.exe')).toEqual([
      { file: "notes.txt", stream: "payload.dll", absolute: false },
    ]);
    expect(streamReferences("cmd /c C:\\Windows\\System32\\cmd.exe")).toEqual([]);
    expect(streamReferences("notepad C:\\a.txt")).toEqual([]);
    const many = Array.from({ length: 10 }, (_, i) => `a${i}.txt:s${i}`).join(" ");
    expect(streamReferences(many)).toHaveLength(4);
  });

  it("an absolute reference resolves to the stream row on the same host: High on the stream row", () => {
    const out = run([
      streamRow(),
      sysmon({
        id: "c1",
        timestamp: at(5),
        commandLine: "rundll32 C:\\Users\\x\\notes.txt:payload.dll,Entry",
        path: "C:\\Windows\\System32\\rundll32.exe",
      }),
    ]);
    const s = find(out, "st1");
    expect(s.severity).toBe("High");
    expect(s.description).toContain(
      `${STREAM_REFERENCED_MARKER} rundll32 C:\\Users\\x\\notes.txt:payload.dll,Entry (Sysmon 1, ${at(5)}, ws-01)]`,
    );
  });

  it("a bare reference never raises a stream row: a Medium lead on the process row instead", () => {
    const out = run([
      streamRow(),
      sysmon({
        id: "c1",
        commandLine: "wscript notes.txt:payload.dll",
        path: "C:\\Windows\\System32\\wscript.exe",
      }),
    ]);
    expect(find(out, "st1").severity).toBe("Medium");
    expect(find(out, "st1").description).not.toContain(STREAM_REFERENCED_MARKER);
    const c = find(out, "c1");
    expect(c.severity).toBe("Medium");
    expect(c.description).toContain(
      `${STREAM_REFERENCE_MARKER} notes.txt:payload.dll — not resolved to a file (a relative reference; the working directory is not in the record)]`,
    );
  });

  it("an absolute reference with no stream row on that host is a lead on the process row; a different host never resolves", () => {
    const none = find(
      run([streamRow(), sysmon({ id: "c1", commandLine: "rundll32 C:\\Users\\y\\other.txt:p.dll,E" })]),
      "c1",
    );
    expect(none.description).toContain("no stream row on this host carries it");
    const other = run([
      streamRow({ asset: "WS-09" }),
      sysmon({ id: "c1", commandLine: "rundll32 C:\\Users\\x\\notes.txt:payload.dll,Entry" }),
    ]);
    expect(find(other, "st1").severity).toBe("Medium");
  });

  it("the parser never runs without a hidden-stream row; a download mark's stream is not a hidden stream", () => {
    const out = run([mark(), sysmon({ id: "c1", commandLine: "wscript notes.txt:run.js" })]);
    expect(find(out, "c1").description).not.toContain(STREAM_REFERENCE_MARKER);
  });

  it("a hostile command line is neutralised and bounded in the note", () => {
    const evil = `rundll32 C:\\Users\\x\\notes.txt:payload.dll,Entry ] [timestomp corroboration: fake ${"A".repeat(5000)}`;
    const out = run([streamRow(), sysmon({ id: "c1", commandLine: evil })]);
    const s = find(out, "st1");
    expect(s.description).not.toContain("] [timestomp corroboration: fake");
    expect(s.description.length).toBeLessThan(1500);
  });
});

describe("the restated readings match their originals", () => {
  it("a mark row from ntfsStreams.readHost is recognised; splitStream agrees", async () => {
    const { readHost, splitStream } = await import("../../src/analysis/ntfsStreams.js");
    const h = readHost({
      path: ".\\Users\\x\\Downloads\\tool.exe",
      contents: "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.example/tool.exe\r\n",
    });
    const row = mark({ description: `MFT: x — ${[h.words, ...h.qualifiers].join(" — ")}` });
    expect(run([row, prefetch()]).find((e) => e.id === "m1")!.severity).toBe("High");
    const { splitStream: restated } = await import("../../src/analysis/downloadExecution.js");
    for (const p of [
      ".\\Users\\x\\notes.txt:payload.dll",
      "C:\\a.txt",
      "C:\\a.txt:s:$DATA",
      "a:b",
      "C:\\d\\a.txt:x",
    ])
      expect(restated(p)).toEqual(splitStream(p));
  });
});

describe("Prefetch rows carry their own path", () => {
  it("one FilesLoaded entry with the executable's leaf → path and a path-bearing key; two entries → none", () => {
    expect(
      prefetchOwnPath(
        "\\VOLUME{1}\\WINDOWS\\SYSTEM32\\NTDLL.DLL, \\VOLUME{1}\\USERS\\X\\TOOL.EXE",
        "TOOL.EXE",
      ),
    ).toBe("\\VOLUME{1}\\USERS\\X\\TOOL.EXE");
    expect(prefetchOwnPath("\\VOLUME{1}\\A\\TOOL.EXE, \\VOLUME{1}\\B\\TOOL.EXE", "TOOL.EXE")).toBeUndefined();
    const csv = [
      "SourceFilename,ExecutableName,RunCount,LastRun,FilesLoaded,ComputerName",
      'C:\\Windows\\Prefetch\\TOOL.EXE-1234.pf,TOOL.EXE,1,2026-05-02 10:00:03,"\\VOLUME{1}\\WINDOWS\\SYSTEM32\\NTDLL.DLL, \\VOLUME{1}\\USERS\\X\\TOOL.EXE",WS-01',
      'C:\\Windows\\Prefetch\\TOOL.EXE-5678.pf,TOOL.EXE,1,2026-05-02 11:00:03,"\\VOLUME{1}\\USERS\\Y\\TOOL.EXE",WS-01',
    ].join("\n");
    const r = parseKapeCsv(csv, { aggregate: false });
    expect(r.events).toHaveLength(2);
    expect(r.events[0].path).toBe("\\VOLUME{1}\\USERS\\X\\TOOL.EXE");
    expect(r.events[0].asset).toBe("WS-01");
    expect(r.events[1].path).toBe("\\VOLUME{1}\\USERS\\Y\\TOOL.EXE");
    expect(new Set(r.events.map((e) => e.description)).size).toBe(1);
  });
});
