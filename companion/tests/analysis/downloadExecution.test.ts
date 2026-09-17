import { describe, it, expect } from "vitest";
import {
  corroborateDownloadExecution,
  filePath,
  sameLocation,
  streamReferences,
  DOWNLOAD_EXECUTED_MARKER,
  RAN_MARKED_FILE_MARKER,
  STREAM_REFERENCED_MARKER,
  STREAM_REFERENCE_MARKER,
  YARA_MATCHES_MARK_MARKER,
  EXECUTIONS_NAMED_MAX,
} from "../../src/analysis/downloadExecution.js";
import {
  BROWSER_VISIT_MARKER,
  REFERRER_VISIT_MARKER,
  VISIT_PRECEDES_MARK_MARKER,
} from "../../src/analysis/downloadVisitOrigin.js";
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

  it("recognizes an NT device path (BAM's Binary column) as its own volume kind (#985 item 2/3)", () => {
    expect(filePath("\\Device\\HarddiskVolume3\\Users\\x\\Downloads\\tool.exe")).toEqual({
      volume: "harddiskvolume3",
      volumeKind: "device",
      relative: "users\\x\\downloads\\tool.exe",
    });
    // Case-insensitive, matching every other volume prefix this function already recognizes.
    expect(filePath("\\device\\HARDDISKVOLUME3\\Users\\x\\a.exe")?.volumeKind).toBe("device");
  });

  it("sameLocation gives a correctly-worded, kind-aware note for every differing volume pairing", () => {
    const device = filePath("\\Device\\HarddiskVolume3\\Users\\x\\a.exe")!;
    const drive = filePath("C:\\Users\\x\\a.exe")!;
    const guid = filePath("\\VOLUME{01d5-ab}\\Users\\x\\a.exe")!;
    expect(sameLocation(device, drive)).toEqual({
      same: true,
      volumeNote: "volume not compared (device vs drive)",
    });
    expect(sameLocation(guid, drive)).toEqual({
      same: true,
      volumeNote: "volume not compared (guid vs drive)",
    });
    // Two device paths still distinguish by their own volume token — not a blanket "not compared".
    const otherDevice = filePath("\\Device\\HarddiskVolume4\\Users\\x\\a.exe")!;
    expect(sameLocation(device, otherDevice)).toEqual({ same: false });
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
    expect(find(out, "m1").description).toContain("volume not compared (drive vs guid)");
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
    expect(run(plain)).toEqual(plain);
    expect(run(plain)[0]).toBe(plain[0]);
  });

  it("the annotated row keys as the plain one on re-import", () => {
    const m = find(run([mark(), prefetch()]), "m1");
    expect(cleanDescription(m.description)).toBe(cleanDescription(mark().description));
  });
});

// #985: velociraptorImport.ts's actionEvent() always sets sources: ["Velociraptor"] — never the
// tool name — so a Prefetch/Amcache/ShimCache/UserAssist row imported through Velociraptor carried
// no signal `classify()` recognised. The tool name is still in `description`, in a fixed segment
// (`Velociraptor [<artifact>]: <action>: <subject>`) written by the importer's own code, never by
// attacker-influenced `<subject>` text.
describe("Velociraptor-shaped rows (no literal tool name in sources)", () => {
  const veloRow = (over: Partial<Ev> = {}): Ev => ({
    id: "v1",
    timestamp: at(3),
    description: "Velociraptor [Windows.Forensics.Prefetch]: Executed (prefetch) (1×): tool.exe - @ WS-01",
    severity: "Info",
    mitreTechniques: [],
    path: "C:\\Users\\x\\Downloads\\tool.exe",
    asset: "WS-01",
    sources: ["Velociraptor"],
    ...over,
  });

  it("a Velociraptor Prefetch row corroborates a mark the same way a KAPE one does", () => {
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), veloRow()]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.description).toContain("Prefetch last run");
  });

  it("a Velociraptor Amcache/ShimCache row is presence, listed and never a raise", () => {
    const out = run([
      mark({ sources: ["Sysmon"], asset: "WS-01" }),
      veloRow({
        id: "a1",
        description:
          "Velociraptor [Windows.Forensics.Amcache/InventoryApplicationFile]: Program file present (Amcache): tool.exe - @ WS-01",
      }),
      veloRow({
        id: "sh1",
        description:
          "Velociraptor [Windows.Registry.AppCompatCache]: Present in ShimCache (time shown is the file's modification time, not a run time): tool.exe - @ WS-01",
      }),
    ]);
    const m = find(out, "m1");
    expect(m.severity).toBe("Medium");
    expect(m.description).toContain("Amcache present");
    expect(m.description).toContain("ShimCache present");
    expect(find(out, "a1").severity).toBe("Info");
  });

  it("a UserAssist row is execution evidence: raises to High like Prefetch, no technique added", () => {
    const out = run([
      mark({ sources: ["Sysmon"], asset: "WS-01" }),
      veloRow({
        id: "u1",
        description: "Velociraptor [Windows.Registry.UserAssist]: Ran (UserAssist) (5×): tool.exe - @ WS-01",
      }),
    ]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.mitreTechniques).toEqual([]);
    expect(m.description).toContain("UserAssist");
  });

  it("a subject that happens to contain 'prefetch' or 'UserAssist' does not spoof a classification", () => {
    // The bounded match only reads the fixed action segment before the subject's own colon
    // boundary — a downloaded file named to look like the action text must not self-corroborate.
    const spoofPath = "C:\\Users\\x\\Downloads\\notprefetch_UserAssist_tool.exe";
    const out = run([
      mark({ sources: ["Sysmon"], asset: "WS-01", path: spoofPath }),
      {
        id: "spoof1",
        timestamp: at(3),
        description: `Velociraptor [Some.Other.Artifact]: Did something unrelated: ${spoofPath} - @ WS-01`,
        severity: "Info",
        mitreTechniques: [],
        path: spoofPath,
        asset: "WS-01",
        sources: ["Velociraptor"],
      },
    ]);
    expect(find(out, "m1").description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
  });

  it("a non-Velociraptor row with a lookalike description prefix is not classified by it", () => {
    // The description-based fallback is gated on sources actually naming Velociraptor — a row from
    // another importer (or a KAPE row whose free text happens to start the same way) must not be
    // read as if it were one (#985 code review).
    const out = run([
      mark({ sources: ["Sysmon"], asset: "WS-01" }),
      {
        id: "lookalike1",
        timestamp: at(3),
        description:
          "Velociraptor [Windows.Forensics.Prefetch]: Executed (prefetch) (1×): tool.exe - @ WS-01",
        severity: "Info",
        mitreTechniques: [],
        path: "C:\\Users\\x\\Downloads\\tool.exe",
        asset: "WS-01",
        sources: ["SomeOtherTool"],
      },
    ]);
    expect(find(out, "m1").description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
  });

  it("a real Windows.Registry.UserAssist row from parseVelociraptorJson corroborates a mark", async () => {
    // Pinned against the actual importer, not a hand-built description (#985 code review): Name
    // carries a full resolved path (velociraptorImport.test.ts's own UserAssist fixture uses
    // "C:\\Tools\\mimikatz.exe"), not a GUID-prefixed shell token.
    const { parseVelociraptorJson } = await import("../../src/analysis/velociraptorImport.js");
    const { events } = parseVelociraptorJson(
      JSON.stringify([
        {
          _Source: "Windows.Registry.UserAssist",
          Name: "C:\\Users\\x\\Downloads\\tool.exe",
          NumberOfExecutions: 3,
          LastExecution: at(3),
          Fqdn: "WS-01",
        },
      ]),
    );
    const row = events[0] as unknown as Ev;
    expect(row.description).toContain("Ran (UserAssist)");
    expect(row.sources).toContain("Velociraptor");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), { ...row, id: "real-ua1" }]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.description).toContain("UserAssist ran");
  });
});

// #985 item 4 (hash-across-artifacts half, CLI-sourced YARA only — see RECOMMENDATION-985-1a-yara
// for why the Velociraptor-native YARA leg is a separate follow-up): a download mark's file,
// matched by PATH to a YARA rule hit from the raw CLI importer. The CLI row's own sha256/md5 is
// the rule author's reference-sample hash (rule metadata), never a hash the CLI computes of the
// scanned file — so it must never veto a path match, and must never enter the hash-bucket join.
describe("mark → YARA content match (CLI-sourced only)", () => {
  const yaraRow = async (headerLine: string, over: Partial<Ev> = {}): Promise<Ev> => {
    const { parseYaraOutput } = await import("../../src/analysis/yaraImport.js");
    const { events } = parseYaraOutput(headerLine);
    return { ...(events[0] as unknown as Ev), id: "y1", timestamp: at(3), ...over };
  };
  const TOOL_PATH = String.raw`C:\Users\x\Downloads\tool.exe`;
  const OTHER_PATH = String.raw`C:\Users\x\Downloads\other.exe`;

  it("a CLI YARA match at the mark's exact path raises the mark to High, no technique, both rows noted", async () => {
    const yara = await yaraRow(`EvilRule [apt,trojan] ${TOOL_PATH}`);
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), yara]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.mitreTechniques).toEqual([]);
    expect(m.description).toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(m.description).toContain("YARA: EvilRule content match");
    const y = find(out, "y1");
    expect(y.description).toContain(YARA_MATCHES_MARK_MARKER);
  });

  it("the mark's own real hash disagreeing with the YARA row's rule-metadata hash does NOT veto the path match", async () => {
    // Pins the exact bug the design review found: candidatesFor's path-bucket hashVeto ran
    // unconditionally against every candidate, including a CLI YARA row whose hash field isn't
    // this row's own identity at all.
    const yara = await yaraRow(`EvilRule [author="x",sha256="${"ab".repeat(32)}"] ${TOOL_PATH}`);
    const out = run([
      mark({
        sources: ["Sysmon"],
        asset: "WS-01",
        sha256: "cd".repeat(32), // a real, independently-observed hash — genuinely differs from the rule's
      }),
      yara,
    ]);
    expect(find(out, "m1").description).toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(find(out, "m1").severity).toBe("High");
  });

  it("a YARA row at a different path never joins", async () => {
    const yara = await yaraRow(`EvilRule [apt] ${OTHER_PATH}`);
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), yara]);
    expect(find(out, "m1").description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(find(out, "m1").severity).toBe("Medium");
  });

  it("two named, disagreeing hosts never join (a second named-host execution row supplies the host)", async () => {
    const yara = await yaraRow(`EvilRule [apt] ${TOOL_PATH}`, { asset: "WS-02" });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), yara]);
    expect(find(out, "y1").description).not.toContain(YARA_MATCHES_MARK_MARKER);
  });

  it("a CLI YARA row's rule-metadata hash never participates in an unrelated mark's hash-bucket match", async () => {
    // Closes the cross-source hash-bucket collision the design review found: a CLI YARA row must
    // never be findable via byHash, not just never ADD itself to it.
    const sharedHash = "ef".repeat(32);
    const yara = await yaraRow(`EvilRule [author="x",sha256="${sharedHash}"] ${OTHER_PATH}`);
    const out = run([
      mark({
        sources: ["Sysmon"],
        asset: "WS-01",
        path: String.raw`C:\Users\x\Downloads\unrelated.exe`,
        sha256: sharedHash,
      }),
      yara,
    ]);
    expect(find(out, "m1").description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(find(out, "m1").severity).toBe("Medium");
  });
});

// #985 item 4 (hash-across-artifacts half, THOR leg — 985-1a-3): a download mark's file, matched
// by path OR hash to a THOR (Nextron) finding. Unlike CLI YARA, THOR's own sha256/md5/path are
// genuine per-row identity (thorRowMap.ts's own documented contract — what correlate.ts already
// unions on), so both bucket paths are eligible. The mark raises to the THOR finding's OWN graded
// severity, not a flat tier.
describe("mark → THOR finding", () => {
  const ENVELOPE = { scanid: "S-test0001", log_version: "v1.0.0" };
  const TOOL_PATH = String.raw`C:\Users\x\Downloads\tool.exe`;
  const OTHER_PATH = String.raw`C:\Users\x\Downloads\other.exe`;

  const standaloneThorRow = async (row: Record<string, unknown>, over: Partial<Ev> = {}): Promise<Ev> => {
    const { parseThorReport } = await import("../../src/analysis/thorImport.js");
    const { events } = parseThorReport(JSON.stringify(row));
    return { ...(events[0] as unknown as Ev), id: "t1", timestamp: at(3), ...over };
  };

  const veloThorRow = async (row: Record<string, unknown>, over: Partial<Ev> = {}): Promise<Ev> => {
    const { thorFields } = await import("../../src/analysis/thorRowMap.js");
    const f = thorFields(row, { artifact: "Generic.Scanner.ThorZIP", host: "DESKTOP-01" });
    return {
      id: "t1",
      timestamp: at(3),
      description: f?.description ?? "",
      severity: f?.severity ?? "Info",
      mitreTechniques: f?.mitre ?? [],
      ...(f?.path ? { path: f.path } : {}),
      ...(f?.sha256 ? { sha256: f.sha256 } : {}),
      ...(f?.md5 ? { md5: f.md5 } : {}),
      sources: ["Velociraptor"],
      ...over,
    };
  };

  it("a standalone THOR alert (sources: THOR) at the mark's path raises the mark to Critical, no technique, both rows noted", async () => {
    const thor = await standaloneThorRow({
      ...ENVELOPE,
      level: "Alert",
      module: "ProcessCheck",
      message: "Malicious process found",
      process_name: "tool.exe",
      image_file: TOOL_PATH,
      image_sha256: "11".repeat(32),
    });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), thor]);
    const m = find(out, "m1");
    expect(m.severity).toBe("Critical");
    expect(m.mitreTechniques).toEqual([]);
    expect(m.description).toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(m.description).toContain("THOR flagged");
    const t = find(out, "t1");
    expect(t.description).toContain(YARA_MATCHES_MARK_MARKER);
  });

  it("a Velociraptor-streamed THOR row (sources: Velociraptor, description 'THOR ...') also matches, raised to its own severity", async () => {
    const thor = await veloThorRow({
      ...ENVELOPE,
      level: "Warning",
      module: "Filescan",
      message: "Possibly Dangerous file found",
      file: TOOL_PATH,
      sha256: "22".repeat(32),
    });
    expect(thor.description.startsWith("THOR Warning [Filescan]")).toBe(true);
    const out = run([mark({ sources: ["Sysmon"], asset: "DESKTOP-01" }), thor]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High"); // LEVEL["warning"] -> High
    expect(m.description).toContain(DOWNLOAD_EXECUTED_MARKER);
  });

  it("a THOR row matches by hash alone, at a different path", async () => {
    const sharedHash = "33".repeat(32);
    const thor = await standaloneThorRow({
      ...ENVELOPE,
      level: "Notice",
      module: "Filescan",
      message: "Suspicious file found",
      file: OTHER_PATH,
      sha256: sharedHash,
    });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01", sha256: sharedHash }), thor]);
    const m = find(out, "m1");
    expect(m.severity).toBe("Medium"); // LEVEL["notice"] -> Medium
    expect(m.description).toContain("(by hash, at");
  });

  it("a subjectIsEntry (LogScan) THOR row carries no path — excluded by classify()'s existing !e.path gate, no new logic needed", async () => {
    const thor = await veloThorRow({
      ...ENVELOPE,
      level: "Warning",
      module: "LogScan",
      message: "Suspicious Log Entry found",
      entry: "2026-08-18T16:14:39.033 Engine:command line reported as threat: tool.exe",
      file: TOOL_PATH, // the LOG the entry was read from, not the finding's subject
    });
    expect(thor.path).toBeUndefined();
    const out = run([mark({ sources: ["Sysmon"], asset: "DESKTOP-01" }), thor]);
    expect(find(out, "m1").description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(find(out, "m1").severity).toBe("Medium");
  });

  it("a self-scan-demoted (Info) THOR row that matches a mark neither raises the mark beyond its own evidence nor re-promotes itself", async () => {
    // Simulates mapGeneric's/thorImport.ts's own self-scan demotion, which runs upstream of this
    // pass (#985 item 4, 985-1a-3 design review, finding F2): the row already carries severity
    // "Info" by the time it reaches corroborateDownloadExecution.
    const thor: Ev = {
      id: "t1",
      timestamp: at(3),
      description: "THOR Warning [Filescan]: Possibly Dangerous file found — tool.exe",
      severity: "Info",
      mitreTechniques: [],
      path: TOOL_PATH,
      sources: ["Velociraptor"],
      asset: "WS-01",
    };
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), thor]);
    expect(find(out, "m1").severity).toBe("Medium"); // unchanged — the mark's own starting severity
    expect(find(out, "t1").severity).toBe("Info"); // not re-promoted to Medium
  });

  it("a THOR row at a different path/hash never joins", async () => {
    const thor = await standaloneThorRow({
      ...ENVELOPE,
      level: "Alert",
      module: "Filescan",
      message: "Malicious file found",
      file: OTHER_PATH,
    });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), thor]);
    expect(find(out, "m1").description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(find(out, "m1").severity).toBe("Medium");
  });

  it("two named, disagreeing hosts never join", async () => {
    const thor = await standaloneThorRow(
      { ...ENVELOPE, level: "Alert", module: "Filescan", message: "Malicious file found", file: TOOL_PATH },
      { asset: "WS-02" },
    );
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), thor]);
    expect(find(out, "t1").description).not.toContain(YARA_MATCHES_MARK_MARKER);
  });

  it("a THOR message naming Sysmon or event ID 4688 is still labelled THOR, not mislabelled by the description-text heuristics (F7)", async () => {
    const thor = await standaloneThorRow({
      ...ENVELOPE,
      level: "Alert",
      module: "LogScan",
      message: "Suspicious Sysmon Event ID 4688 process creation logged",
      file: TOOL_PATH,
    });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), thor]);
    expect(find(out, "m1").description).toContain("THOR flagged");
    expect(find(out, "m1").description).not.toMatch(/Sysmon 1 flagged|Security 4688 flagged/);
  });

  it("a spoofed description starting 'THOR ' from an unrecognized source never corroborates (F5)", () => {
    const out = run([
      mark({ sources: ["Sysmon"], asset: "WS-01" }),
      {
        id: "t1",
        timestamp: at(3),
        description: "THOR Alert [Fake]: not a real THOR row",
        severity: "Critical",
        mitreTechniques: [],
        path: TOOL_PATH,
        sources: ["SomeOtherTool"],
        asset: "WS-01",
      },
    ]);
    expect(find(out, "m1").description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(find(out, "m1").severity).toBe("Medium");
  });
});

// #985 item 4 (hash-across-artifacts half, Velociraptor-native YARA leg — 985-1a-2): a download
// mark's file, matched by path or hash to a Velociraptor-native YARA hit (velociraptorImport.ts's
// mapYara). Unlike CLI YARA, its sha256/md5 (vrHashes) are genuine per-row identity, and its
// severity (yaraGrade.ts's gradeYaraHit) already reflects self-scan/volatile/heuristic demotion, so
// the mark raises proportionally to it — read through the classification-time flag, not a string
// compare on the artifact label (985-1a-3's own F5 fix, reused here).
describe("mark → Velociraptor-native YARA content match", () => {
  const TOOL_PATH = String.raw`C:\Users\x\Downloads\tool.exe`;
  const OTHER_PATH = String.raw`C:\Users\x\Downloads\other.exe`;

  const veloYaraRow = async (row: Record<string, unknown>, over: Partial<Ev> = {}): Promise<Ev> => {
    const { parseVelociraptorJson } = await import("../../src/analysis/velociraptorImport.js");
    const { events } = parseVelociraptorJson(JSON.stringify({ "Windows.Detection.Yara.Glob": [row] }));
    return { ...(events[0] as unknown as Ev), id: "y1", timestamp: at(3), ...over };
  };

  it("a named-malware rule at the mark's exact path raises the mark to High, no technique, both rows noted", async () => {
    const yara = await veloYaraRow({
      Rule: "APT_Malware_Foo",
      OSPath: TOOL_PATH,
      HashSHA256: "44".repeat(32),
    });
    expect(yara.description).toBe(
      `Velociraptor [Windows.Detection.Yara.Glob] YARA: APT_Malware_Foo - ${TOOL_PATH}`,
    );
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), yara]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.mitreTechniques).toEqual([]);
    expect(m.description).toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(m.description).toContain("Velociraptor YARA: APT_Malware_Foo content match");
    expect(find(out, "y1").description).toContain(YARA_MATCHES_MARK_MARKER);
  });

  it("a self-scan hit (severity: Info) neither raises the mark beyond its own evidence nor re-promotes itself", async () => {
    const yara = await veloYaraRow({
      Rule: "APT_Malware_Foo",
      OSPath: String.raw`C:\Program Files\Velociraptor\Velociraptor.exe`,
    });
    expect(yara.severity).toBe("Info");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01", path: yara.path }), yara]);
    expect(find(out, "m1").severity).toBe("Medium"); // unchanged — the mark's own starting severity
    expect(find(out, "y1").severity).toBe("Info"); // not re-promoted to Medium
  });

  it("a heuristic-trusted hit (Low, NOT Info) IS re-promoted when it matches — intentional, not a self-scan (F1)", async () => {
    const yara = await veloYaraRow({
      Rule: "SIGNATURE_BASE_SUSP_Something",
      OSPath: String.raw`C:\Windows\System32\svchost.exe`,
    });
    expect(yara.severity).toBe("Low");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01", path: yara.path }), yara]);
    expect(find(out, "m1").severity).toBe("Medium"); // raise(Medium, Low) stays Medium — no-op here
    expect(find(out, "y1").severity).toBe("Medium"); // re-promoted from Low — the reciprocal arm's intended behaviour
  });

  it("a heuristic rule elsewhere (Medium) raises the mark proportionally, not to a flat tier", async () => {
    const yara = await veloYaraRow({
      Rule: "SIGNATURE_BASE_SUSP_Something",
      OSPath: TOOL_PATH,
    });
    expect(yara.severity).toBe("Medium");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), yara]);
    expect(find(out, "m1").severity).toBe("Medium");
    expect(find(out, "m1").description).toContain(DOWNLOAD_EXECUTED_MARKER);
  });

  it("a hit matches by hash alone, at a different path", async () => {
    const sharedHash = "55".repeat(32);
    const yara = await veloYaraRow({
      Rule: "APT_Malware_Foo",
      OSPath: OTHER_PATH,
      HashSHA256: sharedHash,
    });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01", sha256: sharedHash }), yara]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.description).toContain("(by hash, at");
  });

  it("a hit at a different path/hash never joins", async () => {
    const yara = await veloYaraRow({ Rule: "APT_Malware_Foo", OSPath: OTHER_PATH });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), yara]);
    expect(find(out, "m1").description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(find(out, "m1").severity).toBe("Medium");
  });

  it("a rule/hit-context mentioning Sysmon or event ID 4688 is still labelled Velociraptor YARA, not mislabelled (F7)", async () => {
    const yara = await veloYaraRow({
      Rule: "Sysmon_4688_Suspicious_Child",
      OSPath: TOOL_PATH,
    });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), yara]);
    expect(find(out, "m1").description).toContain("Velociraptor YARA:");
    expect(find(out, "m1").description).not.toMatch(/Sysmon 1 content match|Security 4688 content match/);
  });

  it("a memory hit shaped with a canonical process/start marker still classifies as detection, not execution (F3)", async () => {
    const yara = await veloYaraRow(
      { Rule: "APT_Malware_Foo", OSPath: TOOL_PATH },
      { canonical: { event: { category: "process", type: "start" } } },
    );
    // If misclassified as execution, the note would say "process start"/"last run" and raise flat
    // High unconditionally; as detection it says "content match" and raises proportionally.
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), yara]);
    expect(find(out, "m1").description).toContain("Velociraptor YARA: APT_Malware_Foo content match");
  });

  it("CLI YARA's own flat-High raise is unaffected by the proportionalSeverity flag", async () => {
    const { parseYaraOutput } = await import("../../src/analysis/yaraImport.js");
    const { events } = parseYaraOutput(`EvilRule [apt] ${TOOL_PATH}`);
    const cliYara: Ev = { ...(events[0] as unknown as Ev), id: "c1", timestamp: at(3) };
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), cliYara]);
    expect(find(out, "m1").severity).toBe("High");
  });
});

// #985 item 2/3: a download mark's file, matched by path (device or drive-lettered) to a BAM
// (Background Activity Moderator) execution record — Windows.Forensics.Bam via
// velociraptorImport.ts's bamFields(). Execution-kind, like Prefetch: an observation time to order
// against the mark's anchor, a flat-High raise on an after-anchor match, no severity of its own.
describe("mark → BAM execution", () => {
  const DEVICE_TOOL_PATH = String.raw`\Device\HarddiskVolume3\Users\x\Downloads\tool.exe`;
  const DEVICE_OTHER_PATH = String.raw`\Device\HarddiskVolume3\Users\x\Downloads\other.exe`;

  const bamRow = async (row: Record<string, unknown>, over: Partial<Ev> = {}): Promise<Ev> => {
    const { parseVelociraptorJson } = await import("../../src/analysis/velociraptorImport.js");
    const { events } = parseVelociraptorJson(JSON.stringify({ "Windows.Forensics.Bam": [row] }));
    return { ...(events[0] as unknown as Ev), id: "b1", ...over };
  };

  it("a BAM record after the mark's anchor raises the mark to High, no technique, both rows noted", async () => {
    const bam = await bamRow({
      SID: "S-1-5-21-1-2-3-1001",
      UserName: "alice",
      Binary: DEVICE_TOOL_PATH,
      Bam_time: at(3),
    });
    expect(bam.description).toBe(
      "Velociraptor [Windows.Forensics.Bam] BAM: tool.exe last run 2026-05-02T10:00:03.000Z (user alice)",
    );
    expect(bam.severity).toBe("Info");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), bam]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.mitreTechniques).toEqual([]);
    expect(m.description).toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(m.description).toContain("BAM last run");
    const b = find(out, "b1");
    expect(b.description).toContain(RAN_MARKED_FILE_MARKER);
  });

  it("device-vs-drive: a BAM device path matches a drive-lettered mark on the relative path alone", async () => {
    const bam = await bamRow({
      SID: "S-1-5-21-1-2-3-1001",
      UserName: "alice",
      Binary: DEVICE_TOOL_PATH,
      Bam_time: at(3),
    });
    const out = run([
      mark({ sources: ["Sysmon"], asset: "WS-01", path: String.raw`C:\Users\x\Downloads\tool.exe` }),
      bam,
    ]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.description).toContain("volume not compared (drive vs device)");
  });

  it("a run before the anchor or with no readable time is said and raises nothing", async () => {
    const before = await bamRow({
      SID: "S-1-5-21-1-2-3-1001",
      UserName: "alice",
      Binary: DEVICE_TOOL_PATH,
      Bam_time: at(-86400),
    });
    const out = run([mark(), before]);
    expect(find(out, "m1").severity).toBe("Medium");
    expect(find(out, "m1").description).toContain("BAM last run");
  });

  it("a BAM record at a different path never joins", async () => {
    const bam = await bamRow({
      SID: "S-1-5-21-1-2-3-1001",
      UserName: "alice",
      Binary: DEVICE_OTHER_PATH,
      Bam_time: at(3),
    });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), bam]);
    expect(find(out, "m1").description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(find(out, "m1").severity).toBe("Medium");
  });

  it("two named, disagreeing hosts never join", async () => {
    const bam = await bamRow(
      { SID: "S-1-5-21-1-2-3-1001", UserName: "alice", Binary: DEVICE_TOOL_PATH, Bam_time: at(3) },
      { asset: "WS-02" },
    );
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), bam]);
    expect(find(out, "b1").description).not.toContain(RAN_MARKED_FILE_MARKER);
  });

  it("a hostile binary basename naming Sysmon or event ID 4688 is still labelled BAM, not mislabelled", async () => {
    const bam = await bamRow({
      SID: "S-1-5-21-1-2-3-1001",
      UserName: "alice",
      Binary: String.raw`\Device\HarddiskVolume3\Users\x\Downloads\Sysmon 4688.exe`,
      Bam_time: at(3),
    });
    const out = run([
      mark({ sources: ["Sysmon"], asset: "WS-01", path: String.raw`C:\Users\x\Downloads\Sysmon 4688.exe` }),
      bam,
    ]);
    expect(find(out, "m1").description).toContain("BAM last run");
    expect(find(out, "m1").description).not.toMatch(/Sysmon 1 last run|Security 4688 last run/);
  });

  it("thorFields and bamFields compose without cross-contamination", async () => {
    const { parseVelociraptorJson } = await import("../../src/analysis/velociraptorImport.js");
    // A THOR row is unaffected by bamFields being tried second (thorFields short-circuits first).
    const thorRaw = parseVelociraptorJson(
      JSON.stringify({
        "Generic.Scanner.ThorZIP": [
          {
            scanid: "S-1",
            log_version: "v1",
            level: "Alert",
            module: "Filescan",
            message: "m",
            file: "a.exe",
          },
        ],
      }),
    ).events[0];
    expect(thorRaw.description).toMatch(/^THOR /);
    // A BAM row is unaffected by THOR's absence.
    const bamRaw = parseVelociraptorJson(
      JSON.stringify({
        "Windows.Forensics.Bam": [
          { SID: "S-1-5-21-1-2-3-1001", UserName: "alice", Binary: DEVICE_TOOL_PATH, Bam_time: at(3) },
        ],
      }),
    ).events[0];
    expect(bamRaw.description).toContain("BAM: tool.exe");
  });
});

// #985 (browser-origin half): a mark's own download URL or referrer, matched against a
// Velociraptor browser-history "Visited" row for the same URL — T1189's precondition, never the
// technique itself (no mitreTechniques added in any case here).
describe("mark → browser visit", () => {
  const visitRow = async (url: string, over: Partial<Ev> = {}): Promise<Ev> => {
    const { parseVelociraptorJson } = await import("../../src/analysis/velociraptorImport.js");
    const { events } = parseVelociraptorJson(
      JSON.stringify([
        {
          _Source: "Windows.Applications.Chrome.History",
          visited_url: url,
          title: "Evil",
          visit_count: 1,
          visit_time: at(-30),
          Fqdn: "WS-01",
        },
      ]),
    );
    return { ...(events[0] as unknown as Ev), id: "v1", ...over };
  };

  it("the mark's own URL, visited: raises to Medium, no technique, both rows noted", async () => {
    const visit = await visitRow("https://evil.example/tool.exe");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), visit]);
    const m = find(out, "m1");
    expect(m.severity).toBe("Medium");
    expect(m.mitreTechniques).toEqual([]);
    expect(m.description).toContain(BROWSER_VISIT_MARKER);
    expect(m.description).toContain("visited the download URL");
    const v = find(out, "v1");
    expect(v.severity).toBe("Medium");
    expect(v.description).toContain(VISIT_PRECEDES_MARK_MARKER);
  });

  it("a visit to the referrer page (not the download URL) is noted separately", async () => {
    const visit = await visitRow("https://phish.example/page");
    const out = run([
      mark({
        sources: ["Sysmon"],
        asset: "WS-01",
        description: `MFT: .\\Users\\x\\Downloads\\tool.exe — downloaded from the Internet zone (https://evil.example/tool.exe, referrer https://phish.example/page) — ${PROVENANCE_NOTE}`,
      }),
      visit,
    ]);
    const m = find(out, "m1");
    expect(m.severity).toBe("Medium");
    expect(m.mitreTechniques).toEqual([]);
    expect(m.description).toContain(REFERRER_VISIT_MARKER);
    expect(m.description).toContain("visited the referrer page");
    expect(m.description).not.toContain("visited the download URL");
  });

  it("normalizes scheme/host case and a trailing slash, but not the path", async () => {
    const visit = await visitRow("HTTPS://Evil.Example/tool.exe/");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), visit]);
    expect(find(out, "m1").description).toContain(BROWSER_VISIT_MARKER);
    const differentPath = await visitRow("https://evil.example/other.exe");
    const miss = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), differentPath]);
    expect(find(miss, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
  });

  it("two named, disagreeing hosts never join", async () => {
    const visit = await visitRow("https://evil.example/tool.exe", { asset: "WS-02" });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), visit]);
    expect(find(out, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
  });

  it("a non-Velociraptor row with a lookalike 'Visited' description does not spoof a match", () => {
    const out = run([
      mark({ sources: ["Sysmon"], asset: "WS-01" }),
      {
        id: "lookalike1",
        timestamp: at(-30),
        description:
          "Velociraptor [Windows.Applications.Chrome.History]: Visited (1×): https://evil.example/tool.exe - @ WS-01",
        severity: "Info",
        mitreTechniques: [],
        asset: "WS-01",
        sources: ["SomeOtherTool"],
      },
    ]);
    expect(find(out, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
  });

  it("a visit AFTER the mark, or within tolerance, is never labeled 'preceded' and raises nothing", async () => {
    // #985 code review: matching by URL alone is not evidence of order. A revisit, a re-download
    // check, or analyst verification browsing after the file already exists must not corroborate
    // a drive-by story the evidence doesn't support.
    const after = await visitRow("https://evil.example/tool.exe", { timestamp: at(30) });
    const outAfter = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), after]);
    expect(find(outAfter, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
    expect(find(outAfter, "m1").severity).toBe("Medium"); // the mark's own default severity, unraised
    const v = find(outAfter, "v1");
    expect(v.description).not.toContain(VISIT_PRECEDES_MARK_MARKER);
    expect(v.severity).toBe("Info");
    const within = await visitRow("https://evil.example/tool.exe", { timestamp: at(1) });
    const outWithin = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), within]);
    expect(find(outWithin, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
  });

  it("a real Zone.Identifier mark from ntfsStreams.readHost is corroborated by a real visit", async () => {
    // Pinned against the actual mark-producing code, not a hand-typed description (#985 code
    // review, same lesson as the #1196 UserAssist fix): if markWords()'s wording ever drifts,
    // this test — not just the regex it exercises — fails.
    const { readHost } = await import("../../src/analysis/ntfsStreams.js");
    const h = readHost({
      path: ".\\Users\\x\\Downloads\\tool.exe",
      contents: "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.example/tool.exe\r\n",
    });
    const row = mark({
      sources: ["Sysmon"],
      asset: "WS-01",
      description: `MFT: x — ${[h.words, ...h.qualifiers].join(" — ")}`,
    });
    const visit = await visitRow("https://evil.example/tool.exe");
    expect(find(run([row, visit]), "m1").description).toContain(BROWSER_VISIT_MARKER);
  });

  it("a referrer equal to the download URL after normalization is not double-counted", async () => {
    const visit = await visitRow("https://evil.example/tool.exe");
    const out = run([
      mark({
        sources: ["Sysmon"],
        asset: "WS-01",
        description: `MFT: .\\Users\\x\\Downloads\\tool.exe — downloaded from the Internet zone (https://evil.example/tool.exe, referrer HTTPS://Evil.Example/tool.exe/) — ${PROVENANCE_NOTE}`,
      }),
      visit,
    ]);
    const m = find(out, "m1");
    expect(m.description).toContain("visited the download URL");
    expect(m.description).not.toContain("visited the referrer page");
    const v = find(out, "v1");
    expect(
      v.description.match(new RegExp(VISIT_PRECEDES_MARK_MARKER.replace(/[[\]]/g, "\\$&"), "g")) ?? [],
    ).toHaveLength(1);
  });

  it("a default port (:443 on https) folds; a different explicit port does not", async () => {
    const visit = await visitRow("https://evil.example:443/tool.exe");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), visit]);
    expect(find(out, "m1").description).toContain(BROWSER_VISIT_MARKER);
    const otherPort = await visitRow("https://evil.example:8443/tool.exe");
    const miss = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), otherPort]);
    expect(find(miss, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
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

  it("a bare or relative reference resolves to nothing and is not a lead — the grammar also matches host:port", () => {
    const out = run([
      streamRow(),
      sysmon({
        id: "c1",
        commandLine: "wscript notes.txt:payload.dll",
        path: "C:\\Windows\\System32\\wscript.exe",
      }),
      sysmon({ id: "c2", commandLine: "tool proxy.example.com:8080 10.0.0.1:443" }),
    ]);
    expect(find(out, "st1").severity).toBe("Medium");
    expect(find(out, "st1").description).not.toContain(STREAM_REFERENCED_MARKER);
    for (const id of ["c1", "c2"]) {
      expect(find(out, id).severity).toBe("Low");
      expect(find(out, id).description).not.toContain(STREAM_REFERENCE_MARKER);
    }
  });

  it("an absolute reference with no stream row on that host is a lead on the process row; a different host never resolves", () => {
    const none = find(
      run([streamRow(), sysmon({ id: "c1", commandLine: "rundll32 C:\\Users\\y\\other.txt:p.dll,E" })]),
      "c1",
    );
    expect(none.description).toContain("no stream row at this location carries it");
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

describe("code review round — Codex findings", () => {
  it("1. a differing SHA-256 beside a matching MD5 is a disagreement, never a hash join", () => {
    const out = run([
      mark({
        sha256: "ab".repeat(32),
        md5: "11".repeat(16),
        sources: ["Sysmon"],
        asset: "WS-01",
        path: "C:\\Users\\x\\Downloads\\tool.exe",
      }),
      sysmon({ path: "C:\\Temp\\other.exe", sha256: "cd".repeat(32), md5: "11".repeat(16) }),
    ]);
    const m = find(out, "m1");
    expect(m.severity).toBe("Medium");
    expect(m.description).not.toContain("by hash");
  });

  it("2. a note whose evidence left the case comes off on the next merge; severity is never lowered", () => {
    const first = run([mark(), prefetch()]);
    const later = run([find(first, "m1")]);
    const m = find(later, "m1");
    expect(m.description).not.toContain(DOWNLOAD_EXECUTED_MARKER);
    expect(m.severity).toBe("High");
    const p = run([find(first, "p1")]);
    expect(find(p, "p1").description).not.toContain(RAN_MARKED_FILE_MARKER);
  });

  it("3. fan-out is bounded: 500 marks × 500 executions on one path name 8 and count the rest, in bounded time", () => {
    const marks = Array.from({ length: 500 }, (_, i) => mark({ id: `m${i}` }));
    const runs = Array.from({ length: 500 }, (_, i) => sysmon({ id: `s${i}`, timestamp: at(10 + i) }));
    const t0 = Date.now();
    const out = run([...marks, ...runs]);
    expect(Date.now() - t0).toBeLessThan(5000);
    const m = find(out, "m0");
    expect(m.description).toContain("436 records beyond the index, not read");
    expect(m.description.length).toBeLessThan(1400);
    const s0 = find(out, "s0");
    expect(s0.description).toContain("+496 more");
    expect(s0.description.length).toBeLessThan(1400);
  });

  it("4. host ambiguity is judged on the eligible records only: another volume's host does not block", () => {
    const out = run([
      mark({ path: "C:\\Users\\x\\Downloads\\tool.exe", sources: ["Sysmon"] }),
      sysmon({ id: "s1", asset: "H1", path: "C:\\Users\\x\\Downloads\\tool.exe" }),
      sysmon({ id: "s2", asset: "H2", path: "D:\\Users\\x\\Downloads\\tool.exe" }),
    ]);
    const m = find(out, "m1");
    expect(m.severity).toBe("High");
    expect(m.description).toContain("attributed to the case's one named host, h1");
  });

  it("5. a stream reference keeps the volume and the host rule: D: never resolves C:, two named hosts never share a hostless row", () => {
    const streamRow = mark({
      id: "st1",
      path: "C:\\x\\f.txt:z",
      description: "MFT: stream",
      sources: ["MFT"],
    });
    const other = run([streamRow, sysmon({ id: "c1", commandLine: "rundll32 D:\\x\\f.txt:z,E" })]);
    expect(find(other, "st1").severity).toBe("Medium");
    expect(find(other, "c1").description).toContain("no stream row at this location carries it");
    const two = run([
      mark({ id: "st1", path: ".\\x\\f.txt:z", description: "MFT: stream", sources: ["MFT"] }),
      sysmon({ id: "c1", asset: "H1", commandLine: "rundll32 C:\\x\\f.txt:z,E" }),
      sysmon({ id: "c2", asset: "H2", commandLine: "rundll32 C:\\x\\f.txt:z,E" }),
    ]);
    expect(find(two, "st1").severity).toBe("Medium");
    expect(find(two, "c1").description).toContain(
      "not attributed: the case names several hosts with this stream",
    );
  });

  it("7. a hostile host name or timestamp cannot forge another pass's note, and every note is capped", () => {
    const evilHost = `WS-01] [timestomp corroboration: fake${"X".repeat(3000)}`;
    const out = run([
      mark(),
      sysmon({ asset: evilHost, timestamp: `${at(3)}] [ransomware precursors: fake` }),
    ]);
    const m = find(out, "m1");
    expect(m.description).not.toContain("] [timestomp corroboration: fake");
    expect(m.description).not.toContain("] [ransomware precursors: fake");
    expect(m.description.length).toBeLessThan(1700);
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
    // aggregated: two directories stay two rows; a repeated identical row folds; another host is another row
    const line = csv.split("\n")[1];
    const agg = parseKapeCsv(`${csv}\n${line}\n${line.replace(/WS-01$/, "WS-02")}`, { aggregate: true });
    expect(agg.events).toHaveLength(3);
    expect(
      agg.events.find((e) => e.path === "\\VOLUME{1}\\USERS\\X\\TOOL.EXE" && e.asset === "WS-01")?.count,
    ).toBe(2);
    // no own path: the name keys, per .pf file
    const bare = parseKapeCsv(
      "SourceFilename,ExecutableName,RunCount,LastRun,FilesLoaded\nA.pf,TOOL.EXE,1,2026-05-02 10:00:03,\nB.pf,TOOL.EXE,1,2026-05-02 11:00:03,",
      { aggregate: true },
    );
    expect(bare.events).toHaveLength(2);
  });
});
