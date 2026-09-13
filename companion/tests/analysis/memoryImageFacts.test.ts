// windows.info / windows.crashinfo say what the image is — one row, only what the rows say
// (#933 item 12).
import { describe, it, expect } from "vitest";
import { parseMemory } from "../../src/analysis/memoryImport.js";
import { DUMP_LAYERS, readImageFacts, readSystemTime } from "../../src/analysis/memoryImageFacts.js";

const INFO_TEXT = [
  "Volatility 3 Framework 2.7.0",
  "Variable\tValue",
  "",
  "Kernel Base\t0xf80002a5e000",
  "DTB\t0x187000",
  "Symbols\tfile:///opt/vol3/symbols/windows/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz",
  "Is64Bit\tTrue",
  "IsPAE\tFalse",
  "primary\t0 WindowsIntel32e",
  "memory_layer\t1 WindowsCrashDump64Layer",
  "base_layer\t2 FileLayer",
  "KdVersionBlock\t0xf80002c3e0a0",
  "Major/Minor\t15.7601",
  "MachineType\t34404",
  "KeNumberProcessors\t1",
  "SystemTime\t2012-07-22 02:45:08",
  "NtSystemRoot\tC:\\Windows",
  "NtProductType\tNtProductWinNt",
  "NtMajorVersion\t6",
  "NtMinorVersion\t1",
  "PE MajorOperatingSystemVersion\t6",
  "PE TimeDateStamp\tSat Nov 20 09:30:02 2010",
].join("\n");

const infoJson = (over: Record<string, string> = {}) => {
  const vars: Record<string, string> = {
    "Kernel Base": "0xf80002a5e000",
    DTB: "0x187000",
    Symbols: "file:///x/ntkrnlmp.pdb/ABC-2.json.xz",
    Is64Bit: "True",
    primary: "0 WindowsIntel32e",
    memory_layer: "1 FileLayer",
    SystemTime: "2012-07-22T02:45:08+00:00",
    NtMajorVersion: "6",
    NtMinorVersion: "1",
    ...over,
  };
  return Object.entries(vars).map(([Variable, Value]) => ({ __children: [], Variable, Value }));
};

const CRASH = [
  {
    __children: [],
    Signature: "PAGE",
    MajorVersion: 15,
    MinorVersion: 7601,
    DirectoryTableBase: "0x187000",
    PfnDataBase: "0x1",
    PsLoadedModuleList: "0x2",
    PsActiveProcessHead: "0x3",
    MachineImageType: "0x8664",
    NumberProcessors: 1,
    KdDebuggerDataBlock: "0x4",
    DumpType: "Bitmap Dump (0x5)",
    SystemUpTime: "0:12:34",
    SystemTime: "2012-07-22T02:45:08+00:00",
    Comment: "] [x note d41d8cd98f00b204e9800998ecf8427e",
  },
];

describe("windows.info becomes ONE image row that says only what the rows say", () => {
  it("text export: one Low row, dated at the kernel SystemTime, with the facts the table knows", () => {
    const r = parseMemory(INFO_TEXT, { filename: "windows.info.txt" });
    expect(r.kept).toBe(1);
    const [e] = r.events;
    expect(e.severity).toBe("Low");
    expect(e.timestamp).toBe("2012-07-22T02:45:08.000Z");
    expect(e.description).toContain(
      "Memory image [kernel SystemTime recovered from the image: 2012-07-22T02:45:08.000Z]",
    );
    expect(e.description).toContain("[os: NT 6.1]");
    expect(e.description).toContain("[64-bit]");
    // the PDB GUID is a 32-hex run; shown broken so no correlator reads it as a file hash
    expect(e.description).toContain("[symbols: ntkrnlmp.pdb/3844DBB9…30FA-2.json.xz]");
    expect(e.description).toContain(
      "[layers: primary: 0 WindowsIntel32e; memory_layer: 1 WindowsCrashDump64Layer (crash dump); base_layer: 2 FileLayer (the backing file)]",
    );
    expect(e.description).toContain("[kernel base 0xf80002a5e000]");
    expect(e.description).toContain("[dtb 0x187000]");
    expect(e.description).not.toMatch(/captured at|PE TimeDateStamp|KdVersionBlock/);
    expect(r.iocs).toEqual([]);
  });
  it("JSON export: the same row; each known layer class gets its kind, an unknown one none", () => {
    for (const [cls, kind] of Object.entries(DUMP_LAYERS)) {
      const r = parseMemory(JSON.stringify(infoJson({ memory_layer: `1 ${cls}` })), {
        filename: "windows.info.json",
      });
      expect(r.events[0].description, cls).toContain(`memory_layer: 1 ${cls} (${kind})`);
    }
    const odd = parseMemory(JSON.stringify(infoJson({ memory_layer: "1 HibernationLayer" })), {
      filename: "windows.info.json",
    });
    expect(odd.events[0].description).toContain("memory_layer: 1 HibernationLayer]");
    expect(odd.events[0].description).not.toContain("HibernationLayer (");
  });
  it("SystemTime reads in its three forms; an unreadable one leaves the row undated and says so", () => {
    expect(readSystemTime("2012-07-22 02:45:08")).toBe("2012-07-22T02:45:08.000Z");
    expect(readSystemTime("2012-07-22T02:45:08+00:00")).toBe("2012-07-22T02:45:08.000Z");
    expect(readSystemTime("2012-07-22 02:45:08 UTC")).toBe("2012-07-22T02:45:08.000Z");
    expect(readSystemTime("2012-07-22T04:45:08+02:00")).toBe("2012-07-22T02:45:08.000Z");
    expect(readSystemTime("never")).toBe("");
    const r = parseMemory(JSON.stringify(infoJson({ SystemTime: "] [x" })), {
      filename: "windows.info.json",
    });
    expect(r.events[0].timestamp).toBe("");
    expect(r.events[0].description).toContain("[kernel SystemTime: not readable — ) (x]");
  });
  it("a runtime layer name and a variable value that spell a tag or a hash are neutralised", () => {
    const r = parseMemory(
      JSON.stringify(
        infoJson({ "] [evil": "1 FileLayer", Symbols: "file:///x/" + "a".repeat(32) + ".json.xz" }),
      ),
      { filename: "windows.info.json" },
    );
    expect(r.events[0].description).not.toContain("] [evil");
    expect(r.events[0].description).not.toMatch(/[a-f0-9]{32}/i);
  });
});

describe("windows.crashinfo reads the dump type as Volatility renders it", () => {
  it("a bitmap dump holds only the pages its bitmap lists; it is never called a kernel dump", () => {
    const r = parseMemory(JSON.stringify(CRASH), { filename: "windows.crashinfo.json" });
    expect(r.kept).toBe(1);
    const [e] = r.events;
    expect(e.description).toContain("Memory image (crash dump header)");
    expect(e.description).toContain(
      "[dump type: Bitmap Dump (0x5) — holds only the pages its bitmap lists; which pages were excluded is not in this record]",
    );
    expect(e.description).not.toMatch(/kernel dump|active memory|user-space/i);
    expect(e.description).toContain("[dump-header SystemTime: 2012-07-22T02:45:08.000Z]");
    expect(e.description).toContain("[uptime: 0:12:34]");
    expect(e.description).toContain("[comment: ) (x note d41d8cd9…427e]");
    expect(e.timestamp).toBe("2012-07-22T02:45:08.000Z");
  });
  it("a full dump and an unknown type", () => {
    const full = parseMemory(JSON.stringify([{ ...CRASH[0], DumpType: "Full Dump (0x1)" }]), {
      filename: "windows.crashinfo.json",
    });
    expect(full.events[0].description).toContain("[dump type: Full Dump (0x1) — full dump]");
    const odd = parseMemory(JSON.stringify([{ ...CRASH[0], DumpType: "Weird (0x9)" }]), {
      filename: "windows.crashinfo.json",
    });
    expect(odd.events[0].description).toContain("[dump type: Weird (0x9)]");
    expect(odd.events[0].description).not.toContain("Weird (0x9) —");
  });
});

describe("image facts carry onto the rows of the same upload", () => {
  const malfind = () => [
    {
      __children: [],
      PID: 3120,
      Process: "evil.exe",
      "Start VPN": "0x400000",
      "End VPN": "0x401fff",
      Tag: "VadS",
      Protection: "PAGE_EXECUTE_READWRITE",
      CommitCharge: 1,
      PrivateMemory: 1,
      "File output": "Disabled",
      Notes: "MZ header",
      Hexdump: "",
      Disasm: "",
    },
  ];
  const pslist = () => [
    {
      __children: [],
      PID: 4,
      PPID: 0,
      ImageFileName: "System",
      Offset: "0x1",
      Threads: 1,
      Handles: 1,
      SessionId: "N/A",
      Wow64: false,
      CreateTime: "2012-07-22T02:42:31+00:00",
      ExitTime: null,
    },
  ];
  it("a High row gets the suffix and the envelope; an Info row the envelope only", () => {
    const r = parseMemory(
      JSON.stringify({
        "windows.info.Info": infoJson(),
        "windows.malfind.Malfind": malfind(),
        "windows.pslist.PsList": pslist(),
      }),
      { minSeverity: "Info" },
    );
    const high = r.events.find((e) => e.severity === "High");
    const info = r.events.find((e) => /System \(PID 4/.test(e.description));
    expect(high?.description).toContain("[image: kernel SystemTime 2012-07-22T02:45:08.000Z]");
    // only process rows carry a canonical envelope today; the facts ride on it where it exists
    expect(info?.description).not.toContain("[image:");
    expect(info?.canonical?.image).toMatchObject({
      systemTime: "2012-07-22T02:45:08.000Z",
      layers: ["primary: 0 WindowsIntel32e", "memory_layer: 1 FileLayer"],
    });
    expect(info?.canonical?.image?.dumpKind).toBeUndefined(); // FileLayer alone establishes no format
  });
  it("a crash header alone labels the carried time as the dump header's; with windows.info both merge", () => {
    const crashOnly = parseMemory(
      JSON.stringify({ "windows.crashinfo.Crashinfo": CRASH, "windows.malfind.Malfind": malfind() }),
    );
    const high = crashOnly.events.find((e) => e.severity === "High");
    expect(high?.description).toContain("[image: dump-header SystemTime 2012-07-22T02:45:08.000Z]");
    expect(high?.description).not.toContain("kernel SystemTime");
    const both = parseMemory(
      JSON.stringify({
        "windows.info.Info": infoJson({ SystemTime: "2012-07-22T02:45:00+00:00" }),
        "windows.crashinfo.Crashinfo": CRASH,
        "windows.pslist.PsList": pslist(),
      }),
      { minSeverity: "Info" },
    );
    const row = both.events.find((e) => /System \(PID 4/.test(e.description));
    expect(row?.canonical?.image).toMatchObject({
      systemTime: "2012-07-22T02:45:00.000Z", // windows.info's, not the header's
      dumpType: "Bitmap Dump (0x5)", // the header's, merged in
    });
  });
  it("a table is windows.info by its own fields, never by a label or a two-column shape", () => {
    const fake = [
      { __children: [], Variable: "SystemTime", Value: "2012-07-22T02:45:08+00:00" },
      { __children: [], Variable: "note", Value: "hello" },
    ];
    const r = parseMemory(
      JSON.stringify({ "windows.info.Info": fake, "windows.malfind.Malfind": malfind() }),
    );
    expect(r.events.some((e) => e.description.startsWith("Memory image"))).toBe(false);
    expect(r.events.find((e) => e.severity === "High")?.description).not.toContain("[image:");
    const lone = parseMemory(
      JSON.stringify({ "windows.foo.Foo": [{ __children: [], DumpType: "Bitmap Dump (0x5)", X: 1 }] }),
    );
    expect(lone.events.some((e) => e.description.startsWith("Memory image"))).toBe(false);
  });
  it("a placeholder establishes nothing: no bitness, no symbols, no time from '-' or N/A", () => {
    const r = parseMemory(
      JSON.stringify(infoJson({ Is64Bit: "N/A", Symbols: "-", SystemTime: "-", "Kernel Base": "N/A" })),
      { filename: "windows.info.json" },
    );
    const d = r.events[0].description;
    expect(d).not.toMatch(/\[(?:32|64)-bit\]|\[symbols:|\[kernel base/);
    expect(d).toContain("[kernel SystemTime: not readable — ]");
  });
  it("a long layer stack keeps whole tags and marks the row", () => {
    const over: Record<string, string> = {};
    for (let i = 0; i < 40; i++) over[`layer_${i}_${"x".repeat(20)}`] = `${i} FileLayer`;
    const r = parseMemory(JSON.stringify(infoJson(over)), { filename: "windows.info.json" });
    const d = r.events[0].description;
    expect(d.length).toBeLessThanOrEqual(600);
    expect((d.match(/\[/g) ?? []).length).toBe((d.match(/\]/g) ?? []).length);
    expect(d).toMatch(/ #[A-Za-z0-9_-]{22}$/);
  });
  it("readImageFacts finds nothing in an upload without an info table", () => {
    expect(readImageFacts([{ plugin: "windows.pslist", rows: pslist() }])).toBeNull();
  });
});
