import { describe, it, expect } from "vitest";
import { parseMemory, isRekallCommandList, looksLikeVolatilityText, looksLikeMemprocfsFindevil } from "../../src/analysis/memoryImport.js";

// ── Volatility 3 JSON-renderer fixtures (each node carries `__children`) ──────
function pslist(): object[] {
  return [
    { __children: [], PID: 4, PPID: 0, ImageFileName: "System", Threads: 129, CreateTime: "2021-04-29 21:26:48.000000", ExitTime: null },
    { __children: [], PID: 880, PPID: 4, ImageFileName: "smss.exe", CreateTime: "2021-04-29 21:26:48.000000", ExitTime: null },
    { __children: [], PID: 3120, PPID: 880, ImageFileName: "evil.exe", CreateTime: "2021-04-29 21:40:00.000000", ExitTime: null },
  ];
}
function netscan(): object[] {
  return [
    { __children: [], Offset: 1, Proto: "TCPv4", LocalAddr: "10.0.0.5", LocalPort: 50122, ForeignAddr: "203.0.113.50", ForeignPort: 443, State: "ESTABLISHED", PID: 3120, Owner: "evil.exe", Created: "2021-04-29 21:41:00.000000" },
    { __children: [], Offset: 2, Proto: "TCPv4", LocalAddr: "0.0.0.0", LocalPort: 445, ForeignAddr: "0.0.0.0", ForeignPort: 0, State: "LISTENING", PID: 4, Owner: "System", Created: "N/A" },
  ];
}
function malfind(): object[] {
  return [
    { __children: [], PID: 3120, Process: "evil.exe", "Start VPN": "0x2000000", "End VPN": "0x2003fff", Tag: "VadS", Protection: "PAGE_EXECUTE_READWRITE", CommitCharge: 1, PrivateMemory: 1, Hexdump: "MZ......", Disasm: "push rbp" },
  ];
}
function cmdline(): object[] {
  return [
    { __children: [], PID: 3120, Process: "powershell.exe", Args: "powershell.exe -nop -w hidden -enc SQBFAFgA" },
    { __children: [], PID: 600, Process: "svchost.exe", Args: "C:\\Windows\\system32\\svchost.exe -k netsvcs" },
  ];
}

describe("parseMemory — Volatility 3 pslist", () => {
  it("maps each process to an Info evidence event with parent links, time, and a process IOC", () => {
    const r = parseMemory(JSON.stringify(pslist()), { filename: "windows.pslist.json" });
    expect(r.format).toBe("volatility");
    expect(r.tool).toBe("Volatility");
    expect(r.processes).toBe(3);

    const evil = r.events.find((e) => e.description.includes("evil.exe"));
    expect(evil?.severity).toBe("Info");
    expect(evil?.processName).toBe("evil.exe");
    expect(evil?.parentName).toBe("smss.exe");                  // PPID 880 → smss.exe
    expect(evil?.timestamp).toBe("2021-04-29T21:40:00.000000Z");
    expect(evil?.sources).toContain("Volatility");
    expect(r.iocs.some((i) => i.type === "process" && i.value === "evil.exe")).toBe(true);
  });
});

describe("parseMemory — Volatility 3 netscan", () => {
  it("maps connections, harvests the foreign IP, and grades an external ESTABLISHED conn Low", () => {
    const r = parseMemory(JSON.stringify(netscan()), { filename: "netscan.json" });
    const conn = r.events.find((e) => e.description.includes("203.0.113.50"));
    expect(conn?.severity).toBe("Low");                          // external + ESTABLISHED
    expect(conn?.dstIp).toBe("203.0.113.50");
    expect(conn?.srcIp).toBe("10.0.0.5");
    expect(conn?.port).toBe(443);
    expect(conn?.processName).toBe("evil.exe");
    expect(r.iocs.some((i) => i.type === "ip" && i.value === "203.0.113.50")).toBe(true);
    // 0.0.0.0 listener → no IP IOC, Info severity.
    expect(r.iocs.some((i) => i.type === "ip" && i.value === "0.0.0.0")).toBe(false);
    const listen = r.events.find((e) => e.description.includes("LISTENING"));
    expect(listen?.severity).toBe("Info");
  });
});

describe("parseMemory — Volatility 3 malfind", () => {
  it("flags injected/executable private memory as High with ATT&CK T1055", () => {
    const r = parseMemory(JSON.stringify(malfind()), { filename: "malfind.json" });
    expect(r.injected).toBe(1);
    const inj = r.events[0];
    expect(inj.severity).toBe("High");
    expect(inj.mitreTechniques).toContain("T1055");
    expect(inj.processName).toBe("evil.exe");
    expect(inj.description).toContain("PAGE_EXECUTE_READWRITE");
  });
});

describe("parseMemory — Volatility 3 cmdline", () => {
  it("bumps a suspicious (encoded/hidden) command line and leaves a benign one Info", () => {
    const r = parseMemory(JSON.stringify(cmdline()), { filename: "cmdline.json" });
    const ps = r.events.find((e) => e.description.includes("powershell.exe"));
    expect(ps?.severity).toBe("Medium");                         // -enc / -w hidden = weak tradecraft
    expect(ps?.mitreTechniques).toContain("T1059");
    const svc = r.events.find((e) => e.description.includes("svchost.exe"));
    expect(svc?.severity).toBe("Info");
  });
});

describe("parseMemory — Volatility 3 pstree (nested __children)", () => {
  it("resolves parent names from the tree structure", () => {
    const tree = [
      {
        __children: [
          {
            __children: [
              { __children: [], PID: 3120, PPID: 2044, ImageFileName: "evil.exe", CreateTime: "2021-04-29 21:40:00.000000" },
            ],
            PID: 2044, PPID: 880, ImageFileName: "explorer.exe", CreateTime: "2021-04-29 21:30:00.000000",
          },
        ],
        PID: 880, PPID: 4, ImageFileName: "smss.exe", CreateTime: "2021-04-29 21:26:48.000000",
      },
    ];
    const r = parseMemory(JSON.stringify(tree), { filename: "windows.pstree.json" });
    expect(r.processes).toBeGreaterThanOrEqual(1);
    const evil = r.events.find((e) => e.description.includes("evil.exe"));
    expect(evil?.parentName).toBe("explorer.exe");               // from the tree, not just PPID
  });
});

describe("parseMemory — combined plugin map + jsonl", () => {
  it("parses a { plugin: rows } map into multiple tables", () => {
    const map = { "windows.pslist.PsList": pslist(), "windows.netscan.NetScan": netscan() };
    const r = parseMemory(JSON.stringify(map));
    expect(r.format).toBe("volatility-map");
    expect(r.tables).toBe(2);
    expect(r.events.some((e) => e.description.includes("evil.exe"))).toBe(true);
    expect(r.events.some((e) => e.description.includes("203.0.113.50"))).toBe(true);
  });
  it("parses a JSON-Lines (one row per line) Volatility export", () => {
    const jsonl = pslist().map((o) => JSON.stringify(o)).join("\n");
    const r = parseMemory(jsonl, { filename: "pslist.jsonl" });
    expect(r.format).toBe("volatility-jsonl");
    expect(r.processes).toBe(3);
  });
});

describe("parseMemory — Rekall JSON statement list", () => {
  it("walks [m/t/r] statements, classifies pslist, and resolves the _EPROCESS name + pid", () => {
    const rekall = [
      ["m", { tool_name: "rekall", plugin: { name: "pslist" } }],
      ["t", [{ cname: "_EPROCESS", name: "Offset" }, { cname: "ppid", name: "PPID" }], {}],
      ["r", { _EPROCESS: { id: 1, type: "_EPROCESS", name: "System", Cybox: { Name: "System", PID: 4 } }, ppid: 0, process_create_time: { epoch: 1619731608 } }],
      ["r", { _EPROCESS: { name: "evil.exe", Cybox: { PID: 3120 } }, ppid: 2044, process_create_time: { epoch: 1619732400 } }],
    ];
    const r = parseMemory(JSON.stringify(rekall));
    expect(r.format).toBe("rekall");
    expect(r.tool).toBe("Rekall");
    const evil = r.events.find((e) => e.description.includes("evil.exe"));
    expect(evil).toBeTruthy();
    expect(evil?.processName).toBe("evil.exe");
    expect(evil?.sources).toContain("Rekall");
    expect(r.iocs.some((i) => i.type === "process" && i.value === "evil.exe")).toBe(true);
  });

  it("isRekallCommandList recognises the statement list and rejects a plain array of rows", () => {
    expect(isRekallCommandList([["m", {}], ["r", { a: 1 }]])).toBe(true);
    expect(isRekallCommandList(pslist())).toBe(false);
    expect(isRekallCommandList({})).toBe(false);
  });
});

describe("parseMemory — options & edges", () => {
  it("applies a severity floor (keeps malfind High, drops Info process rows)", () => {
    const combined = { "windows.malfind.Malfind": malfind(), "windows.pslist.PsList": pslist() };
    const r = parseMemory(JSON.stringify(combined), { minSeverity: "High" });
    expect(r.events.length).toBeGreaterThan(0);
    expect(r.events.every((e) => e.severity === "High")).toBe(true);
  });

  it("harvests dll paths as IOCs but emits no events by default (opt-in via dllTelemetry)", () => {
    const dlls = [
      { __children: [], PID: 3120, Process: "evil.exe", Base: "0x100000", Size: 4096, Name: "evil.dll", Path: "C:\\Temp\\evil.dll", LoadTime: "N/A" },
    ];
    const noTel = parseMemory(JSON.stringify({ "windows.dlllist.DllList": dlls }));
    expect(noTel.events.length).toBe(0);
    expect(noTel.iocs.some((i) => i.type === "file" && /evil\.dll/i.test(i.value))).toBe(true);
    const tel = parseMemory(JSON.stringify({ "windows.dlllist.DllList": dlls }), { dllTelemetry: true });
    expect(tel.events.length).toBe(1);
  });

  it("reports empty for non-memory JSON", () => {
    const r = parseMemory(JSON.stringify({ foo: "bar" }));
    expect(r.events.length).toBe(0);
    expect(r.iocs.length).toBe(0);
  });
});

describe("parseMemory — Volatility 3 TEXT/grid renderer (default `vol`, no -r json)", () => {
  // A real-shaped malfind text export: banner, TAB-separated header, two rows each followed by a
  // hexdump block and a disassembly block (which must be skipped, not parsed as rows).
  const malfindText = [
    "Volatility 3 Framework 2.28.0",
    "",
    "PID\tProcess\tStart VPN\tEnd VPN\tTag\tProtection\tCommitCharge\tPrivateMemory\tFile output\tNotes\tHexdump\tDisasm",
    "",
    "7352\tSearchHost.exe\t0x1e1901d0000\t0x1e1901effff\tVadS\tPAGE_EXECUTE_READWRITE\t5\t1\tDisabled\tN/A\t",
    "48 89 54 24 10 48 89 4c 24 08 4c 89 44 24 18 4c H.T$.H.L$.L.D$.L",
    "89 4c 24 20 48 8b 41 28 48 8b 48 08 48 8b 51 50 .L$ H.A(H.H.H.QP",
    "0x1e1901d0000:\tmov\tqword ptr [rsp + 0x10], rdx",
    "0x1e1901d0005:\tmov\tqword ptr [rsp + 8], rcx",
    "6900\tpowershell.exe\t0x2ea5f970000\t0x2ea5f97cfff\tVadS\tPAGE_EXECUTE_READWRITE\t1\t1\tDisabled\tN/A\t",
    "00 00 00 00 00 00 00 00 90 78 9b 5f ea 02 00 00 .........x._....",
    "0x2ea5f970000:\tadd\tbyte ptr [rax], al",
  ].join("\n");

  it("looksLikeVolatilityText recognises the banner and a known-column header (and rejects plain text)", () => {
    expect(looksLikeVolatilityText(malfindText)).toBe(true);
    expect(looksLikeVolatilityText("PID\tProcess\tProtection\tTag\tStart VPN\n7352\tx\tRWX\tVadS\t0x1")).toBe(true); // no banner, header cols
    expect(looksLikeVolatilityText("just some\nlog lines\nwith no tabs")).toBe(false);
  });

  it("parses the grid into malfind events, skipping the hexdump + disasm continuation lines", () => {
    const r = parseMemory(malfindText, { filename: "malfind.txt" });
    expect(r.format).toBe("volatility-text");
    expect(r.tool).toBe("Volatility");
    expect(r.injected).toBe(2);                                  // two data rows, not the hexdump/disasm lines
    expect(r.events).toHaveLength(2);
    expect(r.events.every((e) => e.severity === "High")).toBe(true);
    expect(r.events.every((e) => e.mitreTechniques.includes("T1055"))).toBe(true);
    const sh = r.events.find((e) => e.description.includes("SearchHost.exe"));
    expect(sh?.processName).toBe("SearchHost.exe");
    expect(sh?.description).toContain("PAGE_EXECUTE_READWRITE");
    expect(r.iocs.some((i) => i.type === "process" && i.value === "SearchHost.exe")).toBe(true);
  });

  it("parses a tab-separated pslist text grid with parent links", () => {
    const pslistText = [
      "Volatility 3 Framework 2.28.0",
      "PID\tPPID\tImageFileName\tCreateTime",
      "880\t4\tsmss.exe\t2021-04-29 21:26:48.000000",
      "3120\t880\tevil.exe\t2021-04-29 21:40:00.000000",
    ].join("\n");
    const r = parseMemory(pslistText, { filename: "windows.pslist.txt" });
    expect(r.format).toBe("volatility-text");
    expect(r.processes).toBe(2);
    const evil = r.events.find((e) => e.description.includes("evil.exe"));
    expect(evil?.parentName).toBe("smss.exe");                   // PPID 880 → smss.exe
    expect(evil?.processName).toBe("evil.exe");
  });
});

// ── MemProcFS findevil ──────────────────────────────────────────────────────

const FINDEVIL_SAMPLE = [
  "   #    PID Process        Type            Address          Description",
  "-----------------------------------------------------------------------",
  "0000   8684 Velociraptor.e HIGH_ENTROPY    000000c001c00000 Entropy:[8.00]       p-rw-- ",
  "0001   3080 elastic-agent. PEB_MASQ        0000000000000000 ",
  "0002      4 System         DRIVER_PATH     ffff848b42043b00 Driver:[winpmem] Module:[\\??\\C:\\Windows\\Temp\\winpmem.sys]",
  "0004   6416 svchost.exe    YR_HACKTOOL     0000022a7a0b804e Windows_Hacktool_SharpDump_7c17d8b1 [0]",
  "0005   6416 svchost.exe    YR_HACKTOOL     0000022a7a0b8341 Windows_Hacktool_SharpMove_05e28928 [1]",
  "000e   4152 taskhostw.exe  THREAD          00007ff824bb6870 TID:5756 SYSTEM_IMPERSONATION",
  "0013   6364 explorer.exe   PE_NOLINK       00007ff800bb0000 Module:[SearchIndexerCore.dll] VAD:[\\Windows\\System32\\SearchIndexerCore.dll]",
  "0019   1004 chrome.exe     PE_PATCHED      00007ff824c43000 00003161f000 010000003161f025 A r-x Image ---wxc \\Windows\\System32\\ntdll.dll",
  "0027   1004 chrome.exe     PRIVATE_RWX     00007fffc3b80000 0001ffcb2000 01000001ffcb2867 A rwx p----- ",
  "0028   1004 chrome.exe     PRIVATE_RWX     00007fffc3b81000 0001ff7b4000 01000001ff7b4847 A rwx p----- ",
  "000b   6900 powershell.exe PROC_DEBUG      0000000000000000 ",
].join("\n");

describe("parseMemory — MemProcFS findevil", () => {
  it("looksLikeMemprocfsFindevil detects the header+data pattern and rejects plain text", () => {
    expect(looksLikeMemprocfsFindevil(FINDEVIL_SAMPLE)).toBe(true);
    expect(looksLikeMemprocfsFindevil("just some log lines\nwith no structure")).toBe(false);
    expect(looksLikeMemprocfsFindevil("Volatility 3 Framework 2.28.0\nPID\tProcess\n4\tSystem")).toBe(false);
  });

  it("produces format=memprocfs-findevil and tool=MemProcFS", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    expect(r.format).toBe("memprocfs-findevil");
    expect(r.tool).toBe("MemProcFS");
    expect(r.total).toBeGreaterThan(0);
  });

  it("maps YR_HACKTOOL to Critical with T1588.002 and includes the YARA rule name", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    const sd = r.events.find((e) => e.description.includes("SharpDump"));
    expect(sd?.severity).toBe("Critical");
    expect(sd?.mitreTechniques).toContain("T1588.002");
    expect(sd?.processName).toBe("svchost.exe");
    // Two different hacktools → two separate events (not aggregated together)
    const sm = r.events.find((e) => e.description.includes("SharpMove"));
    expect(sm).toBeTruthy();
  });

  it("maps THREAD with SYSTEM_IMPERSONATION to High with T1134", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    const ev = r.events.find((e) => e.description.includes("taskhostw.exe") && e.description.includes("SYSTEM_IMPERSONATION"));
    expect(ev?.severity).toBe("High");
    expect(ev?.mitreTechniques).toContain("T1134");
  });

  it("maps PEB_MASQ to High with T1036.005", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    const ev = r.events.find((e) => e.description.includes("PEB_MASQ"));
    expect(ev?.severity).toBe("High");
    expect(ev?.mitreTechniques).toContain("T1036.005");
    expect(ev?.processName).toBe("elastic-agent.");
  });

  it("maps DRIVER_PATH to Low (or Medium for suspicious paths) and harvests the module as a file IOC", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    const ev = r.events.find((e) => e.description.includes("winpmem"));
    // Temp path → suspicious → Medium
    expect(ev?.severity).toBe("Medium");
    expect(ev?.mitreTechniques).toContain("T1014");
    expect(r.iocs.some((i) => i.type === "file" && /winpmem\.sys/i.test(i.value))).toBe(true);
  });

  it("maps PE_NOLINK to Medium with T1055 and harvests the VAD path as a file IOC", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    const ev = r.events.find((e) => e.description.includes("SearchIndexerCore"));
    expect(ev?.severity).toBe("Medium");
    expect(ev?.mitreTechniques).toContain("T1055");
    expect(r.iocs.some((i) => i.type === "file" && /SearchIndexerCore/i.test(i.value))).toBe(true);
  });

  it("maps PE_PATCHED to High with T1055 and harvests the patched DLL path as a file IOC", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    const ev = r.events.find((e) => e.description.includes("PE_PATCHED") && e.description.includes("ntdll.dll"));
    expect(ev?.severity).toBe("High");
    expect(ev?.mitreTechniques).toContain("T1055");
    expect(r.iocs.some((i) => i.type === "file" && /ntdll\.dll/i.test(i.value))).toBe(true);
  });

  it("groups multiple PRIVATE_RWX rows from the same process into one event (count reflects all pages)", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    const chromePrwx = r.events.filter(
      (e) => e.description.includes("chrome.exe") && e.description.includes("PRIVATE_RWX"),
    );
    // Two PRIVATE_RWX rows from chrome.exe PID 1004 → aggregated into one event
    expect(chromePrwx).toHaveLength(1);
    expect((chromePrwx[0].count ?? 1)).toBe(2);
    expect(chromePrwx[0].severity).toBe("Medium");
  });

  it("maps HIGH_ENTROPY to Medium and PROC_DEBUG to Medium", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    const he = r.events.find((e) => e.description.includes("HIGH_ENTROPY"));
    expect(he?.severity).toBe("Medium");
    expect(he?.mitreTechniques).toContain("T1027");
    const pd = r.events.find((e) => e.description.includes("PROC_DEBUG"));
    expect(pd?.severity).toBe("Medium");
  });

  it("tags all events with sources=[MemProcFS]", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    expect(r.events.every((e) => e.sources?.includes("MemProcFS"))).toBe(true);
  });

  it("reports injected count = number of YR_* rows", () => {
    const r = parseMemory(FINDEVIL_SAMPLE);
    expect(r.injected).toBe(2);                                  // two YR_HACKTOOL rows
  });
});

// ── MemProcFS findevil.csv ──────────────────────────────────────────────────

const FINDEVIL_CSV = [
  "PID,ProcessName,Type,Address,Description",
  '4,System,DRIVER_PATH,0xffff848b42043b00,"Driver:[winpmem] Module:[\\??\\C:\\Windows\\Temp\\winpmem.sys]"',
  '6416,svchost.exe,YR_HACKTOOL,0x22a7a0b804e,"Windows_Hacktool_SharpDump_7c17d8b1 [0]"',
  '6416,svchost.exe,YR_HACKTOOL,0x22a7a0b8341,"Windows_Hacktool_SharpMove_05e28928 [1]"',
  '4152,taskhostw.exe,THREAD,0x7ff824bb6870,"TID:5756 SYSTEM_IMPERSONATION"',
  '6364,explorer.exe,PE_NOLINK,0x7ff800bb0000,"Module:[SearchIndexerCore.dll] VAD:[\\Windows\\System32\\SearchIndexerCore.dll]"',
  '1004,chrome.exe,PRIVATE_RWX,0x7fffc3b80000,"..."',
  '1004,chrome.exe,PRIVATE_RWX,0x7fffc3b81000,"..."',
  '6900,powershell.exe,PROC_DEBUG,0x0,""',
].join("\n");

describe("parseMemory — MemProcFS findevil CSV", () => {
  it("produces format=memprocfs-findevil-csv and tool=MemProcFS", () => {
    const r = parseMemory(FINDEVIL_CSV);
    expect(r.format).toBe("memprocfs-findevil-csv");
    expect(r.tool).toBe("MemProcFS");
    expect(r.total).toBe(8);
  });

  it("maps YR_HACKTOOL rows to Critical/T1588.002 (same logic as text format)", () => {
    const r = parseMemory(FINDEVIL_CSV);
    const sd = r.events.find((e) => e.description.includes("SharpDump"));
    expect(sd?.severity).toBe("Critical");
    expect(sd?.mitreTechniques).toContain("T1588.002");
  });

  it("maps THREAD SYSTEM_IMPERSONATION to High/T1134", () => {
    const r = parseMemory(FINDEVIL_CSV);
    const ev = r.events.find((e) => e.description.includes("SYSTEM_IMPERSONATION"));
    expect(ev?.severity).toBe("High");
    expect(ev?.mitreTechniques).toContain("T1134");
  });

  it("groups PRIVATE_RWX rows from the same chrome.exe PID into one event", () => {
    const r = parseMemory(FINDEVIL_CSV);
    const chromePrwx = r.events.filter(
      (e) => e.description.includes("chrome.exe") && e.description.includes("PRIVATE_RWX"),
    );
    expect(chromePrwx).toHaveLength(1);
    expect((chromePrwx[0].count ?? 1)).toBe(2);
  });

  it("harvests the winpmem driver path as a file IOC (Medium for Temp path)", () => {
    const r = parseMemory(FINDEVIL_CSV);
    expect(r.iocs.some((i) => i.type === "file" && /winpmem\.sys/i.test(i.value))).toBe(true);
    const driverEv = r.events.find((e) => e.description.includes("winpmem"));
    expect(driverEv?.severity).toBe("Medium");
  });

  it("reports injected count = YR_* rows only", () => {
    const r = parseMemory(FINDEVIL_CSV);
    expect(r.injected).toBe(2);
  });
});

// ── MemProcFS yara.csv ──────────────────────────────────────────────────────

const YARA_CSV = [
  "MatchIndex,Tags,Description,RuleAuthor,RuleVersion,MemoryType,MemoryTag,MemoryBaseAddress,ObjectAddress,PID,ProcessName,ProcessPath,CommandLine,User,Created,AddressCount,String0,Address0",
  '0,"","","Elastic Security","","Virtual Memory (VAD)","HEAP-00 [SegSegment]",22a7a000000,"",6416,svchost.exe,\\Device\\HarddiskVolume1\\Windows\\System32\\svchost.exe,"C:\\Windows\\system32\\svchost.exe -k osprivacy -p -s camsvc",SYSTEM,"2026-06-03 08:31:44",1,9c9bba3-a0ea-431c-866c-77004802d,22a7a0b804e',
  '1,"","","Elastic Security","","Virtual Memory (VAD)","HEAP-00 [SegSegment]",22a7a000000,"",6416,svchost.exe,\\Device\\HarddiskVolume1\\Windows\\System32\\svchost.exe,"C:\\Windows\\system32\\svchost.exe -k osprivacy -p -s camsvc",SYSTEM,"2026-06-03 08:31:44",1,8BF82BBE-909C-4777-A2FC-EA7C070FF43E,22a7a0b8341',
].join("\n");

describe("parseMemory — MemProcFS yara.csv", () => {
  it("produces format=memprocfs-yara-csv and tool=MemProcFS", () => {
    const r = parseMemory(YARA_CSV);
    expect(r.format).toBe("memprocfs-yara-csv");
    expect(r.tool).toBe("MemProcFS");
    expect(r.total).toBe(2);
  });

  it("maps every row to Critical/T1055 with process and memory context in the description", () => {
    const r = parseMemory(YARA_CSV);
    expect(r.events.length).toBeGreaterThan(0);
    expect(r.events.every((e) => e.severity === "Critical")).toBe(true);
    expect(r.events.every((e) => e.mitreTechniques?.includes("T1055"))).toBe(true);
    expect(r.events.some((e) => e.description.includes("svchost.exe"))).toBe(true);
    expect(r.events.some((e) => e.description.includes("Virtual Memory (VAD)"))).toBe(true);
  });

  it("aggregates matches from the same process+base-address into one event with count", () => {
    const r = parseMemory(YARA_CSV);
    // Both rows are svchost PID 6416, same MemoryBaseAddress 22a7a000000 → one event, count 2
    expect(r.events).toHaveLength(1);
    expect((r.events[0].count ?? 1)).toBe(2);
    expect(r.events[0].processName).toBe("svchost.exe");
  });

  it("preserves the Created timestamp from the CSV row", () => {
    const r = parseMemory(YARA_CSV);
    expect(r.events[0].timestamp).toBeTruthy();
    expect(r.events[0].timestamp).toContain("2026-06-03");
  });

  it("harvests the process path as a file IOC", () => {
    const r = parseMemory(YARA_CSV);
    expect(r.iocs.some((i) => i.type === "file" && /svchost\.exe/i.test(i.value))).toBe(true);
  });

  it("reports injected = total rows (all are YARA hits)", () => {
    const r = parseMemory(YARA_CSV);
    expect(r.injected).toBe(2);
  });
});

// ─── MemProcFS timeline_all.csv ──────────────────────────────────────────────

const TIMELINE_HEADER = "Time,Type,Action,PID,Value32,Value64,Text,Pad";
const TS = "2026-06-03 08:57:15";

function timelineRow(type: string, action: string, pid: string, text: string, ts = TS): string {
  return `"${ts}",${type},${action},${pid},0x0,0x0,"${text}","  "`;
}

describe("parseMemory — MemProcFS timeline_all.csv", () => {
  it("is detected as memprocfs-timeline format", () => {
    const csv = [TIMELINE_HEADER, timelineRow("NTFS", "MOD", "0", "\\1\\Windows\\foo.etl")].join("\n");
    const r = parseMemory(csv);
    expect(r.format).toBe("memprocfs-timeline");
    expect(r.tool).toBe("MemProcFS");
  });

  it("PROC CRE → Info event tagged sources=[MemProcFS] with process IOC + file IOC", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("PROC", "CRE", "1868", "svchost.exe [*SYSTEM] \\Device\\HarddiskVolume1\\Windows\\System32\\svchost.exe"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events).toHaveLength(1);
    const ev = r.events[0];
    expect(ev.severity).toBe("Info");
    expect(ev.description).toContain("svchost.exe");
    expect(ev.description).toContain("start");
    expect(ev.sources).toContain("MemProcFS");
    expect(r.iocs.some((i) => i.type === "process" && i.value === "svchost.exe")).toBe(true);
    expect(r.iocs.some((i) => i.type === "file" && /svchost\.exe/i.test(i.value))).toBe(true);
  });

  it("PROC DEL → Info event with 'exit' in description", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("PROC", "DEL", "1796", "sppsvc.exe [*] \\Device\\HarddiskVolume1\\Windows\\System32\\sppsvc.exe"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events[0].description).toContain("exit");
  });

  it("ShTask CRE → Medium severity / T1053.005", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("ShTask", "CRE", "0", "Backdoor - [C:\\Users\\evil.exe :: -persist] (SYSTEM)"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events).toHaveLength(1);
    const ev = r.events[0];
    expect(ev.severity).toBe("Medium");
    expect(ev.mitreTechniques).toContain("T1053.005");
    expect(ev.description).toContain("created");
    expect(ev.description).toContain("Backdoor");
  });

  it("ShTask DEL → Medium severity / T1070", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("ShTask", "DEL", "0", "CleanupTask - [cmd.exe :: /c del /q] (SYSTEM)"),
    ].join("\n");
    const r = parseMemory(csv);
    const ev = r.events[0];
    expect(ev.severity).toBe("Medium");
    expect(ev.mitreTechniques).toContain("T1070");
    expect(ev.description).toContain("deleted");
  });

  it("ShTask MOD → Low severity / T1053.005", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("ShTask", "MOD", "0", "SvcRestartTask - [Custom Handler :: timer] (NetworkService)"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events[0].severity).toBe("Low");
    expect(r.events[0].mitreTechniques).toContain("T1053.005");
  });

  it("Net TCPv4 with real remote → Low event + network IOC", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("Net", "CRE", "3548", "TCPv4  SYN_SENT     192.168.195.154:53145         192.168.56.51:1514          "),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events.length).toBeGreaterThan(0);
    const ev = r.events[0];
    expect(ev.severity).toBe("Low");
    expect(ev.mitreTechniques).toContain("T1071");
    expect(ev.description).toContain("192.168.56.51");
    expect(r.iocs.some((i) => i.type === "network" && i.value === "192.168.56.51")).toBe(true);
  });

  it("Net UDPv6 with *** remote → no event, no IOC", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("Net", "CRE", "2232", "UDPv6  ***          [::]:0                        ***                         "),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events).toHaveLength(0);
    expect(r.iocs).toHaveLength(0);
  });

  it("WEB VISIT → Info event / T1217 + URL IOC + domain IOC", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("WEB", "CRE", "7908", "browser:[CHROME] type:[VISIT] url:[https://github.com/hasamba] info:[hasamba · GitHub]"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events).toHaveLength(1);
    const ev = r.events[0];
    expect(ev.severity).toBe("Info");
    expect(ev.mitreTechniques).toContain("T1217");
    expect(ev.description).toContain("github.com");
    expect(r.iocs.some((i) => i.type === "url")).toBe(true);
    expect(r.iocs.some((i) => i.type === "domain" && i.value === "github.com")).toBe(true);
  });

  it("WEB DOWNLOAD → Low event / T1105", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("WEB", "CRE", "7908", "browser:[CHROME] type:[DOWNLOAD] url:[https://evil.com/payload.exe] info:[]"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events[0].severity).toBe("Low");
    expect(r.events[0].mitreTechniques).toContain("T1105");
  });

  it("NTFS CRE with exec extension → file IOC, no event", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("NTFS", "CRE", "0", "\\1\\Users\\Public\\evil.exe"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events).toHaveLength(0);
    expect(r.iocs.some((i) => i.type === "file" && /evil\.exe/i.test(i.value))).toBe(true);
  });

  it("NTFS MOD → no event, no IOC", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("NTFS", "MOD", "0", "\\1\\Windows\\System32\\LogFiles\\WMI\\foo.etl"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events).toHaveLength(0);
    expect(r.iocs).toHaveLength(0);
  });

  it("REG and THREAD rows are dropped", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("REG", "MOD", "0", "HKLM\\SYSTEM\\CurrentControlSet\\Services"),
      timelineRow("THREAD", "CRE", "372", "TID: 5740"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events).toHaveLength(0);
    expect(r.iocs).toHaveLength(0);
  });

  it("preserves the Time column timestamp on events", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("ShTask", "CRE", "0", "EvilTask - [evil.exe :: -x]", "2026-06-03 09:30:00"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.events[0].timestamp).toContain("2026-06-03");
  });

  it("total = total rows in file", () => {
    const csv = [
      TIMELINE_HEADER,
      timelineRow("PROC",   "CRE", "100", "calc.exe [] \\Device\\HarddiskVolume1\\Windows\\calc.exe"),
      timelineRow("REG",    "MOD", "0",   "HKLM\\foo"),
      timelineRow("THREAD", "CRE", "200", "TID: 1"),
    ].join("\n");
    const r = parseMemory(csv);
    expect(r.total).toBe(3);
  });
});
