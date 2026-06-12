import { describe, it, expect } from "vitest";
import { parseMemory, isRekallCommandList } from "../../src/analysis/memoryImport.js";

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
