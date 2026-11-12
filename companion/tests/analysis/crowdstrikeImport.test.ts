import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  parseCrowdstrikeExport,
  isCrowdstrikeRecord,
  crowdstrikeCsvSig,
  CROWDSTRIKE_SOURCE,
} from "../../src/analysis/crowdstrikeImport.js";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import { parseLoginEvent } from "../../src/analysis/loginGraph.js";
import { familyOfEvent } from "../../src/analysis/caseMainSource.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Synthetic Falcon sensor rows (#2592). Hosts WS-01/WS-02, domains under example.com, documentation
// IP ranges — no real case data.
type Row = Record<string, unknown>;

function ev(name: string, extra: Row = {}): Row {
  return {
    "#event_simpleName": name,
    aid: "0123456789abcdef0123456789abcdef",
    ComputerName: "WS-01",
    timestamp: "1731400000000",
    ContextTimeStamp: "1731399999.456",
    ...extra,
  };
}
const ndjson = (...rows: Row[]): string => rows.map((r) => JSON.stringify(r)).join("\n");
const parse = (...rows: Row[]) => parseCrowdstrikeExport(ndjson(...rows));
type Parsed = ReturnType<typeof parse>;
const iocValues = (r: Parsed, type: string) => r.iocs.filter((i) => i.type === type).map((i) => i.value);

function asEvent(e: Parsed["events"][number]): ForensicEvent {
  return {
    ...e,
    id: "e1",
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: e.mitreTechniques ?? [],
  };
}

const PROC = {
  ImageFileName: "\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe",
  CommandLine: "notepad.exe C:\\Users\\alice\\notes.txt",
  ParentBaseFileName: "explorer.exe",
  RawProcessId: "4242",
  TargetProcessId: "123456789012",
  SHA256HashData: "a".repeat(64),
  MD5HashData: "b".repeat(32),
};
const ENCODED = "powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AA==";

describe("isCrowdstrikeRecord / crowdstrikeCsvSig", () => {
  it("accepts LogScale and FDR event names with aid or ComputerName", () => {
    expect(isCrowdstrikeRecord(ev("ProcessRollup2"))).toBe(true);
    expect(isCrowdstrikeRecord({ event_simpleName: "DnsRequest", aid: "x" })).toBe(true);
    expect(isCrowdstrikeRecord({ "#event_simpleName": "DnsRequest", ComputerName: "WS-01" })).toBe(true);
  });
  it("rejects a row with neither aid nor ComputerName, or with no event name", () => {
    expect(isCrowdstrikeRecord({ "#event_simpleName": "ProcessRollup2", timestamp: "1" })).toBe(false);
    expect(isCrowdstrikeRecord({ aid: "x", ComputerName: "WS-01" })).toBe(false);
    expect(isCrowdstrikeRecord(null)).toBe(false);
  });
  it("CSV header signature needs the event name and aid/ComputerName", () => {
    expect(crowdstrikeCsvSig(new Set(["#event_simplename", "aid", "commandline"]))).toBe(true);
    expect(crowdstrikeCsvSig(new Set(["event_simplename", "computername"]))).toBe(true);
    expect(crowdstrikeCsvSig(new Set(["event_simplename", "timestamp"]))).toBe(false);
  });
});

describe("time, host, source", () => {
  it("dates by ContextTimeStamp, not the sensor send time (AC4)", () => {
    expect(parse(ev("ProcessRollup2", PROC)).events[0].timestamp).toBe("2024-11-12T08:26:39.456Z");
  });
  it("falls back by validity: blank/zero/malformed values are skipped", () => {
    const a = parse(ev("ProcessRollup2", { ...PROC, ContextTimeStamp: "", ProcessStartTime: "1731399000" }));
    expect(a.events[0].timestamp).toBe("2024-11-12T08:10:00.000Z");
    const b = parse(ev("ProcessRollup2", { ...PROC, ContextTimeStamp: "0", ProcessStartTime: "x" }));
    expect(b.events[0].timestamp).toBe("2024-11-12T08:26:40.000Z");
  });
  it("host is ComputerName, else aid (AC5)", () => {
    expect(parse(ev("ProcessRollup2", PROC)).events[0].asset).toBe("WS-01");
    const noName = ev("ProcessRollup2", PROC);
    delete noName.ComputerName;
    expect(parse(noName).events[0].asset).toBe("0123456789abcdef0123456789abcdef");
  });
  it("every row carries the CrowdStrike Falcon source and maps to family crowdstrike (AC12)", () => {
    const r = parse(ev("ProcessRollup2", PROC), ev("SomethingNew", { Foo: "bar" }));
    expect(r.events).toHaveLength(2);
    for (const e of r.events) {
      expect(e.sources).toEqual([CROWDSTRIKE_SOURCE]);
      expect(e.description.startsWith("CrowdStrike Falcon: ")).toBe(true);
      expect(familyOfEvent(asEvent(e))).toBe("crowdstrike");
    }
  });
  it("blank #event_simpleName falls through to event_simpleName", () => {
    const r = parse({
      "#event_simpleName": "",
      event_simpleName: "DnsRequest",
      aid: "x",
      DomainName: "a.example.com",
    });
    expect(r.events[0].description).toContain("DnsRequest");
  });
});

describe("process rows", () => {
  it("carries image, command line, parent, OS pid and hashes; hashes are IOCs (AC8)", () => {
    const r = parse(ev("ProcessRollup2", PROC));
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("notepad.exe C:\\Users\\alice\\notes.txt");
    expect(e.description).toContain("explorer.exe");
    expect(e.pid).toBe(4242); // RawProcessId — the OS pid, not Falcon's TargetProcessId
    expect(e.commandLine).toBe(PROC.CommandLine);
    expect(e.parentName).toBe("explorer.exe");
    expect(iocValues(r, "hash")).toEqual(expect.arrayContaining(["a".repeat(64), "b".repeat(32)]));
  });
  it("encoded PowerShell is graded above Info and the existing tagger rule matches (AC9)", () => {
    const rules = compileText(
      readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
    );
    const r = parse(ev("ProcessRollup2", { ...PROC, CommandLine: ENCODED }));
    expect(r.events[0].severity).not.toBe("Info");
    const ids = runTagger([asEvent(r.events[0])], rules).perEvent[0]?.ruleIds ?? [];
    expect(ids).toContain("win_powershell_encoded");
  });
  it("a malicious row survives a file with more distinct benign groups than the cap", () => {
    const rows: Row[] = [];
    for (let i = 0; i < 2100; i++)
      rows.push(
        ev("ProcessRollup2", {
          ...PROC,
          RawProcessId: String(1000 + i),
          CommandLine: `notepad.exe f${i}.txt`,
        }),
      );
    rows.push(ev("ProcessRollup2", { ...PROC, RawProcessId: "9", CommandLine: ENCODED }));
    const r = parseCrowdstrikeExport(ndjson(...rows));
    expect(r.events.some((e) => e.commandLine?.includes("-enc"))).toBe(true);
  });
});

describe("network rows", () => {
  const conn = (ip: string) =>
    ev("NetworkConnectIP4", {
      LocalAddressIP4: "10.0.0.5",
      LocalPort: "50123",
      RemoteAddressIP4: ip,
      RemotePort: "443",
      ContextProcessId: "123",
    });
  it("keeps the remote address and port; public remote is an IOC, private is not (AC6)", () => {
    const pub = parse(conn("203.0.113.10"));
    expect(pub.events[0].description).toContain("203.0.113.10");
    expect(pub.events[0].description).toContain("443");
    expect(iocValues(pub, "ip")).toContain("203.0.113.10");
    expect(iocValues(parse(conn("10.0.0.9")), "ip")).toEqual([]);
  });
  it("two connections to different remotes stay two rows (AC7)", () => {
    expect(parse(conn("203.0.113.10"), conn("203.0.113.11")).events).toHaveLength(2);
  });
  it("public IPv6 is an IOC; ULA and link-local are not", () => {
    const six = (ip: string) =>
      parse(ev("NetworkConnectIP6", { LocalAddressIP6: "fd00::5", RemoteAddressIP6: ip, RemotePort: "443" }));
    expect(iocValues(six("2001:db8::10"), "ip")).toContain("2001:db8::10");
    expect(iocValues(six("fd12::1"), "ip")).toEqual([]);
    expect(iocValues(six("fe80::1"), "ip")).toEqual([]);
  });
});

describe("dns, file, registry, task, service, unknown", () => {
  it("DnsRequest → domain IOC (AC8)", () => {
    const r = parse(ev("DnsRequest", { DomainName: "c2.example.com", RequestType: "1" }));
    expect(r.events[0].description).toContain("c2.example.com");
    expect(iocValues(r, "domain")).toContain("c2.example.com");
  });
  it("*Written carries the target file and its hash", () => {
    const r = parse(
      ev("NewExecutableWritten", {
        TargetFileName: "\\Device\\HarddiskVolume3\\Users\\Public\\x.exe",
        SHA256HashData: "c".repeat(64),
      }),
    );
    expect(r.events[0].description).toContain("\\Users\\Public\\x.exe");
    expect(iocValues(r, "hash")).toContain("c".repeat(64));
  });
  it("same task name with different commands stays two rows", () => {
    const t = (cmd: string) => ev("ScheduledTaskRegistered", { TaskName: "\\Updater", TaskExecCommand: cmd });
    expect(parse(t("C:\\Windows\\updater.exe"), t("C:\\Users\\Public\\evil.exe")).events).toHaveLength(2);
  });
  it("registry and service rows carry their fields", () => {
    const reg = parse(
      ev("AsepValueUpdate", {
        RegObjectName: "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        RegValueName: "upd",
        RegStringValue: "C:\\x.exe",
      }),
    );
    expect(reg.events[0].description).toContain("CurrentVersion\\Run");
    expect(reg.events[0].description).toContain("C:\\x.exe");
    const svc = parse(ev("ServiceStarted", { ServiceDisplayName: "Updater", ImageFileName: "C:\\svc.exe" }));
    expect(svc.events[0].description).toContain("Updater");
  });
  it("an unknown event imports as Info with key=value pairs, not dropped (AC11)", () => {
    const r = parse(ev("BrandNewEvent", { Foo: "bar", Count: "7" }));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].description).toContain("Foo=bar");
  });
});

describe("logon rows (AC10)", () => {
  it("UserLogon and UserLogonFailed2 both reach the login graph", () => {
    const ok = parse(
      ev("UserLogon", {
        UserName: "alice",
        LogonDomain: "CORP",
        LogonType: "10",
        RemoteAddressIP4: "198.51.100.7",
      }),
    );
    const bad = parse(
      ev("UserLogonFailed2", { UserName: "bob", LogonType: "3", RemoteAddressIP4: "198.51.100.8" }),
    );
    expect(parseLoginEvent(asEvent(ok.events[0]))).toMatchObject({
      account: "alice",
      host: "WS-01",
      logonType: 10,
      outcome: "success",
      sourceIp: "198.51.100.7",
    });
    expect(parseLoginEvent(asEvent(bad.events[0]))).toMatchObject({ account: "bob", outcome: "failed" });
    expect(ok.events[0].description).toContain("Logon success (type 10)");
    expect(bad.events[0].description).toContain("Logon FAILED (type 3)");
    expect(iocValues(ok, "ip")).toContain("198.51.100.7");
  });
  it("uses UserPrincipal when UserName is absent", () => {
    const r = parse(ev("UserLogon", { UserPrincipal: "carol@example.com", LogonType: "2" }));
    expect(parseLoginEvent(asEvent(r.events[0]))?.account).toBe("carol@example.com");
  });
});

describe("detection rows keep the vendor verdict", () => {
  it("DetectionSummaryEvent maps severity, MITRE and disposition", () => {
    const r = parse(
      ev("DetectionSummaryEvent", {
        SeverityName: "High",
        TechniqueId: "T1059.001",
        Tactic: "Execution",
        Technique: "PowerShell",
        DetectName: "SuspiciousPowerShell",
        PatternDispositionDescription: "Process blocked",
        FileName: "powershell.exe",
      }),
    );
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1059.001");
    expect(r.events[0].description).toContain("Process blocked");
  });
  it("numeric and Informational severities map 1:1", () => {
    expect(parse(ev("EppDetectionSummaryEvent", { Severity: "4", DetectName: "x" })).events[0].severity).toBe(
      "High",
    );
    expect(
      parse(ev("DetectionSummaryEvent", { SeverityName: "Informational", DetectName: "x" })).events[0]
        .severity,
    ).toBe("Info");
  });
});

describe("CSV input", () => {
  it("reads a CSV export with header-keyed rows", () => {
    const csv = [
      "#event_simpleName,aid,ComputerName,ContextTimeStamp,RemoteAddressIP4,RemotePort",
      "NetworkConnectIP4,abc,WS-02,1731399999.456,203.0.113.10,443",
    ].join("\n");
    const r = parseCrowdstrikeExport(csv);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].asset).toBe("WS-02");
    expect(r.events[0].timestamp).toBe("2024-11-12T08:26:39.456Z");
    expect(iocValues(r, "ip")).toContain("203.0.113.10");
  });
});
