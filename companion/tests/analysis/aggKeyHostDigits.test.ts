import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";

// #1917 (the #1905 bug class): an aggregation key folds digit runs to '#' so rotating ids collapse.
// Several keys folded the HOST too, so WS01, WS02 and WS03 shared one key and three machines came
// back as one event on the first — the other hosts were gone from the forensic timeline. Each
// importer path below must keep digit-different hosts apart and still fold one host's volatile ids.

const HOSTS = ["WS01.example.com", "WS02.example.com", "WS03.example.com"];

type Ev = { asset?: string; count?: number };
const assets = (events: Ev[]): string[] => events.map((e) => e.asset ?? "").sort();

function vr(rows: object[]): Ev[] {
  return parseVelociraptorJson(JSON.stringify(rows), { aggregate: true }).events;
}

// One builder per Velociraptor mapper whose key held the host. `vary` is a volatile number that must
// NOT split one host's rows.
const VR_PATHS: Record<string, (host: string, vary: number) => object> = {
  generic: (host, vary) => ({
    _Source: "Custom.Example.Artifact",
    Fqdn: host,
    Message: `worker ${vary} finished the task`,
  }),
  usn: (host, vary) => ({
    _Source: "Windows.Forensics.Usn",
    Fqdn: host,
    Timestamp: "2025-12-05T03:12:59Z",
    OSPath: `C:\\temp\\log${vary}.txt`,
    Reason: ["FILE_CREATE"],
  }),
  prefetch: (host, vary) => ({
    _Source: "Windows.Forensics.Prefetch",
    Fqdn: host,
    Executable: "PSEXESVC.EXE",
    RunCount: vary,
    ExecutablePath: "\\DEVICE\\HARDDISKVOLUME4\\WINDOWS\\PSEXESVC.EXE",
    LastRunTimes: ["2026-07-02T12:16:39Z"],
    OSPath: "C:\\Windows\\Prefetch\\PSEXESVC.EXE-3B54.pf",
  }),
  pslist: (host, vary) => ({
    Fqdn: host,
    Pid: String(vary),
    Ppid: "592",
    Name: "svchost.exe",
    Username: "NT AUTHORITY\\LOCAL SERVICE",
    Exe: "C:\\Windows\\System32\\svchost.exe",
    CommandLine: "C:\\Windows\\System32\\svchost.exe -k netsvcs",
    StartTime: "2026-06-12T11:12:45.8986623Z",
    EndTime: "0001-01-01T00:00:00Z",
    CallChain: "svchost.exe",
    PSTree: null,
  }),
  netstat: (host, vary) => ({
    _Source: "Windows.Network.Netstat",
    Fqdn: host,
    Pid: vary,
    Name: "evil.exe",
    Path: "C:\\temp\\evil.exe",
    Raddr: "198.51.100.7",
    Status: "ESTABLISHED",
    _ts: 1677662400,
  }),
  startup: (host, vary) => ({
    _Source: "Windows.Sys.StartupItems",
    Fqdn: host,
    Name: "updater",
    OSPath: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\updater",
    Details: `"C:\\ProgramData\\updater\\v${vary}\\updater.exe"`,
    Enabled: "enable",
  }),
};

describe("Velociraptor aggregation keys keep digit-different hosts apart (#1917)", () => {
  for (const [path, row] of Object.entries(VR_PATHS)) {
    it(`${path}: three hosts that differ only by digits stay three events`, () => {
      const events = vr(HOSTS.map((h) => row(h, 1)));
      expect(events).toHaveLength(3);
      expect(assets(events)).toEqual(HOSTS);
    });

    it(`${path}: one host's rows that differ only by a volatile number still aggregate`, () => {
      const events = vr([row(HOSTS[0], 1234), row(HOSTS[0], 5678)]);
      expect(events).toHaveLength(1);
      expect(events[0].count).toBe(2);
    });
  }
});

describe("SIEM generic aggregation key keeps digit-different hosts apart (#1917)", () => {
  const rec = (host: string, vary: number): object => ({
    vendor: "ExampleEDR",
    "@timestamp": "2026-01-02T03:04:05Z",
    hostname: host,
    severity: "high",
    message: `Service PSEXESVC installed by pid ${vary}`,
  });

  it("three hosts that differ only by digits stay three events", () => {
    const r = parseSiemExport(JSON.stringify(HOSTS.map((h) => rec(h, 1))), { aggregate: true });
    expect(r.events).toHaveLength(3);
    expect(assets(r.events)).toEqual(HOSTS);
  });

  it("one host's rows that differ only by a volatile number still aggregate", () => {
    const r = parseSiemExport(JSON.stringify([rec(HOSTS[0], 1234), rec(HOSTS[0], 5678)]), {
      aggregate: true,
    });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });
});

describe("Velociraptor Sigma over a parsed event keeps hosts apart with a long rule title (#1917 review)", () => {
  // The overlay used to prepend the unbounded rule title to the Windows key, and the message
  // fingerprint step then cut the whole key at 440 characters — taking the host-bearing part with it.
  const sigma = (host: string): object => ({
    _Source: "Windows.Hayabusa.Sigma",
    Rule: { Title: `Suspicious LSASS Access ${"x".repeat(500)}`, Level: "high" },
    System: {
      EventID: 10,
      Channel: "Microsoft-Windows-Sysmon/Operational",
      Computer: host,
      TimeCreated: "2023-03-01T10:00:00Z",
    },
    EventData: { TargetImage: "C:\\Windows\\System32\\lsass.exe", SourceImage: "C:\\temp\\tool.exe" },
    Details: "GrantedAccess 0x1010 from tool.exe",
  });

  it("three hosts that differ only by digits stay three events", () => {
    const events = vr(HOSTS.map(sigma));
    expect(events).toHaveLength(3);
    expect(assets(events)).toEqual(HOSTS);
  });
});
