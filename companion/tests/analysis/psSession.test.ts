import { describe, it, expect } from "vitest";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { parseEvtxXml } from "../../src/analysis/evtxXmlImport.js";
import { parseChainsawReport } from "../../src/analysis/chainsawImport.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { canonicalConformanceIssues } from "../../src/analysis/canonicalEvent.js";
import { psSessionIdOf } from "../../src/analysis/canonicalPowerShell.js";

// #2078: every importer that reads Windows PowerShell logs records the session a row ran in — the
// PowerShell host process id the ENGINE stamped on the record (Execution ProcessID) — on
// canonical.powershell, so synthesis can send the rest of a session that has a High row.

const PS_OP = "Microsoft-Windows-PowerShell/Operational";
const SCRIPT = "New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name x";

function expectSession(e: { canonical?: unknown } | undefined, pid: number): void {
  expect(e).toBeDefined();
  expect(psSessionIdOf(e as never)).toBe(`pid:${pid}`);
  expect((e as { canonical: { powershell: unknown } }).canonical.powershell).toEqual({
    sessionId: `pid:${pid}`,
    processId: pid,
  });
  expect(canonicalConformanceIssues((e as { canonical: unknown }).canonical)).toEqual([]);
}

describe("siemImport — PowerShell session key (#2078)", () => {
  it("reads NXLog / OTRF-Mordor flat ExecutionProcessID on a 4104", () => {
    const rec = {
      EventID: 4104,
      Channel: PS_OP,
      Hostname: "WS-01.example.com",
      "@timestamp": "2026-05-20T03:00:00Z",
      ExecutionProcessID: 4242,
      ScriptBlockText: SCRIPT,
      MessageNumber: "1",
      MessageTotal: "1",
    };
    const r = parseSiemExport(JSON.stringify([rec]), { aggregate: false });
    expectSession(r.events[0], 4242);
  });

  it("reads Winlogbeat winlog.process.pid on a 4103", () => {
    const rec = {
      "@timestamp": "2026-05-20T03:40:00Z",
      host: { name: "WS-01.example.com" },
      winlog: {
        channel: PS_OP,
        event_id: 4103,
        computer_name: "WS-01.example.com",
        process: { pid: 4242, thread: { id: 7 } },
        event_data: { Payload: "CommandInvocation(net.exe): net use y: https://d.example.net/x" },
      },
    };
    const r = parseSiemExport(JSON.stringify([rec]), { aggregate: false });
    expectSession(r.events[0], 4242);
  });

  it("records nothing off the PowerShell channel, even with a ProcessID", () => {
    const rec = {
      EventID: 4688,
      Channel: "Security",
      Hostname: "WS-01.example.com",
      "@timestamp": "2026-05-20T03:00:00Z",
      ProcessID: 4,
      NewProcessName: "C:\\Windows\\System32\\cmd.exe",
      CommandLine: "cmd.exe /c whoami",
    };
    const r = parseSiemExport(JSON.stringify([rec]), { aggregate: false });
    expect(r.events[0].canonical?.powershell).toBeUndefined();
  });

  it("records nothing for a PowerShell row with no usable pid", () => {
    const rec = {
      EventID: 4104,
      Channel: PS_OP,
      Hostname: "WS-01.example.com",
      "@timestamp": "2026-05-20T03:00:00Z",
      ExecutionProcessID: 0,
      ScriptBlockText: SCRIPT,
    };
    const r = parseSiemExport(JSON.stringify([rec]), { aggregate: false });
    expect(r.events[0].canonical?.powershell).toBeUndefined();
  });
});

describe("evtxXmlImport — PowerShell session key (#2078)", () => {
  it("reads the System Execution ProcessID attribute", () => {
    const xml = `<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-PowerShell"/><EventID>4104</EventID>
<TimeCreated SystemTime="2026-05-20T03:00:00.000Z"/><EventRecordID>77</EventRecordID>
<Execution ProcessID="5150" ThreadID="12"/><Channel>${PS_OP}</Channel><Computer>WS-01.example.com</Computer></System>
<EventData><Data Name="MessageNumber">1</Data><Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">${SCRIPT}</Data><Data Name="ScriptBlockId">0b8f7f3e-0000-4000-8000-000000000001</Data></EventData>
</Event></Events>`;
    const r = parseEvtxXml(xml, { aggregate: false });
    expectSession(r.events[0], 5150);
  });
});

describe("chainsawImport — PowerShell session key (#2078)", () => {
  it("reads System.Execution.#attributes.ProcessID from an embedded Event document", () => {
    const hit = {
      group: "Sigma",
      kind: "individual",
      document: {
        kind: "evtx",
        data: {
          Event: {
            System: {
              Provider: { "#attributes": { Name: "Microsoft-Windows-PowerShell" } },
              EventID: 4104,
              Channel: PS_OP,
              Computer: "WS-01.example.com",
              Execution: { "#attributes": { ProcessID: 6160, ThreadID: 3 } },
              TimeCreated: { "#attributes": { SystemTime: "2026-05-20T03:00:00.000Z" } },
            },
            EventData: { ScriptBlockText: SCRIPT, MessageNumber: 1, MessageTotal: 1 },
          },
        },
      },
      rule: { name: "Run key via PowerShell", level: "medium", tags: [] },
      timestamp: "2026-05-20T03:00:00.000Z",
    };
    const r = parseChainsawReport(JSON.stringify([hit]));
    expectSession(r.events[0], 6160);
  });

  it("reads SystemData.Execution_attributes.ProcessID from a flat hunt row", () => {
    const row = {
      EventTime: "2026-05-20T03:00:00Z",
      Detection: "Run key via PowerShell",
      Severity: "medium",
      "Rule Group": "Sigma",
      Computer: "WS-01.example.com",
      Channel: PS_OP,
      EventID: 4104,
      SystemData: {
        EventID: 4104,
        Execution_attributes: { ProcessID: 6161, ThreadID: 3 },
        TimeCreated_attributes: { SystemTime: "2026-05-20T03:00:00Z" },
        Channel: PS_OP,
        Computer: "WS-01.example.com",
      },
      EventData: { ScriptBlockText: SCRIPT },
    };
    const r = parseChainsawReport(JSON.stringify([row]));
    expectSession(r.events[0], 6161);
  });
});

describe("velociraptorImport — PowerShell session key (#2078)", () => {
  it("reads System.Execution.ProcessID from a parsed EVTX row", () => {
    const row = {
      System: {
        EventID: { Value: 4104 },
        Channel: PS_OP,
        Computer: "WS-01.example.com",
        EventRecordID: 91,
        Execution: { ProcessID: 7272, ThreadID: 9 },
        TimeCreated: { SystemTime: 1779246000 },
      },
      EventData: { ScriptBlockText: SCRIPT, MessageNumber: 1, MessageTotal: 1, ScriptBlockId: "sb-1" },
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events.find((x) => /Script block/i.test(x.description));
    expectSession(e, 7272);
  });
});
