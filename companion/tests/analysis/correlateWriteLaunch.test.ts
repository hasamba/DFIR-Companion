import { describe, it, expect } from "vitest";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1557 — a Sysmon file write (EID 11) of a binary and the launch of that binary (EID 1) 42 ms later
// are two facts: the write says who dropped the file, the launch says what it ran. Correlation
// folded them into one row on the shared path: the High write's text won the description while the
// process name, pid and command line fell back to the launch, so the launch's own row vanished and
// the model never saw what the binary ran. These rows are the real hunt's shapes with lab names.

const HOST = "WS-01";
const FQDN = `${HOST}.example.com`;
const DROP = "C:\\Users\\Public\\Sim\\ProgramData\\Microsoft\\msxsl.exe";
const PS = "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const SHA = "9695CF4566DDF878A69C3D419E0DA4EEA87B0F24261AD8E79A3A9C4A9885429C";
const MD5 = "C8B5D63042BC4BBB7F5C0F9E15B61F16";
const CMD = `"${DROP}" /d /v:off /c echo LAB-CANARY msxsl.exe 29D88F75006BE8A.txt 29D88F75006BE8A.txt `;
const WRITE_TIME = "2026-09-22T14:37:51.830322Z";
const LAUNCH_TIME = "2026-09-22T14:37:51.894584Z";

const writeData = {
  CreationUtcTime: "2026-09-22 14:37:51.829",
  Image: PS,
  ProcessGuid: "6FEF6725-92A4-6AB2-1501-000000000A00",
  ProcessId: 10756,
  RuleName: "EXE",
  TargetFilename: DROP,
  User: `${HOST}\\lab`,
  UtcTime: "2026-09-22 14:37:51.829",
};

const system = (eid: number, recordId: number, time: string) => ({
  Channel: "Microsoft-Windows-Sysmon/Operational",
  Computer: HOST,
  EventID: eid,
  EventRecordID: recordId,
  TimeCreated_attributes: { SystemTime: time },
});

const chainsawWrite = {
  EventTime: WRITE_TIME,
  Detection: "Windows Shell/Scripting Application File Write to Suspicious Folder",
  Severity: "high",
  "Rule Group": "Sigma",
  Computer: HOST,
  Channel: "Microsoft-Windows-Sysmon/Operational",
  EventID: 11,
  SystemData: system(11, 1001, WRITE_TIME),
  EventData: writeData,
  Fqdn: FQDN,
};

const chainsawLaunch = (detection: string) => ({
  EventTime: LAUNCH_TIME,
  Detection: detection,
  Severity: "medium",
  "Rule Group": "Sigma",
  Computer: HOST,
  Channel: "Microsoft-Windows-Sysmon/Operational",
  EventID: 1,
  SystemData: system(1, 1002, LAUNCH_TIME),
  EventData: {
    CommandLine: CMD,
    Hashes: `MD5=${MD5},SHA256=${SHA}`,
    Image: DROP,
    OriginalFileName: "Cmd.Exe",
    ParentCommandLine: PS,
    ParentImage: PS,
    ParentProcessId: 10756,
    ProcessGuid: "6FEF6725-92BF-6AB2-2B01-000000000A00",
    ProcessId: 1112,
    User: `${HOST}\\lab`,
    UtcTime: "2026-09-22 14:37:51.871",
  },
  Fqdn: FQDN,
});

const hayabusaWrite = {
  Timestamp: "2026-09-22T14:37:51.830323219Z",
  Computer: HOST,
  Channel: "Microsoft-Windows-Sysmon/Operational",
  EID: 11,
  Level: "high",
  Title: "Suspicious Binaries and Scripts in Public Folder",
  RecordID: 1001,
  Details: `Path: ${DROP} ¦ Proc: ${PS} ¦ PID: 10756 ¦ PGUID: 6FEF6725-92A4-6AB2-1501-000000000A00`,
  _Event: {
    System: {
      EventID: { Value: 11 },
      TimeCreated: { SystemTime: 1790087871.8303232 },
      EventRecordID: 1001,
      Channel: "Microsoft-Windows-Sysmon/Operational",
      Computer: HOST,
    },
    EventData: writeData,
  },
  _Source: "Windows.Sigma.Base",
  Fqdn: FQDN,
};

function toEvents(rows: object[], artifact: string, prefix: string): ForensicEvent[] {
  return parseVelociraptorJson(JSON.stringify(rows), { artifact }).events.map((e, i) => {
    const { aggKey, ...rest } = e as ForensicEvent & { aggKey?: string };
    void aggKey;
    return {
      ...rest,
      id: `${prefix}e${i + 1}`,
      mitreTechniques: rest.mitreTechniques ?? [],
      relatedFindingIds: rest.relatedFindingIds ?? [],
      sourceScreenshots: rest.sourceScreenshots ?? [],
      sources: rest.sources?.length ? rest.sources : ["Velociraptor"],
    };
  });
}

const isLaunch = (e: ForensicEvent) => e.canonical?.event?.category === "process";
const isWrite = (e: ForensicEvent) => e.canonical?.event?.category === "file";

describe("correlateEvents — a file write and the launch of that file stay two rows (#1557)", () => {
  it("keeps the EID 11 write and the EID 1 launch of one path apart, and the launch keeps its command line", () => {
    const hayabusa = toEvents([hayabusaWrite], "Windows.Hayabusa.Rules", "1");
    const chainsaw = toEvents(
      [chainsawWrite, chainsawLaunch("Potential Defense Evasion Via Binary Rename")],
      "Windows.EventLogs.Chainsaw",
      "2",
    );
    const rows = [...hayabusa, ...chainsaw];
    // The shapes the importer really produces: both sides typed, same path, same host, 64 ms apart.
    expect(rows.filter(isWrite)).toHaveLength(2);
    expect(rows.filter(isLaunch)).toHaveLength(1);
    expect(new Set(rows.map((e) => e.path))).toEqual(new Set([DROP]));

    for (const input of [rows, [...rows].reverse()]) {
      const out = correlateEvents(input);
      const launches = out.filter((e) => /Process create \(EID 1\)/.test(e.description));
      const writes = out.filter((e) => /File created \(EID 11\)/.test(e.description));
      expect(launches).toHaveLength(1);
      expect(writes).toHaveLength(1);
      // The launch row states what ran, and the write row does not borrow it.
      expect(launches[0].commandLine).toBe(CMD);
      expect(launches[0].pid).toBe(1112);
      expect(launches[0].processName?.toLowerCase()).toBe("msxsl.exe");
      expect(writes[0].commandLine).toBeUndefined();
      expect(writes[0].pid).toBeUndefined();
      // The two parsers' readings of the one write record still corroborate each other.
      expect(writes[0].sources).toEqual(expect.arrayContaining(["Velociraptor", "Chainsaw"]));
    }
  });

  it("a pathless hash hit cannot bridge the write and the launch", () => {
    const rows = [
      ...toEvents([hayabusaWrite], "Windows.Hayabusa.Rules", "1"),
      ...toEvents([chainsawLaunch("Msxsl.EXE Execution")], "Windows.EventLogs.Chainsaw", "2"),
    ];
    const yara: ForensicEvent = {
      id: "y1",
      timestamp: "2026-09-22T14:37:52Z",
      description: `THOR Alert [Filescan]: renamed command processor — sha256 ${SHA.toLowerCase()}`,
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: FQDN,
      sources: ["THOR"],
    };
    const out = correlateEvents([...rows, yara]);
    expect(out.filter((e) => /Process create \(EID 1\)/.test(e.description))).toHaveLength(1);
    expect(out.filter((e) => /File created \(EID 11\)/.test(e.description))).toHaveLength(1);
  });
});
