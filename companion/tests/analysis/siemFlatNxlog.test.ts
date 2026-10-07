import { describe, it, expect } from "vitest";
import { parseSiemExport } from "../../src/analysis/siemImport.js";

// Flat NXLog / OTRF Mordor shape (#2023): the event-data fields sit at the TOP LEVEL of the record,
// beside EventID / Channel / Hostname — there is no event_data / winlog.event_data / EventData object.
// Records trimmed from the public OTRF APT29 Evals Day 1 dataset.
const RLO = "\u202e";
const BASE = {
  EventTime: "2020-05-01 22:55:57",
  SourceName: "Microsoft-Windows-Sysmon",
  Channel: "Microsoft-Windows-Sysmon/Operational",
  Hostname: "SCRANTON.lab.local",
  host: "wec.lab.local",
  tags: ["mordorDataset"],
  "@version": "1",
};

const PAYLOAD_START = {
  ...BASE,
  EventID: 1,
  UtcTime: "2020-05-02 02:55:56.157",
  ProcessGuid: "{47ab858c-e13c-5eac-a903-000000000400}",
  ProcessId: "8524",
  Image: `C:\\ProgramData\\victim\\${RLO}cod.3aka3.scr`,
  CommandLine: `"C:\\ProgramData\\victim\\${RLO}cod.3aka3.scr" /S`,
  User: "LAB\\analyst",
  ParentImage: "C:\\Windows\\explorer.exe",
  ParentCommandLine: "C:\\Windows\\Explorer.EXE",
  Message: `Process Create:\r\nImage: C:\\ProgramData\\victim\\${RLO}cod.3aka3.scr`,
};

const BENIGN_START = {
  ...BASE,
  EventID: 1,
  UtcTime: "2020-05-02 02:56:10.000",
  ProcessGuid: "{47ab858c-e13c-5eac-aa03-000000000400}",
  ProcessId: "9000",
  Image: "C:\\Windows\\System32\\backgroundTaskHost.exe",
  CommandLine: "C:\\Windows\\System32\\backgroundTaskHost.exe -ServerName:App",
  User: "LAB\\analyst",
  ParentImage: "C:\\Windows\\System32\\svchost.exe",
  Message: "Process Create:\r\nImage: C:\\Windows\\System32\\backgroundTaskHost.exe",
};

const PROC_ACCESS = {
  ...BASE,
  EventID: 10,
  UtcTime: "2020-05-02 03:11:19.000",
  SourceImage: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  TargetImage: "C:\\Windows\\System32\\lsass.exe",
  GrantedAccess: "0x1010",
  SourceProcessId: "4000",
  TargetProcessId: "640",
  Message: "Process accessed:\r\nTargetImage: C:\\Windows\\System32\\lsass.exe",
};

const lines = (...recs: object[]) => recs.map((r) => JSON.stringify(r)).join("\n");

describe("parseSiemExport — flat NXLog / Mordor Windows records (#2023)", () => {
  it("does not collapse distinct process starts on one host into one group", () => {
    const r = parseSiemExport(lines(PAYLOAD_START, BENIGN_START));
    expect(r.events).toHaveLength(2);
  });

  it("names the started image in the description", () => {
    const r = parseSiemExport(lines(PAYLOAD_START));
    expect(r.events[0].description).toContain("cod.3aka3.scr");
    expect(r.events[0].asset).toBe("SCRANTON.lab.local");
  });

  it("grades the right-to-left-override payload above Low", () => {
    const r = parseSiemExport(lines(PAYLOAD_START));
    expect(["Medium", "High", "Critical"]).toContain(r.events[0].severity);
  });

  it("names both processes on a process-access event instead of (unknown process)", () => {
    const r = parseSiemExport(lines(PROC_ACCESS));
    expect(r.events[0].description).not.toContain("unknown process");
    expect(r.events[0].description).toMatch(/lsass\.exe/i);
    expect(r.events[0].description).toMatch(/powershell\.exe/i);
  });

  it("uses the Sysmon UtcTime, not the collector's local EventTime", () => {
    const r = parseSiemExport(lines(PAYLOAD_START));
    expect(r.events[0].timestamp).toBe("2020-05-02T02:55:56.157Z");
  });

  it("still reads nested event_data when present (no regression for winlogbeat shape)", () => {
    const nested = {
      "@timestamp": "2020-05-02T02:55:56.157Z",
      log_name: "Microsoft-Windows-Sysmon/Operational",
      computer_name: "HOST1",
      event_id: 1,
      event_data: { UtcTime: "2020-05-02 02:55:56.157", Image: "C:\\Temp\\evil.exe" },
    };
    const r = parseSiemExport(lines(nested));
    expect(r.events[0].description).toContain("evil.exe");
  });
});
