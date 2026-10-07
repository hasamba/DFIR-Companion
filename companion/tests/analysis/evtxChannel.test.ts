import { describe, it, expect } from "vitest";
import { canonicalChannel } from "../../src/analysis/evtxChannel.js";
import { evtxRecordIdentity } from "../../src/analysis/evtxRecordId.js";
import { hayabusaAct } from "../../src/analysis/hayabusaAct.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";

describe("canonicalChannel (#1996)", () => {
  it("expands Hayabusa short names, case-insensitively", () => {
    expect(canonicalChannel("Sysmon")).toBe("Microsoft-Windows-Sysmon/Operational");
    expect(canonicalChannel(" sysmon ")).toBe("Microsoft-Windows-Sysmon/Operational");
    expect(canonicalChannel("Sec")).toBe("Security");
    expect(canonicalChannel("Sys")).toBe("System");
    expect(canonicalChannel("App")).toBe("Application");
    expect(canonicalChannel("PwSh")).toBe("Microsoft-Windows-PowerShell/Operational");
    expect(canonicalChannel("WinRM")).toBe("Microsoft-Windows-WinRM/Operational");
    expect(canonicalChannel("TaskSch")).toBe("Microsoft-Windows-TaskScheduler/Operational");
  });
  it("passes long and unknown names through unchanged", () => {
    expect(canonicalChannel("Security")).toBe("Security");
    expect(canonicalChannel("Microsoft-Windows-Sysmon/Operational")).toBe(
      "Microsoft-Windows-Sysmon/Operational",
    );
    expect(canonicalChannel("Custom/Thing")).toBe("Custom/Thing");
  });
});

describe("short channel names reach the shared callees (#1996)", () => {
  it("evtxRecordIdentity mints the same id for Sec and Security", () => {
    expect(evtxRecordIdentity("Sec", 42)).toBe("evtx:security:42");
    expect(evtxRecordIdentity("Security", 42)).toBe("evtx:security:42");
    expect(evtxRecordIdentity("Sysmon", 7)).toBe("evtx:microsoft-windows-sysmon/operational:7");
  });
  it("hayabusaAct recognises Sysmon and Sec", () => {
    expect(hayabusaAct("11", "Sysmon")).toBe("file-write");
    expect(hayabusaAct("1", "Sysmon")).toBe("process-start");
    expect(hayabusaAct("4688", "Sec")).toBe("process-start");
    expect(hayabusaAct("4688", "Sys")).toBeUndefined();
  });
});

describe("Hayabusa import with short channel names (#1996)", () => {
  const rec = (channel: string, eid: number): object => ({
    Timestamp: "2021-12-12 12:00:00.000 +00:00",
    Computer: "FS01.example.com",
    Channel: channel,
    EventID: eid,
    RecordID: 555,
    Level: "high",
    RuleTitle: "Some Rule",
    Details: { Proc: "C:\\Windows\\Temp\\a.exe", CmdLine: "a.exe" },
  });
  it("Sec 4688 mints the same identity as Security", () => {
    const out = JSON.stringify(parseHayabusaTimeline(JSON.stringify([rec("Sec", 4688)])));
    expect(out).toContain("evtx:security:555");
    expect(out).not.toContain("evtx:sec:");
  });
  it("Sysmon EID 11 gets the canonical channel in its identity", () => {
    const out = JSON.stringify(parseHayabusaTimeline(JSON.stringify([rec("Sysmon", 11)])));
    expect(out).toContain("evtx:microsoft-windows-sysmon/operational:555");
  });
});
