import { describe, it, expect } from "vitest";
import { interpreterTechniques } from "../../src/analysis/processInterpreter.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";

// ATT&CK T1059 is "Command and Scripting Interpreter". It was put on every Sysmon 1 and Security 4688
// row, so one case carried it on 5,232 of 5,766 events, every phase read "Execution", and the MITRE
// matrix counted taskhostw.exe as scripting. A process earns it only when it IS an interpreter.

describe("interpreterTechniques", () => {
  it("tags the shells and script hosts", () => {
    for (const image of [
      "C:\\Windows\\System32\\cmd.exe",
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
      "C:\\Windows\\SysWOW64\\wscript.exe",
      "C:\\Windows\\System32\\cscript.exe",
      "C:\\Python312\\python.exe",
      "C:\\Program Files\\nodejs\\node.exe",
      "/usr/bin/BASH.EXE",
    ]) {
      expect(interpreterTechniques(image), image).toEqual(["T1059"]);
    }
  });

  it("does not tag an ordinary program", () => {
    for (const image of [
      "C:\\Windows\\System32\\taskhostw.exe",
      "C:\\Windows\\System32\\svchost.exe",
      "C:\\Windows\\System32\\msiexec.exe",
      "C:\\Windows\\explorer.exe",
      "C:\\Tools\\mycmd.exe",
      "",
    ]) {
      expect(interpreterTechniques(image), image).toEqual([]);
    }
  });
});

function techniques(rec: Record<string, unknown>): string[] {
  const parsed = parseSiemExport(JSON.stringify([{ "@timestamp": "2026-01-02T03:04:05Z", ...rec }]));
  return parsed.events[0].mitreTechniques;
}

function sysmon(image: string, commandLine: string): string[] {
  return techniques({
    channel: "Microsoft-Windows-Sysmon/Operational",
    computer_name: "H1",
    event_id: 1,
    event_data: { Image: image, CommandLine: commandLine },
  });
}

describe("process-create events through the Windows importer", () => {
  it("leaves a Sysmon process create for an ordinary program without T1059", () => {
    expect(sysmon("C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe")).not.toContain("T1059");
  });

  it("tags a Sysmon process create for cmd.exe with T1059", () => {
    expect(sysmon("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir")).toContain("T1059");
  });

  it("tags a Security 4688 for powershell.exe with T1059, and not one for notepad.exe", () => {
    const security = (image: string) =>
      techniques({
        channel: "Security",
        computer_name: "H1",
        event_id: 4688,
        event_data: { NewProcessName: image, CommandLine: image },
      });
    expect(security("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")).toContain("T1059");
    expect(security("C:\\Windows\\System32\\notepad.exe")).not.toContain("T1059");
  });

  it("keeps the techniques a specific rule adds, with or without an interpreter", () => {
    const found = sysmon("C:\\Windows\\System32\\vssadmin.exe", "vssadmin delete shadows /all /quiet");
    expect(found.length).toBeGreaterThan(0);
    expect(found).not.toContain("T1059");
  });
});
