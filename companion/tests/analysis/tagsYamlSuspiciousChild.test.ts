import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #2091: one rule graded every Office AND script-host shell child High with T1566.001 (phishing
// attachment). Windows' own System32 scripts (netsh's gatherNetworkInfo.vbs under cscript) then
// read as spearphishing. Office parents keep the phishing tag; script hosts get T1059.005 and skip a
// parent that runs a script out of System32 / SysWOW64.
const RULESET = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
const OFFICE = "win_office_suspicious_child";
const SCRIPT = "win_script_host_suspicious_child";

function ev(parentName: string, processName: string, description: string): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-06-01T00:00:00Z",
    description,
    parentName,
    processName,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Sysmon"],
  };
}

function hit(parentName: string, processName: string, description: string) {
  const res = runTagger([ev(parentName, processName, description)], RULESET);
  return res.perEvent.find((e) => e.eventId === "e1");
}

describe("bundled data/tags.yaml — suspicious child process split (#2091)", () => {
  it("no longer ships the combined win_suspicious_child rule", () => {
    expect(RULESET.rules.find((r) => r.id === "win_suspicious_child")).toBeUndefined();
  });

  it("does not grade cscript running a System32 script (gatherNetworkInfo.vbs)", () => {
    const res = hit(
      "cscript.exe",
      "cmd.exe",
      "Process Create (EID 1) - CommandLine=cmd.exe /c reg export HKLM\\SOFTWARE\\x out.txt - " +
        "ParentImage=C:\\Windows\\System32\\cscript.exe - " +
        "ParentCommandLine=cscript.exe C:\\Windows\\system32\\gatherNetworkInfo.vbs",
    );
    expect(res?.ruleIds ?? []).not.toContain(SCRIPT);
    expect(res?.ruleIds ?? []).not.toContain(OFFICE);
    expect(res?.mitre ?? []).not.toContain("T1566.001");
    expect(res?.severity).not.toBe("High");
  });

  it("does not grade a SysWOW64 script either", () => {
    const res = hit(
      "wscript.exe",
      "cmd.exe",
      'ParentCommandLine="C:\\Windows\\SysWOW64\\wscript.exe" C:\\Windows\\SysWOW64\\slmgr.vbs /dli',
    );
    expect(res?.ruleIds ?? []).not.toContain(SCRIPT);
  });

  it("grades wscript running a user-path script High with T1059.005 and no T1566.001", () => {
    const res = hit(
      "wscript.exe",
      "cmd.exe",
      "ParentCommandLine=wscript.exe C:\\Users\\x\\Downloads\\invoice.vbs",
    );
    expect(res?.ruleIds).toContain(SCRIPT);
    expect(res?.severity).toBe("High");
    expect(res?.mitre).toContain("T1059.005");
    expect(res?.mitre ?? []).not.toContain("T1566.001");
  });

  it("grades mshta spawning cmd High without T1566.001", () => {
    const res = hit("mshta.exe", "cmd.exe", "Process created");
    expect(res?.ruleIds).toContain(SCRIPT);
    expect(res?.severity).toBe("High");
    expect(res?.mitre ?? []).not.toContain("T1566.001");
  });

  it("grades winword spawning powershell High with T1566.001 and T1059", () => {
    const res = hit("winword.exe", "powershell.exe", "Process created");
    expect(res?.ruleIds).toContain(OFFICE);
    expect(res?.severity).toBe("High");
    expect(res?.mitre).toEqual(expect.arrayContaining(["T1566.001", "T1059"]));
  });

  it("keys the exclusion on the parent: a System32 script in the CHILD command line stays High", () => {
    const res = hit(
      "cscript.exe",
      "cmd.exe",
      "CommandLine=cmd.exe /c cscript C:\\Windows\\System32\\gatherNetworkInfo.vbs - " +
        "ParentCommandLine=cscript.exe C:\\Users\\x\\AppData\\Local\\Temp\\a.vbs",
    );
    expect(res?.ruleIds).toContain(SCRIPT);
    expect(res?.severity).toBe("High");
  });

  it("still excludes a System32 script behind script-host switches or %SystemRoot%", () => {
    const switched = hit(
      "cscript.exe",
      "cmd.exe",
      "ParentCommandLine=cscript.exe //nologo //B C:\\Windows\\System32\\gatherNetworkInfo.vbs - User=x",
    );
    expect(switched?.ruleIds ?? []).not.toContain(SCRIPT);
    const envVar = hit(
      "wscript.exe",
      "cmd.exe",
      'ParentCommandLine=wscript.exe "%SystemRoot%\\System32\\slmgr.vbs" /dli',
    );
    expect(envVar?.ruleIds ?? []).not.toContain(SCRIPT);
  });

  it("stays High when a System32 script is only an unused extra argument", () => {
    const res = hit(
      "wscript.exe",
      "cmd.exe",
      "ParentCommandLine=wscript.exe C:\\Users\\x\\invoice.vbs C:\\Windows\\System32\\slmgr.vbs",
    );
    expect(res?.ruleIds).toContain(SCRIPT);
    expect(res?.severity).toBe("High");
  });

  it("stays High for a user folder that merely contains Windows\\System32", () => {
    const res = hit(
      "wscript.exe",
      "cmd.exe",
      "ParentCommandLine=wscript.exe C:\\Users\\x\\Windows\\System32\\invoice.vbs",
    );
    expect(res?.ruleIds).toContain(SCRIPT);
    expect(res?.severity).toBe("High");
  });

  it("keys the exclusion on the parent even when the child field follows it", () => {
    const res = hit(
      "cscript.exe",
      "cmd.exe",
      "ParentCommandLine=cscript.exe C:\\Users\\x\\a.vbs - " +
        "TargetFilename=C:\\Windows\\System32\\evil.vbs",
    );
    expect(res?.ruleIds).toContain(SCRIPT);
  });
});
