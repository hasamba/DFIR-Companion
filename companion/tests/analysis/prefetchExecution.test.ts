import { describe, it, expect } from "vitest";
import { prefetchSignal } from "../../src/analysis/prefetchExecution.js";

// The execution chain recorded in Prefetch on the Trigona case that prompted this module. Every one
// of these graded Info before, which put the whole chain below the forensic floor.
describe("prefetchExecution — the dual-use binaries a Prefetch entry can name", () => {
  it("grades the in-memory C# toolchain Medium with T1027.004", () => {
    for (const exe of ["CSC.EXE", "CVTRES.EXE", "vbc.exe", "MSBuild.exe"]) {
      const s = prefetchSignal(exe);
      expect(s?.severity, exe).toBe("Medium");
      expect(s?.mitre, exe).toContain("T1027.004");
    }
    expect(prefetchSignal("MSBUILD.EXE")?.mitre).toContain("T1127.001");
  });

  it("grades a cloud/bulk exfil tool execution Medium with T1567.002 (name alone, no command line)", () => {
    for (const exe of ["rclone.exe", "RCLONE.EXE", "restic.exe", "megasync.exe", "megacmd.exe"]) {
      const s = prefetchSignal(exe);
      expect(s?.severity, exe).toBe("Medium");
      expect(s?.mitre, exe).toContain("T1567.002");
    }
  });

  it("grades the defense-tampering and anti-forensics utilities with their own technique", () => {
    expect(prefetchSignal("WEVTUTIL.EXE")?.mitre).toEqual(["T1070.001"]);
    expect(prefetchSignal("TASKKILL.EXE")?.mitre).toEqual(["T1562.001"]);
    expect(prefetchSignal("SDBINST.EXE")?.mitre).toEqual(["T1546.011"]);
    expect(prefetchSignal("MOFCOMP.EXE")?.mitre).toEqual(["T1546.003"]);
    expect(prefetchSignal("VSSADMIN.EXE")?.mitre).toEqual(["T1490"]);
    expect(prefetchSignal("CERTUTIL.EXE")?.mitre).toContain("T1105");
    for (const exe of ["WEVTUTIL.EXE", "TASKKILL.EXE", "SDBINST.EXE", "CERTUTIL.EXE"]) {
      expect(prefetchSignal(exe)?.severity, exe).toBe("Medium");
    }
  });

  it("still grades a LOLBin with no technique of its own, from the shared baseline set", () => {
    const s = prefetchSignal("MSHTA.EXE");
    expect(s?.severity).toBe("Medium");
    expect(prefetchSignal("BITSADMIN.EXE")?.severity).toBe("Medium");
  });

  it("reads the name out of a \\DEVICE path when the Executable column is empty", () => {
    const s = prefetchSignal("", "\\DEVICE\\HARDDISKVOLUME4\\WINDOWS\\SYSTEM32\\WEVTUTIL.EXE");
    expect(s?.severity).toBe("Medium");
    expect(s?.mitre).toEqual(["T1070.001"]);
  });
});

describe("prefetchExecution — named offensive tooling grades High on the name alone", () => {
  it("flags credential dumpers", () => {
    for (const exe of ["mimikatz.exe", "MIMIKATZ_X64.EXE", "SafetyKatz.exe", "nanodump.exe", "pwdump7.exe"]) {
      expect(prefetchSignal(exe)?.severity, exe).toBe("High");
    }
    expect(prefetchSignal("mimikatz.exe")?.mitre).toContain("T1003.001");
  });

  it("flags the RogueWinRM / Potato service-account escalation family with T1068 and T1134.002", () => {
    for (const exe of ["RogueWinRM.exe", "JuicyPotato.exe", "GodPotato.exe", "PrintSpoofer64.exe"]) {
      const s = prefetchSignal(exe);
      expect(s?.severity, exe).toBe("High");
      expect(s?.mitre, exe).toContain("T1068");
      expect(s?.mitre, exe).toContain("T1134.002");
    }
  });

  it("flags WinPwn with the same technique its command-line rule carries", () => {
    expect(prefetchSignal("WinPwn.exe")?.mitre).toContain("T1134.001");
  });
});

// The two entries the review that prompted this module asked for that would have manufactured
// findings. Both are guarded deliberately, so both are pinned here.
describe("prefetchExecution — false-positive guards", () => {
  it("says nothing about vssvc.exe, which runs on every backup and every Windows Update", () => {
    expect(prefetchSignal("VSSVC.EXE")).toBeNull();
  });

  it("says nothing about Edge's own cookie_exporter / identity_helper inside the browser install", () => {
    expect(
      prefetchSignal(
        "COOKIE_EXPORTER.EXE",
        "\\DEVICE\\HARDDISKVOLUME4\\PROGRAM FILES (X86)\\MICROSOFT\\EDGE\\APPLICATION\\126.0.1\\COOKIE_EXPORTER.EXE",
      ),
    ).toBeNull();
    expect(
      prefetchSignal(
        "IDENTITY_HELPER.EXE",
        "\\DEVICE\\HARDDISKVOLUME4\\PROGRAM FILES (X86)\\MICROSOFT\\EDGE\\APPLICATION\\126.0.1\\IDENTITY_HELPER.EXE",
      ),
    ).toBeNull();
  });

  it("says nothing about a browser helper whose path the export did not record", () => {
    // An absent ExecutablePath is common in Windows.Forensics.Prefetch exports. It must not read as
    // "ran from outside the browser directory", which would grade every stock Edge helper.
    expect(prefetchSignal("COOKIE_EXPORTER.EXE")).toBeNull();
    expect(prefetchSignal("IDENTITY_HELPER.EXE", "")).toBeNull();
    expect(prefetchSignal("MSEDGE_IDENTITY_HELPER.EXE", "   ")).toBeNull();
  });

  it("DOES grade the same binaries when they ran from outside a browser install", () => {
    const s = prefetchSignal(
      "COOKIE_EXPORTER.EXE",
      "\\DEVICE\\HARDDISKVOLUME4\\USERS\\PUBLIC\\COOKIE_EXPORTER.EXE",
    );
    expect(s?.severity).toBe("Medium");
    expect(s?.mitre).toContain("T1539");
  });

  it("says nothing about the everyday binaries a Prefetch listing is mostly made of", () => {
    for (const exe of [
      "CHROME.EXE",
      "EXCEL.EXE",
      "NOTEPAD.EXE",
      "TEAMS.EXE",
      "SVCHOST.EXE",
      "EXPLORER.EXE",
      "CMD.EXE", // a noisy LOLBin: the name alone carries no information
      "POWERSHELL.EXE",
      "RUNDLL32.EXE.pf", // not a real executable name; must not crash or match
      "",
    ]) {
      expect(prefetchSignal(exe), exe).toBeNull();
    }
  });
});
