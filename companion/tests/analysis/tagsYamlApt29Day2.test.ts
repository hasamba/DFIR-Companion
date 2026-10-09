import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import { runAndApplyTagger } from "../../src/analysis/taggerRun.js";
import { demoteBelowSeverity } from "../../src/analysis/forensicGate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Tradecraft from an APT29-style Day 2 scenario that the default ruleset left at Info (#2079):
// running a script out of an NTFS alternate data stream, an anti-VM WMI probe, AV product
// discovery, an installed-software (Uninstall key) walk, and P/Invoke account/host lookups.
// Every fixture string below is generic — no lab hostnames, users or addresses.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

type Field = "message" | "description" | "commandLine";

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

function tagged(text: string, field: Field = "message") {
  const event = ev({ id: "e1", description: field === "description" ? text : "d", [field]: text });
  return runTagger([event], RULES).perEvent[0];
}

function ruleIds(text: string, field: Field = "message"): string[] {
  return tagged(text, field)?.ruleIds ?? [];
}

const ADS_PIPE = "Get-Content C:\\Users\\Public\\notes.txt -Stream payload | IEX";
const ADS_WRAP = "IEX (Get-Content -Path C:\\ProgramData\\cache.dat -Stream s -Raw)";

describe("win_ads_stream_exec", () => {
  for (const field of ["message", "description", "commandLine"] as const) {
    it(`grades the pipe-to-IEX cradle High with T1564.004 on ${field}`, () => {
      const r = tagged(ADS_PIPE, field);
      expect(r?.ruleIds).toContain("win_ads_stream_exec");
      expect(r?.severity).toBe("High");
      expect(r?.mitre).toEqual(expect.arrayContaining(["T1564.004", "T1059.001"]));
    });
  }

  it("matches the IEX-wrapped form", () => {
    expect(ruleIds(ADS_WRAP)).toContain("win_ads_stream_exec");
    expect(ruleIds('powershell -c "Invoke-Expression (gc .\\a.txt -Stream x)"', "commandLine")).toContain(
      "win_ads_stream_exec",
    );
  });

  it("does not match listing streams (Get-Item -Stream *)", () => {
    expect(ruleIds("Get-Item C:\\Users\\Public\\notes.txt -Stream *")).not.toContain("win_ads_stream_exec");
  });

  it("does not match reading a stream without executing it", () => {
    expect(ruleIds("Get-Content .\\setup.exe -Stream Zone.Identifier")).not.toContain("win_ads_stream_exec");
  });

  it("does not match a 4103 record whose only hit is the Host Application line", () => {
    const message =
      'CommandInvocation(Write-Output): "Write-Output"\r\n' +
      'ParameterBinding(Write-Output): name="InputObject"; value="done"\r\n\r\nContext:\r\n' +
      "        Severity = Informational\r\n" +
      `        Host Application = powershell.exe -c "${ADS_PIPE}"\r\n` +
      "        Engine Version = 5.1\r\n";
    expect(ruleIds(message)).not.toContain("win_ads_stream_exec");
  });
});

describe("win_antivm_wmi_probe", () => {
  it("grades a block naming Win32_BIOS and Win32_PnPEntity Medium with T1497.001", () => {
    const r = tagged(
      "$b = Get-WmiObject Win32_BIOS\n$p = Get-WmiObject Win32_PnPEntity | ? { $_.Name -match 'VBox' }",
    );
    expect(r?.ruleIds).toContain("win_antivm_wmi_probe");
    expect(r?.severity).toBe("Medium");
    expect(r?.mitre).toContain("T1497.001");
  });

  it("matches ComputerSystem before BIOS too", () => {
    expect(ruleIds("gwmi Win32_ComputerSystem; gwmi Win32_BIOS", "commandLine")).toContain(
      "win_antivm_wmi_probe",
    );
  });

  it("does not match a lone Win32_BIOS query", () => {
    expect(ruleIds("Get-WmiObject Win32_BIOS | Select SerialNumber")).not.toContain("win_antivm_wmi_probe");
  });
});

describe("win_av_product_discovery", () => {
  it("grades the SecurityCenter2 AntiVirusProduct query Medium with T1518.001", () => {
    const r = tagged("Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct");
    expect(r?.ruleIds).toContain("win_av_product_discovery");
    expect(r?.severity).toBe("Medium");
    expect(r?.mitre).toContain("T1518.001");
  });

  it("does not match Get-MpComputerStatus", () => {
    expect(ruleIds("Get-MpComputerStatus")).not.toContain("win_av_product_discovery");
  });
});

describe("win_installed_software_enum", () => {
  it("grades the remote Uninstall-key walk Medium with T1518", () => {
    const r = tagged(
      "$k = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)\n" +
        "$u = $k.OpenSubKey('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall')\n" +
        "$u.GetSubKeyNames() | % { $u.OpenSubKey($_).GetValue('DisplayName') }",
    );
    expect(r?.ruleIds).toContain("win_installed_software_enum");
    expect(r?.severity).toBe("Medium");
    expect(r?.mitre).toContain("T1518");
  });

  it("does not match a plain registry read of one Uninstall entry", () => {
    expect(
      ruleIds(
        "Registry value set: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ExampleApp\\DisplayName by msiexec.exe",
      ),
    ).not.toContain("win_installed_software_enum");
  });
});

describe("win_api_lookup_pinvoke", () => {
  const block =
    'Add-Type -TypeDefinition @"\nusing System.Runtime.InteropServices;\npublic class N {\n' +
    '  [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]\n' +
    '  public static extern int NetWkstaGetInfo(string s, int l, out System.IntPtr b);\n}\n"@';

  it("adds T1082 / T1033 and sets no severity of its own", () => {
    const r = tagged(block);
    expect(r?.ruleIds).toContain("win_api_lookup_pinvoke");
    expect(r?.mitre).toEqual(expect.arrayContaining(["T1082", "T1033"]));
    const own = runTagger([ev({ id: "x", message: block })], RULES).perRule.find(
      (p) => p.id === "win_api_lookup_pinvoke",
    );
    expect(own?.severity).toBeUndefined();
  });

  it("never lowers an existing Medium", async () => {
    const row = ev({ id: "m1", severity: "Medium", message: block });
    const applied = await runAndApplyTagger({
      caseId: "c1",
      events: [row],
      ruleset: RULES,
      forensicTimeline: [row],
      tagsStore: { load: async () => [], add: async () => undefined, addMany: async () => [] } as never,
      mutateForensic: true,
    });
    expect(applied.forensicTimeline[0].severity).toBe("Medium");
    expect(applied.forensicTimeline[0].mitreTechniques).toEqual(expect.arrayContaining(["T1082", "T1033"]));
  });

  it("does not match Add-Type -AssemblyName System.Drawing", () => {
    expect(ruleIds("Add-Type -AssemblyName System.Drawing")).not.toContain("win_api_lookup_pinvoke");
  });
});

describe("promotion window", () => {
  const tagsStore = { load: async () => [], add: async () => undefined, addMany: async () => [] } as never;

  it("an Info ADS-exec row tagged in its own import window survives demote", async () => {
    const row = ev({ id: "ads1", commandLine: ADS_PIPE });
    const applied = await runAndApplyTagger({
      caseId: "c1",
      events: [row],
      ruleset: RULES,
      forensicTimeline: [row],
      tagsStore,
      mutateForensic: true,
    });
    expect(applied.forensicTimeline[0].severity).toBe("High");
    expect(demoteBelowSeverity(applied.forensicTimeline, "Low").kept).toHaveLength(1);
  });

  it("a Medium discovery row clears the default Low floor", async () => {
    const row = ev({ id: "av1", message: "gwmi -Namespace root/SecurityCenter2 -Class AntiVirusProduct" });
    const applied = await runAndApplyTagger({
      caseId: "c1",
      events: [row],
      ruleset: RULES,
      forensicTimeline: [row],
      tagsStore,
      mutateForensic: true,
    });
    expect(demoteBelowSeverity(applied.forensicTimeline, "Low").kept).toHaveLength(1);
  });
});
