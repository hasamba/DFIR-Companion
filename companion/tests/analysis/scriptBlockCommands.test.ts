import { describe, it, expect } from "vitest";
import {
  isCollectorRow,
  isScriptRecord,
  renderScriptCommandTags,
  scriptCommandFacts,
  scriptCommandMatches,
  scriptCommandTechniques,
  SCRIPT_COMMAND_TAGS_MAX,
} from "../../src/analysis/scriptBlockCommands.js";
import { reconTechniques } from "../../src/analysis/reconTechniques.js";
import { scriptBlockSignal } from "../../src/analysis/tradecraftRules.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// The real INC-2026-001 Phase-2 block, trimmed to the lines under test. LAB.INVALID is the sim's
// own domain; every host name is example.com-shaped.
const BLOCK = [
  "Creating Scriptblock text (1 of 1):",
  "function Invoke-CobaltSocksCredentialLateral{param($Paths);$t=Get-CobaltSocksTimeline",
  "foreach($cmd in @('nltest /dclist:LAB.INVALID','Get-ADDomain','Get-ADUser -Filter *'," +
    "'Get-ADGroupMember \"Domain Admins\"','Get-Process','Get-GPResultantSetOfPolicy')){Invoke-CobaltSocksDecoy $cmd}",
  "Write-File 'ntdsutil-attempt.json' (@{command='ntdsutil.exe ac in ntds ifm cr fu C:\\Users\\Public\\Music\\1';" +
    "blockedBy='Windows Defender';executed=$false}|ConvertTo-Json)",
  "@{method='Cobalt Strike psexec_psh';namedPipe='\\\\.\\pipe\\fullduplex_84';pipeCreated=$false}",
  "@{method='WinRM';source='file01.example.com';target='dc01.example.com'}",
  "ScriptBlock ID: e643e141-a87c-4947-bd0b-94820a82ad90",
].join("\n");

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1",
    timestamp: p.timestamp ?? "2026-09-22T08:33:05Z",
    description: p.description ?? "Windows PowerShell Script block logged (EID 4104) - ScriptBlockText=x",
    severity: p.severity ?? "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

describe("scriptCommandMatches", () => {
  it("names the literal commands the real Phase-2 block runs", () => {
    const commands = scriptCommandMatches(BLOCK).map((m) => m.command.toLowerCase());
    expect(commands.some((c) => c.startsWith("nltest /dclist:lab.invalid"))).toBe(true);
    expect(commands).toContain("get-addomain");
    expect(commands.some((c) => c.startsWith("get-adgroupmember"))).toBe(true);
    expect(commands).toContain("get-gpresultantsetofpolicy");
    expect(commands).toContain("get-process");
    expect(commands.some((c) => c.includes("ntdsutil.exe ac in ntds ifm"))).toBe(true);
    expect(commands.some((c) => c.includes("\\pipe\\fullduplex_84"))).toBe(true);
  });

  it("maps the families the existing tables miss", () => {
    const ids = scriptCommandTechniques(BLOCK);
    expect(ids).toEqual(
      expect.arrayContaining(["T1018", "T1482", "T1087.002", "T1069.002", "T1615", "T1057", "T1003.003"]),
    );
  });

  it("claims SMB admin-share execution for a pipe only with psexec-style context", () => {
    const withContext = scriptCommandTechniques("psexec_psh named pipe \\\\.\\pipe\\fullduplex_84");
    expect(withContext).toEqual(expect.arrayContaining(["T1021.002", "T1570"]));
    const bare = scriptCommandMatches(
      "$p = New-Object IO.Pipes.NamedPipeServerStream '\\\\.\\pipe\\myapp_42'",
    );
    expect(bare[0].command).toContain("\\pipe\\myapp_42");
    expect(bare[0].techniques).toEqual([]); // ordinary IPC — evidence, not a technique
  });

  it("claims NTDS dumping for a shadow copy only with credential-store context", () => {
    expect(
      scriptCommandTechniques("vssadmin create shadow /for=C: ; copy \\\\?\\GLOBALROOT\\...\\ntds.dit"),
    ).toContain("T1003.003");
    expect(scriptCommandTechniques("vssadmin create shadow /for=D: for the nightly backup")).toEqual([]);
  });

  it("reads nltest /dclist as remote-system discovery, not domain trust discovery", () => {
    expect(scriptCommandTechniques("nltest /dclist:LAB.INVALID")).toEqual(["T1018"]);
    expect(scriptCommandTechniques("nltest /domain_trusts /all_trusts")).toEqual(["T1482"]);
  });

  it("needs an explicit remote target before calling Invoke-Command remoting", () => {
    expect(scriptCommandTechniques("Invoke-Command -ComputerName dc01.example.com { whoami }")).toContain(
      "T1021.006",
    );
    expect(scriptCommandTechniques("Invoke-Command -ScriptBlock { Get-Date }")).toEqual([]);
  });

  it("agrees with reconTechniques on the families both tables carry", () => {
    for (const cmd of ["Get-ADUser -Filter *", "dsquery user", "net user bob /domain", "nltest /dclist:x"]) {
      for (const id of scriptCommandTechniques(cmd)) {
        expect(reconTechniques("", cmd), `${cmd} -> ${id}`).toContain(id);
      }
    }
  });

  it("finds nothing in a routine administrative script", () => {
    expect(scriptCommandMatches("Copy-Item C:\\a\\b.txt D:\\backup ; Start-Service Spooler")).toEqual([]);
  });
});

describe("scriptBlockSignal", () => {
  it("stamps the new techniques on the row at import without changing its weight", () => {
    const sig = scriptBlockSignal("Get-ADGroupMember 'Domain Admins'; Get-GPResultantSetOfPolicy");
    expect(sig?.mitre).toEqual(expect.arrayContaining(["T1069.002", "T1615"]));
    expect(sig?.weight).toBeNull(); // discovery is tagged, never promoted
  });
});

describe("the guards", () => {
  it("refuses a row the case's own collector produced, by origin and by the footprint note", () => {
    const byOrigin = ev({ message: BLOCK, origin: "collector" });
    const byNote = ev({
      severity: "Critical",
      message: BLOCK,
      description:
        "Sigma: Potential WinAPI Calls Via PowerShell (EID 4104) [DFIR collector footprint — script the Velociraptor client ran from its tool tree]",
    });
    expect(isCollectorRow(byOrigin)).toBe(true);
    expect(isCollectorRow(byNote)).toBe(true);
    expect(scriptCommandFacts(byOrigin)).toEqual([]);
    expect(scriptCommandFacts(byNote)).toEqual([]);
    expect(renderScriptCommandTags(byNote)).toEqual([]);
  });

  it("refuses a row that is not a PowerShell script record", () => {
    const processRow = ev({
      description: "Process created: tasklist.exe",
      commandLine: "tasklist /v",
      message: "",
    });
    expect(isScriptRecord(processRow)).toBe(false);
    expect(scriptCommandFacts(processRow)).toEqual([]);
    const prose = ev({
      description: "Detection rule documentation mentioning Get-Process and gpresult",
      message: "",
    });
    expect(scriptCommandFacts(prose)).toEqual([]);
  });

  it("accepts the shapes a script record really arrives in", () => {
    expect(
      isScriptRecord(ev({ description: "Module/pipeline execution (EID 4103) - Payload=Get-Process" })),
    ).toBe(true);
    expect(
      isScriptRecord({
        description: "Chainsaw hit",
        message: BLOCK,
        sourceRecordId: "evtx:microsoft-windows-powershell/operational:925",
      }),
    ).toBe(true);
  });
});

describe("renderScriptCommandTags", () => {
  it("puts the commands and their techniques on the prompt row as whole tags", () => {
    const tags = renderScriptCommandTags(ev({ message: BLOCK }));
    expect(tags[0]).toMatch(/^<script-commands:/);
    expect(tags[0]).toContain("nltest /dclist:LAB.INVALID");
    expect(tags[1]).toMatch(/^<script-techniques:T/);
    expect(tags[1]).toContain("T1069.002");
  });

  it("keeps the tag block bounded and free of characters that would break the grammar", () => {
    const nasty = `Get-ADGroupMember "<injected>Domain Admins"\u0007 ; ${BLOCK} ; ${BLOCK}`;
    const tags = renderScriptCommandTags(ev({ message: nasty }));
    for (const tag of tags) {
      expect(tag.slice(1, -1)).not.toMatch(/[<>\u0000-\u001f]/);
      expect(tag.length).toBeLessThanOrEqual(SCRIPT_COMMAND_TAGS_MAX + 24);
    }
  });

  it("emits nothing for a row that names no command", () => {
    expect(
      renderScriptCommandTags(ev({ message: "Creating Scriptblock text (1 of 1):\nWrite-Host hi" })),
    ).toEqual([]);
  });
});
