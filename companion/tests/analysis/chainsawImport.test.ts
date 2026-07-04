import { describe, it, expect } from "vitest";
import { parseChainsawReport } from "../../src/analysis/chainsawImport.js";

// ── A Chainsaw hunt detection: a Sigma rule matched on an embedded Sysmon process-create.
function sigmaPowershell(): object {
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
            Hashes: "SHA256=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899,MD5=00112233445566778899aabbccddeeff",
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
    expect(e.severity).toBe("High");                 // Sigma high (≥ the EVTX-derived Medium)
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
    (b as any).rule = { name: "Office Spawning PowerShell", level: "critical", tags: ["attack.t1059"] };
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
    const r = parseChainsawReport(JSON.stringify([
      { group: "Antivirus", kind: "individual", name: "Defender Threat", level: "high", tags: ["attack.t1204"], timestamp: "2023-01-02T11:00:00Z" },
    ]));
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
    expect(e.severity).toBe("Medium");        // 4625 failed logon
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
    Computer: "WIN-UK1GV882OK6",
    Channel: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    EventID: 2097,
    SystemData: {
      EventID: 2097,
      Level: 4,
      Provider_attributes: { Name: "Microsoft-Windows-Windows Firewall With Advanced Security" },
      TimeCreated_attributes: { SystemTime: "2025-12-05T02:43:41.735285Z" },
      EventRecordID: 229,
      Channel: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
      Computer: "WIN-UK1GV882OK6",
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
    Computer: "WIN-UK1GV882OK6",
    Channel: "Microsoft-Windows-User Profile Service/Operational",
    EventID: 5,
    SystemData: {
      EventID: 5,
      Provider_attributes: { Name: "Microsoft-Windows-User Profiles Service" },
      TimeCreated_attributes: { SystemTime: "2025-12-05T02:41:39.012742Z" },
      Computer: "WIN-UK1GV882OK6",
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
    expect(e.description).toContain("Chainsaw/Sigma: Uncommon New Firewall Rule Added In Windows Firewall Exception List");
    expect(e.severity).toBe("Medium");
    expect(e.asset).toBe("WIN-UK1GV882OK6");
    expect(e.sources).toEqual(["Chainsaw"]);
    expect(e.timestamp).toBe("2025-12-05T02:43:41.735285Z"); // the event's own EventTime
  });

  it("keeps an Info-graded flat detection (no verdict bump) but still tags it Chainsaw", () => {
    const r = parseChainsawReport(JSON.stringify([flatInfoRdsEvent()]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].description).toContain("Chainsaw/Microsoft RDS Events - User Profile Disk: User Profile Disk - Registry file loaded");
  });

  it("reads NDJSON of the flat shape and aggregates per distinct rule", () => {
    const text = [JSON.stringify(flatSigmaFirewallRule()), JSON.stringify(flatInfoRdsEvent())].join("\n");
    const r = parseChainsawReport(text);
    expect(r.detections).toBe(2);
    expect(r.events).toHaveLength(2);
    expect(r.hostname).toBe("WIN-UK1GV882OK6");
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
    expect(r.events).toHaveLength(1);                 // the Low 4624 dropped
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
