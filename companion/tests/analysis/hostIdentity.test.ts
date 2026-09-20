import { describe, it, expect } from "vitest";
import { resolveRowHost, withFormerHostSuffix } from "../../src/analysis/hostIdentity.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { parseChainsawReport } from "../../src/analysis/chainsawImport.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";

// #1417 — a Velociraptor hunt row carries two host names. `Fqdn` (with ClientId/FlowId) is the
// collector: the machine the file was read from. `Computer` is the name written INTO the event
// record. When a machine was renamed, its own logs still carry the OLD name on old records. In
// INC-2026-028 a Vagrant-built VM logged its provisioning under the box's baked-in name
// WIN-UK1GV882OK6 while every row said Fqdn=DESKTOP-16OJFO6.localdomain — and the timeline
// grew a phantom second host, a High "lateral movement" finding and a two-host answer.

const COLLECTOR = "DESKTOP-16OJFO6.localdomain";
const FORMER = "WIN-UK1GV882OK6";
const SUFFIX = `[logged under former hostname ${FORMER}]`;
const isRenameMark = (e: { description: string }) => / was named .* until /.test(e.description);

// DetectRaptor.Windows.Detection.Evtx — flat Channel/EventID, `Detection` as an object.
function detectRaptorEvtxRow(over: object = {}): object {
  return {
    EventTime: "2025-12-05T03:02:24Z",
    Computer: FORMER,
    Detection: { Name: "T1059.001-PowerShell Web Request", Regex: "Invoke-WebRequest" },
    Channel: "Microsoft-Windows-PowerShell/Operational",
    EventID: 4104,
    EventData: {
      ScriptBlockText:
        "Invoke-WebRequest -Uri https://community.chocolatey.org/install.ps1 -OutFile install.ps1",
      Path: "C:\\ProgramData\\chocolatey\\install.ps1",
    },
    OSPath: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
    FlowId: "F.DAN767KJHL7PI.H",
    ClientId: "C.ca95aa6d40717a04",
    _OrgId: "root",
    Fqdn: COLLECTOR,
    ...over,
  };
}

// Windows.EventLogs.Chainsaw — the flattened Sigma-mapping shape (verdict at top level).
function chainsawFlatRow(over: object = {}): object {
  return {
    EventTime: "2025-12-05T02:41:39Z",
    Detection: "Security Audit Logs Cleared",
    Severity: "critical",
    "Rule Group": "Log Tampering",
    Computer: FORMER,
    Channel: "Security",
    EventID: "1102",
    SystemData: {
      EventID: 1102,
      Provider_attributes: { Name: "Microsoft-Windows-Eventlog" },
      Computer: FORMER,
    },
    EventData: { SubjectUserName: "vagrant", SubjectDomainName: FORMER },
    FlowId: "F.DAN767KJHL7PI.H",
    ClientId: "C.ca95aa6d40717a04",
    _OrgId: "root",
    Fqdn: COLLECTOR,
    ...over,
  };
}

describe("resolveRowHost — collector identity vs. the name inside the record", () => {
  it("prefers Fqdn and reports the record's Computer as the former name when they differ", () => {
    const rh = resolveRowHost({ Fqdn: COLLECTOR, Computer: FORMER, ClientId: "C.1" });
    expect(rh).toEqual({ asset: COLLECTOR, formerName: FORMER, collectorIdentity: true });
  });

  it("does not call a matching Computer a former name — case and DNS suffix ignored", () => {
    expect(resolveRowHost({ Fqdn: "desktop-ope297n.localdomain", Computer: "DESKTOP-OPE297N" })).toEqual({
      asset: "desktop-ope297n.localdomain",
      collectorIdentity: true,
    });
    expect(resolveRowHost({ Fqdn: "WIN11", Computer: "win11.example.com" })).toEqual({
      asset: "WIN11",
      collectorIdentity: true,
    });
  });

  it("reads the record name from System.Computer / SystemData.Computer when no top-level Computer", () => {
    expect(resolveRowHost({ Fqdn: COLLECTOR, System: { Computer: FORMER } })).toEqual({
      asset: COLLECTOR,
      formerName: FORMER,
      collectorIdentity: true,
    });
    expect(resolveRowHost({ Fqdn: COLLECTOR, SystemData: { Computer: FORMER } }).formerName).toBe(FORMER);
  });

  it("falls back to Hostname as the collector identity", () => {
    expect(resolveRowHost({ Hostname: "H1", Computer: FORMER })).toEqual({
      asset: "H1",
      formerName: FORMER,
      collectorIdentity: true,
    });
  });

  // Windows.EventLogs.CondensedAccountUsage: `ClientName` is the RDP client's workstation — the
  // REMOTE machine — and the artifact writes "-" for a field the event did not carry. Neither is
  // the collector, so the record's Computer stays the asset and nothing is a former name.
  it("ClientName is the remote RDP client, never the collector; '-' is an absent value", () => {
    expect(resolveRowHost({ Computer: "DESKTOP-LAB01", ClientName: "-" })).toEqual({
      asset: "DESKTOP-LAB01",
      collectorIdentity: false,
    });
    expect(resolveRowHost({ Computer: "DESKTOP-LAB01", ClientName: "ATTACKER-PC" })).toEqual({
      asset: "DESKTOP-LAB01",
      collectorIdentity: false,
    });
    expect(resolveRowHost({ Fqdn: "-", Computer: "DESKTOP-LAB01" })).toEqual({
      asset: "DESKTOP-LAB01",
      collectorIdentity: false,
    });
  });

  it("a row with no collector identity keeps Computer as the asset, with no former name", () => {
    expect(resolveRowHost({ Computer: FORMER, Channel: "Security" })).toEqual({
      asset: FORMER,
      collectorIdentity: false,
    });
    expect(resolveRowHost({ System: { Computer: "WS05" } })).toEqual({
      asset: "WS05",
      collectorIdentity: false,
    });
    expect(resolveRowHost({ OSPath: "C:\\x" })).toEqual({ asset: "", collectorIdentity: false });
  });

  it("a ForwardedEvents record names another machine on purpose — keep the record's Computer", () => {
    expect(
      resolveRowHost({
        Fqdn: "WEC01.example.com",
        Computer: "WS-77.example.com",
        Channel: "ForwardedEvents",
      }),
    ).toEqual({ asset: "WS-77.example.com", collectorIdentity: true });
  });

  it("withFormerHostSuffix appends once and respects the 600-char cap", () => {
    expect(withFormerHostSuffix("x", FORMER)).toBe(`x ${SUFFIX}`);
    expect(withFormerHostSuffix("x", undefined)).toBe("x");
    expect(withFormerHostSuffix("y".repeat(700), FORMER)).toHaveLength(600);
  });
});

describe("Velociraptor import — a renamed host's old records stay on the one host (#1417)", () => {
  it("DetectRaptor Evtx row: asset is the collector, severity is not demoted, description says former name", () => {
    const r = parseVelociraptorJson(JSON.stringify([detectRaptorEvtxRow()]), {
      artifact: "DetectRaptor.Windows.Detection.Evtx",
      aggregate: false,
    });
    const rows = r.events.filter((e) => !isRenameMark(e));
    expect(rows).toHaveLength(1); // the rename marker is the only other event
    const e = rows[0];
    expect(e.asset).toBe(COLLECTOR);
    expect(e.severity).not.toBe("Info");
    expect(e.description).toContain(SUFFIX);
    expect(e.description).not.toContain("detection sample corpus");
    expect(r.hostname).toBe(COLLECTOR);
  });

  it("Chainsaw flat row shelled out via Velociraptor: same — one host, verdict intact", () => {
    const r = parseVelociraptorJson(JSON.stringify([chainsawFlatRow()]), {
      artifact: "Windows.EventLogs.Chainsaw",
      aggregate: false,
    });
    const e = r.events[0];
    expect(e.asset).toBe(COLLECTOR);
    expect(e.severity).toBe("Critical");
    expect(e.description).toContain(SUFFIX);
  });

  it("parsed-evtx row with System.Computer under a different Fqdn: collector wins", () => {
    const row = {
      _Source: "Windows.EventLogs.Evtx",
      System: {
        EventID: { Value: 4624 },
        Channel: "Security",
        Computer: FORMER,
        TimeCreated: "2025-12-05T02:00:00Z",
      },
      EventData: {
        TargetUserName: "vagrant",
        TargetDomainName: FORMER,
        IpAddress: "10.0.2.2",
        LogonType: "3",
      },
      Fqdn: COLLECTOR,
      ClientId: "C.ca95aa6d40717a04",
    };
    const e = parseVelociraptorJson(JSON.stringify([row])).events[0];
    expect(e.asset).toBe(COLLECTOR);
    expect(e.description).toContain(SUFFIX);
  });

  it("a row whose Computer matches its Fqdn carries no suffix (the common case is untouched)", () => {
    const e = parseVelociraptorJson(JSON.stringify([detectRaptorEvtxRow({ Computer: "DESKTOP-16OJFO6" })]), {
      artifact: "DetectRaptor.Windows.Detection.Evtx",
      aggregate: false,
    }).events[0];
    expect(e.asset).toBe(COLLECTOR);
    expect(e.description).not.toContain("former hostname");
  });

  it("no collector identity at all: the sample-host demotion still applies (the case it was written for)", () => {
    const bare = { ...detectRaptorEvtxRow(), Fqdn: undefined, ClientId: undefined, FlowId: undefined };
    const e = parseVelociraptorJson(JSON.stringify([bare]), {
      artifact: "DetectRaptor.Windows.Detection.Evtx",
      aggregate: false,
    }).events[0];
    expect(e.asset).toBe(FORMER);
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("sample corpus");
  });

  it("emits one Info marker per import that names the rename and the last time the old name was seen", () => {
    const rows = [
      detectRaptorEvtxRow({ EventTime: "2025-12-05T03:02:24Z" }),
      detectRaptorEvtxRow({ EventTime: "2025-12-05T03:27:07Z", EventID: 4103 }),
      detectRaptorEvtxRow({ EventTime: "2026-08-30T09:00:00Z", Computer: "DESKTOP-16OJFO6" }),
    ];
    const r = parseVelociraptorJson(JSON.stringify(rows), {
      artifact: "DetectRaptor.Windows.Detection.Evtx",
      aggregate: false,
      minSeverity: "Info",
    });
    const marks = r.events.filter(isRenameMark);
    expect(marks).toHaveLength(1);
    expect(marks[0].asset).toBe(COLLECTOR);
    expect(marks[0].severity).toBe("Info");
    expect(marks[0].description).toContain("2025-12-05T03:27:07");
    expect(marks[0].timestamp).toContain("2025-12-05T03:27:07");
  });
});

describe("Chainsaw import — a Velociraptor Chainsaw hunt file routed to the Chainsaw importer", () => {
  it("flat row with Fqdn: asset is the collector, Critical survives, former name noted", () => {
    const r = parseChainsawReport(JSON.stringify([chainsawFlatRow()]), { aggregate: false });
    const rows = r.events.filter((e) => !isRenameMark(e));
    expect(rows).toHaveLength(1);
    expect(r.events.filter(isRenameMark)).toHaveLength(1);
    const e = rows[0];
    expect(e.asset).toBe(COLLECTOR);
    expect(e.severity).toBe("Critical");
    expect(e.description).toContain(SUFFIX);
    expect(r.hostname).toBe(COLLECTOR);
  });

  it("bare Chainsaw JSON (no Fqdn/ClientId) with the Vagrant name keeps today's demotion to Info", () => {
    const bare = {
      ...chainsawFlatRow(),
      Fqdn: undefined,
      ClientId: undefined,
      FlowId: undefined,
      _OrgId: undefined,
    };
    const r = parseChainsawReport(JSON.stringify([bare]), { aggregate: false, minSeverity: "Info" });
    const e = r.events.find((x) => x.asset === FORMER)!;
    expect(e).toBeDefined();
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("sample corpus");
  });

  it("nested Chainsaw document with System.Computer under a different Fqdn: collector wins", () => {
    const rec = {
      Fqdn: COLLECTOR,
      ClientId: "C.ca95aa6d40717a04",
      rule: { name: "Failed Logon Burst", level: "critical", tags: ["attack.t1110"] },
      group: "Credential Access",
      timestamp: "2025-12-05T02:41:39Z",
      document: {
        kind: "evtx",
        data: {
          Event: {
            System: {
              Provider: { "#attributes": { Name: "Microsoft-Windows-Security-Auditing" } },
              EventID: 4625,
              Channel: "Security",
              Computer: FORMER,
              TimeCreated: { "#attributes": { SystemTime: "2025-12-05T02:41:39Z" } },
            },
            EventData: {
              TargetUserName: "vagrant",
              TargetDomainName: FORMER,
              IpAddress: "10.0.2.2",
              LogonType: "3",
            },
          },
        },
      },
    };
    const r = parseChainsawReport(JSON.stringify([rec]), { aggregate: false });
    const e = r.events[0];
    expect(e.asset).toBe(COLLECTOR);
    expect(e.severity).toBe("Critical");
  });
});

describe("Hayabusa import — a row that names both the collector and a former Computer", () => {
  it("asset is the collector, the verdict survives, former name noted", () => {
    const row = {
      Timestamp: "2025-12-05 03:02:24.000 +00:00",
      Computer: FORMER,
      Fqdn: COLLECTOR,
      ClientId: "C.ca95aa6d40717a04",
      Channel: "PwSh",
      EventID: 4104,
      Level: "high",
      RuleTitle: "PowerShell Web Download",
      Details: { ScriptBlock: "Invoke-WebRequest -Uri https://community.chocolatey.org/install.ps1" },
    };
    const r = parseHayabusaTimeline(JSON.stringify([row]), { aggregate: false });
    const e = r.events[0];
    expect(e.asset).toBe(COLLECTOR);
    expect(e.severity).toBe("High");
    expect(e.description).toContain(SUFFIX);
    expect(e.description).not.toContain("sample corpus");
  });

  it("bare Hayabusa row with the Vagrant name and no collector identity keeps the demotion", () => {
    const row = {
      Timestamp: "2025-12-05 03:02:24.000 +00:00",
      Computer: FORMER,
      Channel: "PwSh",
      EventID: 4104,
      Level: "high",
      RuleTitle: "PowerShell Web Download",
      Details: { ScriptBlock: "whoami" },
    };
    const r = parseHayabusaTimeline(JSON.stringify([row]), { aggregate: false, minSeverity: "Info" });
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].asset).toBe(FORMER);
  });
});

// A Velociraptor FLOW export (the super-timeline bundle) carries no Fqdn/ClientId per row — a row is
// `{System:{Computer}, EventData}`. The import knows the client anyway (`hostFallback`, the client's
// hostname from the server), so that is the collector identity and an older `Computer` is a former
// name — not a second asset (#1458).
const FLOW_HOST = "DESKTOP-16OJFO6";
const BUILD_NAME = "WIN-0NNTB2RTNB1";

function flowEvtxRow(computer: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    System: {
      Provider: { Name: "Microsoft-Windows-Security-Auditing" },
      EventID: { Value: 4624 },
      Level: 0,
      TimeCreated: { SystemTime: 1756213808.06 },
      EventRecordID: 5150,
      Channel: "Security",
      Computer: computer,
    },
    EventData: {
      TargetUserName: "vagrant",
      TargetDomainName: computer,
      LogonType: 2,
      IpAddress: "127.0.0.1",
    },
    Message: "An account was successfully logged on.",
    _Source: "Windows.EventLogs.Evtx",
    ...over,
  };
}

describe("resolveRowHost — an import-level collector stands in when the row has none (#1458)", () => {
  it("uses the fallback as the collector and reads a differing Computer as the former name", () => {
    expect(resolveRowHost({ System: { Computer: BUILD_NAME } }, undefined, FLOW_HOST)).toEqual({
      asset: FLOW_HOST,
      formerName: BUILD_NAME,
      collectorIdentity: true,
    });
  });

  it("a matching Computer is not a former name; a per-row Fqdn still beats the fallback", () => {
    expect(resolveRowHost({ System: { Computer: "desktop-16ojfo6" } }, undefined, FLOW_HOST)).toEqual({
      asset: FLOW_HOST,
      collectorIdentity: true,
    });
    expect(resolveRowHost({ Fqdn: COLLECTOR, Computer: FORMER }, undefined, "OTHER-BOX")).toEqual({
      asset: COLLECTOR,
      formerName: FORMER,
      collectorIdentity: true,
    });
  });

  it("no fallback and no Fqdn keeps today's behaviour", () => {
    expect(resolveRowHost({ System: { Computer: BUILD_NAME } }, undefined, "")).toEqual({
      asset: BUILD_NAME,
      collectorIdentity: false,
    });
  });
});

describe("Velociraptor flow import — old build names stay on the one client (#1458)", () => {
  it("event-log rows under an old Computer land on the flow's client with the former-name note", () => {
    const r = parseVelociraptorJson(JSON.stringify([flowEvtxRow(BUILD_NAME), flowEvtxRow(FLOW_HOST)]), {
      hostFallback: FLOW_HOST,
    });
    const assets = new Set(r.events.map((e) => e.asset));
    expect(assets.has(BUILD_NAME)).toBe(false);
    expect(assets.has(FLOW_HOST)).toBe(true);
    const old = r.events.find((e) => e.description.includes("former hostname"));
    expect(old?.asset).toBe(FLOW_HOST);
    expect(old?.description).toContain(`[logged under former hostname ${BUILD_NAME}]`);
    expect(r.events.some((e) => e.description.startsWith(`Host ${FLOW_HOST} was named ${BUILD_NAME}`))).toBe(
      true,
    );
  });

  it("a DetectRaptor Evtx detection row (the winRowToFlat path) follows the same rule", () => {
    const row = {
      _Source: "DetectRaptor.Windows.Detection.Evtx",
      EventTime: "2025-12-05T03:02:24Z",
      Computer: BUILD_NAME,
      Detection: { Name: "T1059.001-PowerShell Web Request", EventId: "^4104$", Regex: ".", Ignore: "" },
      Channel: "Microsoft-Windows-PowerShell/Operational",
      EventID: 4104,
      EventData: { ScriptBlockText: "Invoke-WebRequest https://community.chocolatey.org/install.ps1" },
      Message: "Creating Scriptblock text (1 of 1)",
      OSPath: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]), { hostFallback: FLOW_HOST });
    expect(r.events.length).toBeGreaterThan(0);
    for (const e of r.events) expect(e.asset).toBe(FLOW_HOST);
    expect(r.events.some((e) => e.description.includes(`former hostname ${BUILD_NAME}`))).toBe(true);
  });

  it("without a fallback the same rows still stand on their own Computer (bare file)", () => {
    const r = parseVelociraptorJson(JSON.stringify([flowEvtxRow(BUILD_NAME)]));
    expect(r.events.every((e) => e.asset === BUILD_NAME)).toBe(true);
    expect(r.events.some((e) => e.description.includes("former hostname"))).toBe(false);
  });
});
