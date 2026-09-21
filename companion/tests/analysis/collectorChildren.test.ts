// The collector's footprint follows the process it spawned (#1500).
//
// On INC-2026-033 the collector's PersistenceSniper run was graded Info where a row named the
// collector (the spawn, the module's script blocks) and left at grade everywhere else: the
// `Add-Type` DLL drops the spawned PowerShell wrote to SystemTemp (Sysmon EID 11), the `net.exe
// users` it ran (EID 1) and `net1.exe` under that, and — on the Velociraptor hunt path — a path-less
// script block of the same process. Those became findings f13 and half of f7.
//
// Every claim here lowers a grade, so the refusals matter more than the matches: a child that did
// not run as SYSTEM, a child whose parent GUID is not a claimed process, a row before its owner was
// created, another host, a Critical.
import { describe, it, expect } from "vitest";
import { parseChainsawReport } from "../../src/analysis/chainsawImport.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { SPAWNED_CHILD_NOTE } from "../../src/analysis/collectorChildren.js";
import { SPAWNED_SCRIPT_NOTE } from "../../src/analysis/collectorLineage.js";
import { applyToForensicEvent } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// The 033 rows, as the Chainsaw artifact streams them (flat verdict + SystemData + EventData).
const HOST = "DESKTOP-16OJFO6";
const TOOLS = "C:\\Program Files\\Velociraptor\\Tools\\tmp15148342";
const SPAWN_TIME = "2026-09-21T15:08:06.679Z";
const SPAWN_PID = 5580;
const SPAWN_GUID = "6FEF6725-4856-6AB1-F501-000000000A00";
const NET_GUID = "6FEF6725-4862-6AB1-FC01-000000000A00";
const NET1_GUID = "6FEF6725-4862-6AB1-FD01-000000000A00";
const OTHER_GUID = "6FEF6725-1111-6AB1-0001-000000000A00";
const SYSTEM = "NT AUTHORITY\\SYSTEM";
const SYSTEM_SID = "S-1-5-18";
const plus = (seconds: number): string => new Date(Date.parse(SPAWN_TIME) + seconds * 1000).toISOString();

function flatRow(
  eid: number,
  time: string,
  detection: string,
  severity: string,
  eventData: Record<string, unknown>,
  over: { computer?: string; execPid?: number; sid?: string } = {},
): object {
  const computer = over.computer ?? HOST;
  return {
    EventTime: time,
    Detection: detection,
    Severity: severity,
    Status: "test",
    "Rule Group": "Sigma",
    Computer: computer,
    Channel:
      eid === 4104 ? "Microsoft-Windows-PowerShell/Operational" : "Microsoft-Windows-Sysmon/Operational",
    EventID: eid,
    _User: null,
    SystemData: {
      Channel:
        eid === 4104 ? "Microsoft-Windows-PowerShell/Operational" : "Microsoft-Windows-Sysmon/Operational",
      Computer: computer,
      EventID: eid,
      EventRecordID: 1,
      Execution_attributes: { ProcessID: over.execPid ?? 3556, ThreadID: 1 },
      Security_attributes: { UserID: over.sid ?? SYSTEM_SID },
      TimeCreated_attributes: { SystemTime: time },
    },
    EventData: eventData,
  };
}

function spawn(
  over: { guid?: string; pid?: number; time?: string; computer?: string; severity?: string } = {},
): object {
  const time = over.time ?? SPAWN_TIME;
  return flatRow(
    1,
    time,
    "Non Interactive PowerShell Process Spawned",
    over.severity ?? "medium",
    {
      UtcTime: time,
      CommandLine: `powershell -ExecutionPolicy bypass -command "import-module \\"${TOOLS}\\PersistenceSniper\\PersistenceSniper.psm1\\"; Find-AllPersistence"`,
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      IntegrityLevel: "System",
      ParentCommandLine:
        '"C:\\Program Files\\Velociraptor\\Velociraptor.exe"  --config "C:\\Program Files\\Velociraptor\\/client.config.yaml" service run ',
      ParentImage: "C:\\Program Files\\Velociraptor\\Velociraptor.exe",
      ParentProcessId: 8420,
      ParentUser: SYSTEM,
      ...(over.guid !== ""
        ? { ProcessGuid: over.guid ?? SPAWN_GUID, ParentProcessGuid: "6FEF6725-4738-6AB1-A701-000000000A00" }
        : {}),
      ProcessId: over.pid ?? SPAWN_PID,
      User: SYSTEM,
    },
    { computer: over.computer },
  );
}

// The `Add-Type` compile artefact the spawned PowerShell wrote (Sysmon EID 11, Medium by Sigma).
function dllDrop(
  over: {
    guid?: string;
    pid?: number;
    time?: string;
    user?: string;
    computer?: string;
    severity?: string;
  } = {},
): object {
  const time = over.time ?? plus(11);
  return flatRow(
    11,
    time,
    "Potential Binary Or Script Dropper Via PowerShell",
    over.severity ?? "medium",
    {
      UtcTime: time,
      Image: "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      ...(over.guid !== "" ? { ProcessGuid: over.guid ?? SPAWN_GUID } : {}),
      ProcessId: over.pid ?? SPAWN_PID,
      TargetFilename: "C:\\Windows\\SystemTemp\\3wkchge1\\3wkchge1.dll",
      User: over.user ?? SYSTEM,
    },
    { computer: over.computer },
  );
}

// `net.exe users` under the spawn, and `net1 users` under that (Sysmon EID 1, Low by Sigma).
function netChild(
  over: {
    guid?: string;
    parentGuid?: string;
    pid?: number;
    parentPid?: number;
    time?: string;
    user?: string;
    computer?: string;
    severity?: string;
  } = {},
): object {
  const time = over.time ?? plus(12);
  return flatRow(
    1,
    time,
    "Local Accounts Discovery",
    over.severity ?? "low",
    {
      UtcTime: time,
      CommandLine: '"C:\\WINDOWS\\system32\\net.exe" users',
      Image: "C:\\Windows\\System32\\net.exe",
      IntegrityLevel: "System",
      ParentCommandLine: `powershell -ExecutionPolicy bypass -command "import-module \\"${TOOLS}\\PersistenceSniper\\PersistenceSniper.psm1\\""`,
      ParentImage: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      ParentProcessId: over.parentPid ?? SPAWN_PID,
      ...(over.guid !== "" ? { ProcessGuid: over.guid ?? NET_GUID } : {}),
      ...(over.parentGuid !== "" ? { ParentProcessGuid: over.parentGuid ?? SPAWN_GUID } : {}),
      ProcessId: over.pid ?? 6012,
      User: over.user ?? SYSTEM,
    },
    { computer: over.computer },
  );
}

function net1Grandchild(over: { guid?: string; parentGuid?: string; time?: string } = {}): object {
  const time = over.time ?? plus(12.1);
  return flatRow(1, time, "Local Accounts Discovery", "low", {
    UtcTime: time,
    CommandLine: "C:\\WINDOWS\\system32\\net1 users",
    Image: "C:\\Windows\\System32\\net1.exe",
    IntegrityLevel: "System",
    ParentCommandLine: '"C:\\WINDOWS\\system32\\net.exe" users',
    ParentImage: "C:\\Windows\\System32\\net.exe",
    ParentProcessId: 6012,
    ...(over.guid !== "" ? { ProcessGuid: over.guid ?? NET1_GUID } : {}),
    ...(over.parentGuid !== "" ? { ParentProcessGuid: over.parentGuid ?? NET_GUID } : {}),
    ProcessId: 5344,
    User: SYSTEM,
  });
}

// A path-less SYSTEM script block of the spawned process (the cdxml module it imported).
function pathlessBlock(over: { pid?: number; time?: string } = {}): object {
  const time = over.time ?? plus(25);
  return flatRow(
    4104,
    time,
    "Powershell Create Scheduled Task",
    "medium",
    {
      MessageNumber: 1,
      MessageTotal: 1,
      ScriptBlockId: "88fae63e-7c27-4ecc-a97f-002d787157c8",
      ScriptBlockText:
        "Find-AllPersistence -IncludeHighFalsePositivesChecks | ConvertTo-CSV -NoTypeInformation",
    },
    { execPid: over.pid ?? SPAWN_PID },
  );
}

const chainsaw = (rows: object[]) => parseChainsawReport(JSON.stringify(rows), { aggregate: false });
type Parsed = { events: { description: string; severity: string; origin?: string; timestamp: string }[] };
const byEid = (r: Parsed, eid: number) => r.events.filter((e) => e.description.includes(`(EID ${eid})`));
const byImage = (r: Parsed, image: string) =>
  r.events.filter((e) => e.description.includes(`Image=${image}`));

describe("collector children — Chainsaw export (#1500)", () => {
  it("grades the spawned PowerShell's file drops Info, collector origin, with the note", () => {
    const r = chainsaw([spawn(), dllDrop()]);
    const [drop] = byEid(r, 11);
    expect(drop.severity).toBe("Info");
    expect(drop.origin).toBe("collector");
    expect(drop.description).toContain(SPAWNED_CHILD_NOTE.trim());
  });

  it("grades the spawn's child AND grandchild Info by process GUID", () => {
    const r = chainsaw([spawn(), netChild(), net1Grandchild()]);
    const [net] = byImage(r, "C:\\Windows\\System32\\net.exe");
    const [net1] = byImage(r, "C:\\Windows\\System32\\net1.exe");
    expect(net.severity).toBe("Info");
    expect(net.origin).toBe("collector");
    expect(net1.severity).toBe("Info");
    expect(net1.origin).toBe("collector");
  });

  it("does not care in which order the file lists the rows", () => {
    const r = chainsaw([net1Grandchild(), dllDrop(), netChild(), spawn()]);
    for (const e of [
      ...byEid(r, 11),
      ...byImage(r, "C:\\Windows\\System32\\net.exe"),
      ...byImage(r, "C:\\Windows\\System32\\net1.exe"),
    ]) {
      expect(e.severity).toBe("Info");
      expect(e.origin).toBe("collector");
    }
  });

  it("the post-import tagger keeps a claimed child at Info", () => {
    const r = chainsaw([spawn(), netChild()]);
    const [net] = byImage(r, "C:\\Windows\\System32\\net.exe");
    const ev = { ...net, id: "e1", mitreTechniques: [], relatedFindingIds: [] } as unknown as ForensicEvent;
    const next = applyToForensicEvent(ev, {
      eventId: "e1",
      tags: ["t"],
      severity: "High",
      mitre: ["T1087.001"],
      ruleIds: ["r1"],
    });
    expect(next.severity).toBe("Info");
    expect(next.mitreTechniques).toContain("T1087.001");
  });

  it("a claimed child never merges with an attacker's identical command", () => {
    const attacker = netChild({
      guid: OTHER_GUID,
      parentGuid: "6FEF6725-2222-6AB1-0002-000000000A00",
      pid: 7777,
      parentPid: 4242,
      time: plus(600),
      user: "CORP\\bob",
      severity: "low",
    });
    const r = parseChainsawReport(JSON.stringify([spawn(), netChild(), attacker]), { aggregate: true });
    const nets = byImage(r, "C:\\Windows\\System32\\net.exe");
    expect(nets).toHaveLength(2);
    expect(nets.map((e) => e.origin).sort()).toEqual([undefined, "collector"].sort());
    expect(nets.find((e) => e.origin !== "collector")?.severity).toBe("Low");
  });
});

describe("collector children — refusals", () => {
  it("keeps a child that did not run as SYSTEM", () => {
    const r = chainsaw([spawn(), netChild({ user: "DESKTOP-16OJFO6\\vagrant" })]);
    const [net] = byImage(r, "C:\\Windows\\System32\\net.exe");
    expect(net.severity).toBe("Low");
    expect(net.origin).toBeUndefined();
  });

  it("keeps a child whose parent GUID is not a claimed process, whatever its parent pid says", () => {
    const r = chainsaw([spawn(), netChild({ parentGuid: OTHER_GUID, parentPid: SPAWN_PID })]);
    expect(byImage(r, "C:\\Windows\\System32\\net.exe")[0].severity).toBe("Low");
  });

  it("keeps a file drop with the spawn's GUID dated before the spawn", () => {
    const r = chainsaw([spawn(), dllDrop({ time: plus(-5) })]);
    expect(byEid(r, 11)[0].severity).toBe("Medium");
  });

  it("keeps a child on another host", () => {
    const r = chainsaw([spawn(), netChild({ computer: "WS02" })]);
    expect(byImage(r, "C:\\Windows\\System32\\net.exe")[0].severity).toBe("Low");
  });

  it("never lowers a Critical", () => {
    const r = chainsaw([spawn(), dllDrop({ severity: "critical" })]);
    const [drop] = byEid(r, 11);
    expect(drop.severity).toBe("Critical");
    expect(drop.origin).toBeUndefined();
  });

  // A Critical process must not vouch for what it went on to do (Codex, review of #1500).
  it("a Critical spawn seeds no lineage: its children keep their grade", () => {
    const r = chainsaw([spawn({ severity: "critical" }), netChild(), dllDrop()]);
    expect(byImage(r, "C:\\Windows\\System32\\net.exe")[0].severity).toBe("Low");
    expect(byEid(r, 11)[0].severity).toBe("Medium");
  });

  it("a Critical child stays Critical and does not vouch for ITS children", () => {
    const r = chainsaw([spawn(), netChild({ severity: "critical" }), net1Grandchild()]);
    expect(byImage(r, "C:\\Windows\\System32\\net.exe")[0].severity).toBe("Critical");
    expect(byImage(r, "C:\\Windows\\System32\\net1.exe")[0].severity).toBe("Low");
  });

  it("keeps a grandchild whose parent was never claimed", () => {
    const r = chainsaw([spawn(), net1Grandchild()]);
    expect(byImage(r, "C:\\Windows\\System32\\net1.exe")[0].severity).toBe("Low");
  });
});

describe("collector children — a GUID-less export falls back to the spawn's pid and lifetime", () => {
  it("claims a direct child and a file drop by parent pid inside the window", () => {
    const r = chainsaw([spawn({ guid: "" }), netChild({ guid: "", parentGuid: "" }), dllDrop({ guid: "" })]);
    expect(byImage(r, "C:\\Windows\\System32\\net.exe")[0].severity).toBe("Info");
    expect(byEid(r, 11)[0].severity).toBe("Info");
  });

  it("does not follow a pid-claimed child to ITS children", () => {
    const r = chainsaw([
      spawn({ guid: "" }),
      netChild({ guid: "", parentGuid: "" }),
      net1Grandchild({ guid: "", parentGuid: "" }),
    ]);
    expect(byImage(r, "C:\\Windows\\System32\\net1.exe")[0].severity).toBe("Low");
  });

  it("refuses a file drop past the spawn's window", () => {
    const r = chainsaw([spawn({ guid: "" }), dllDrop({ guid: "", time: plus(6 * 60) })]);
    expect(byEid(r, 11)[0].severity).toBe("Medium");
  });

  it("refuses a child whose parent pid was reused by another process first", () => {
    const reuse = netChild({
      guid: "",
      parentGuid: "",
      pid: SPAWN_PID,
      parentPid: 999,
      user: "CORP\\bob",
      time: plus(5),
    });
    const r = chainsaw([spawn({ guid: "" }), reuse, netChild({ guid: "", parentGuid: "", time: plus(10) })]);
    const late = byImage(r, "C:\\Windows\\System32\\net.exe").find((e) =>
      e.timestamp.startsWith(plus(10).slice(0, 19)),
    );
    expect(late?.severity).toBe("Low");
  });
});

describe("collector children — Velociraptor hunt path", () => {
  const velo = (rows: object[]) =>
    parseVelociraptorJson(JSON.stringify({ "Windows.EventLogs.Chainsaw": rows }), { aggregate: false });

  it("grades the children and file drops Info with the collector origin", () => {
    const r = velo([net1Grandchild(), netChild(), dllDrop(), spawn()]);
    for (const e of [
      ...byEid(r, 11),
      ...byImage(r, "C:\\Windows\\System32\\net.exe"),
      ...byImage(r, "C:\\Windows\\System32\\net1.exe"),
    ]) {
      expect(e.severity).toBe("Info");
      expect(e.origin).toBe("collector");
      expect(e.description).toContain(SPAWNED_CHILD_NOTE.trim());
    }
  });

  it("grades a path-less SYSTEM script block of the spawned process Info by pid (#1488, this path)", () => {
    const r = velo([pathlessBlock(), spawn()]);
    const [sb] = byEid(r, 4104);
    expect(sb.severity).toBe("Info");
    expect(sb.origin).toBe("collector");
    expect(sb.description).toContain(SPAWNED_SCRIPT_NOTE.trim());
  });

  it("keeps a path-less block with another pid", () => {
    const r = velo([pathlessBlock({ pid: 4340 }), spawn()]);
    expect(byEid(r, 4104)[0].severity).toBe("Medium");
  });
});
