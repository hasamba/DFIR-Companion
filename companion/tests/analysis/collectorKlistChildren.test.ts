// The collector's klist collection reaches its own children (#1699).
//
// On INC-2026-014 the Velociraptor client ran its inline klist artifact: a SYSTEM powershell.exe
// that captures `(& klist sessions 2>&1 | Out-String)`, then runs `cmd.exe /c "klist -li 0x<id>"` per
// logon session. Rule 2d (#1593) graded the PowerShell row Info, but claims it ALONE, so the cmd.exe
// child stayed Medium ("Elevated System Shell Spawned") and synthesis reported "Kerberos ticket
// enumeration" (T1558) in the attacker path.
//
// The new lineage is deliberately narrow: only the klist artifact's script seeds it, only an exact
// klist command in the Windows system directory is claimed, and only by process GUID. Every claim
// lowers a grade, so the refusals below matter more than the match.
import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { SPAWNED_CHILD_NOTE } from "../../src/analysis/collectorChildren.js";

const HOST = "DESKTOP-16OJFO6";
const SYSTEM = "NT AUTHORITY\\SYSTEM";
const T0 = "2026-09-26T13:13:10.493Z";
const plus = (seconds: number): string => new Date(Date.parse(T0) + seconds * 1000).toISOString();

const SCRIPT_GUID = "6FEF6725-C4E6-6AB7-D201-000000000A00";
const CMD_GUID = "6FEF6725-C4EC-6AB7-D801-000000000A00";
const KLIST_LI_GUID = "6FEF6725-C4EC-6AB7-D901-000000000A00";
const KLIST_SESSIONS_GUID = "6FEF6725-C4EB-6AB7-D601-000000000A00";
const OTHER_GUID = "6FEF6725-1111-6AB7-0001-000000000A00";

const VELO_EXE = "C:\\Program Files\\Velociraptor\\Velociraptor.exe";
const VELO_CMD = `"${VELO_EXE}"  --config "C:\\Program Files\\Velociraptor\\/client.config.yaml" service run `;
const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
// The two inline scripts as the INC-2026-014 rows show them (abridged after the capture idiom).
const SESSIONS_SCRIPT =
  'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$ErrorActionPreference=\\"SilentlyContinue\\";function gf($b,$pat){$m=[regex]::Match($b,$pat);if($m.Success){$m.Groups[1].Value.Trim()}else{$null}};$sess=(& klist sessions 2>&1 | Out-String);$out=@();$lines=$sess -split \\"`r?`n\\";$out | ConvertTo-Json"';
const TICKETS_SCRIPT =
  'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$ErrorActionPreference=\\"SilentlyContinue\\";$txt=(& klist 2>&1 | Out-String);$logon=\\"0x0\\";$out | ConvertTo-Json"';
const OTHER_INLINE_SCRIPT =
  'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-Service | ConvertTo-Json"';

interface ProcOver {
  time?: string;
  guid?: string;
  parentGuid?: string;
  user?: string;
  severity?: string;
  detection?: string;
}

function processRow(
  image: string,
  commandLine: string,
  parentImage: string,
  parentCommandLine: string,
  defaults: { guid: string; parentGuid: string; time: string; detection: string; severity: string },
  over: ProcOver = {},
): object {
  const time = over.time ?? defaults.time;
  return {
    EventTime: time,
    Detection: over.detection ?? defaults.detection,
    Severity: over.severity ?? defaults.severity,
    Status: "test",
    "Rule Group": "Sigma",
    Computer: HOST,
    Channel: "Microsoft-Windows-Sysmon/Operational",
    EventID: 1,
    _User: null,
    SystemData: {
      Channel: "Microsoft-Windows-Sysmon/Operational",
      Computer: HOST,
      EventID: 1,
      EventRecordID: 1,
      Execution_attributes: { ProcessID: 3556, ThreadID: 1 },
      Security_attributes: { UserID: "S-1-5-18" },
      TimeCreated_attributes: { SystemTime: time },
    },
    EventData: {
      UtcTime: time,
      Image: image,
      CommandLine: commandLine,
      IntegrityLevel: "System",
      ParentImage: parentImage,
      ParentCommandLine: parentCommandLine,
      ParentProcessId: 1000,
      ProcessId: 2000,
      ...(over.guid !== "" ? { ProcessGuid: over.guid ?? defaults.guid } : {}),
      ...(over.parentGuid !== "" ? { ParentProcessGuid: over.parentGuid ?? defaults.parentGuid } : {}),
      User: over.user ?? SYSTEM,
    },
  };
}

// Velociraptor.exe → SYSTEM powershell.exe running the klist artifact (rule 2d claims this row).
function script(over: ProcOver & { cmd?: string } = {}): object {
  return processRow(
    PS,
    over.cmd ?? SESSIONS_SCRIPT,
    VELO_EXE,
    VELO_CMD,
    {
      guid: SCRIPT_GUID,
      parentGuid: "6FEF6725-4738-6AB1-A701-000000000A00",
      time: T0,
      detection: "Non Interactive PowerShell Process Spawned",
      severity: "medium",
    },
    over,
  );
}

// powershell.exe → cmd.exe /c "klist -li 0x3009c" (Medium "Elevated System Shell Spawned").
function cmdChild(over: ProcOver & { image?: string; cmd?: string } = {}): object {
  return processRow(
    over.image ?? "C:\\Windows\\System32\\cmd.exe",
    over.cmd ?? '"C:\\WINDOWS\\system32\\cmd.exe" /c "klist -li 0x3009c"',
    PS,
    SESSIONS_SCRIPT,
    {
      guid: CMD_GUID,
      parentGuid: SCRIPT_GUID,
      time: plus(5.6),
      detection: "Elevated System Shell Spawned",
      severity: "medium",
    },
    over,
  );
}

// cmd.exe → klist.exe -li 0x3009c.
function klistLi(over: ProcOver & { image?: string; cmd?: string } = {}): object {
  return processRow(
    over.image ?? "C:\\Windows\\System32\\klist.exe",
    over.cmd ?? "klist  -li 0x3009c",
    "C:\\Windows\\System32\\cmd.exe",
    '"C:\\WINDOWS\\system32\\cmd.exe" /c "klist -li 0x3009c"',
    { guid: KLIST_LI_GUID, parentGuid: CMD_GUID, time: plus(5.7), detection: "Proc Exec", severity: "low" },
    over,
  );
}

// powershell.exe → klist.exe sessions.
function klistSessions(over: ProcOver & { cmd?: string } = {}): object {
  return processRow(
    "C:\\Windows\\System32\\klist.exe",
    over.cmd ?? '"C:\\WINDOWS\\system32\\klist.exe" sessions',
    PS,
    SESSIONS_SCRIPT,
    {
      guid: KLIST_SESSIONS_GUID,
      parentGuid: SCRIPT_GUID,
      time: plus(5.3),
      detection: "Proc Exec",
      severity: "low",
    },
    over,
  );
}

const CMD = "C:\\Windows\\System32\\cmd.exe";
const KLIST = "C:\\Windows\\System32\\klist.exe";

type Ev = { description: string; severity: string; origin?: string };
const velo = (rows: object[]): Ev[] =>
  parseVelociraptorJson(JSON.stringify({ "Windows.EventLogs.Chainsaw": rows }), { aggregate: false }).events;
// The row whose OWN image is `image` (not a ParentImage), optionally narrowed by a command fragment.
const one = (events: Ev[], image: string, fragment = ""): Ev => {
  const hits = events.filter(
    (e) =>
      e.description.includes(`(EID 1) - Image=${image} - CommandLine=`) && e.description.includes(fragment),
  );
  expect(hits).toHaveLength(1);
  return hits[0];
};
const expectCollector = (e: Ev) => {
  expect(e.severity).toBe("Info");
  expect(e.origin).toBe("collector");
  expect(e.description).toContain(SPAWNED_CHILD_NOTE.trim());
};
const expectKept = (e: Ev, severity: string) => {
  expect(e.severity).toBe(severity);
  expect(e.origin).not.toBe("collector");
};

describe("the collector's klist collection claims its own children (#1699)", () => {
  it("grades the cmd.exe /c klist -li child, its klist.exe and the klist sessions child as the collector's", () => {
    const events = velo([script(), klistSessions(), cmdChild(), klistLi()]);
    expectCollector(one(events, CMD));
    expectCollector(one(events, KLIST, "-li 0x3009c"));
    expectCollector(one(events, KLIST, "sessions"));
  });

  it("also follows the second script, the one that captures a bare klist", () => {
    const events = velo([script({ cmd: TICKETS_SCRIPT }), cmdChild()]);
    expectCollector(one(events, CMD));
  });

  it("does not depend on input order — the grandchild may come first", () => {
    const events = velo([klistLi(), cmdChild(), script()]);
    expectCollector(one(events, CMD));
    expectCollector(one(events, KLIST, "-li 0x3009c"));
  });
});

describe("the klist lineage refuses everything else (#1699)", () => {
  it("keeps a cmd.exe child of the klist script that runs another command", () => {
    const events = velo([script(), cmdChild({ cmd: '"C:\\WINDOWS\\system32\\cmd.exe" /c "whoami /all"' })]);
    expectKept(one(events, CMD, "whoami /all"), "Medium");
  });

  it("keeps a klist command with extra arguments or a shell operator", () => {
    for (const cmd of [
      '"C:\\WINDOWS\\system32\\cmd.exe" /c "klist -li 0x3009c & whoami"',
      '"C:\\WINDOWS\\system32\\cmd.exe" /c "klist -li 0x3009c > C:\\Users\\Public\\t.txt"',
      '"C:\\WINDOWS\\system32\\cmd.exe" /c "klist -li 0x3009c purge"',
      '"C:\\WINDOWS\\system32\\cmd.exe" /c "klist -li 0x12345678901234567"',
      '"C:\\WINDOWS\\system32\\cmd.exe" /c "klist tgt"',
    ]) {
      const events = velo([script(), cmdChild({ cmd })]);
      expectKept(one(events, CMD), "Medium");
    }
  });

  it("keeps a cmd.exe or klist.exe lookalike outside the system directory", () => {
    const events = velo([
      script(),
      cmdChild({
        image: "C:\\Users\\Public\\cmd.exe",
        cmd: '"C:\\Users\\Public\\cmd.exe" /c "klist -li 0x3009c"',
      }),
    ]);
    expectKept(one(events, "C:\\Users\\Public\\cmd.exe"), "Medium");
    const klist = velo([
      script(),
      klistSessions({ guid: OTHER_GUID }),
      processRow("C:\\Users\\Public\\klist.exe", "klist sessions", PS, SESSIONS_SCRIPT, {
        guid: KLIST_LI_GUID,
        parentGuid: SCRIPT_GUID,
        time: plus(6),
        detection: "Proc Exec",
        severity: "low",
      }),
    ]);
    const lookalike = one(klist, "C:\\Users\\Public\\klist.exe");
    expect(lookalike.severity).not.toBe("Info");
    expect(lookalike.origin).not.toBe("collector");
  });

  it("keeps a klist child whose parent is not the klist script", () => {
    const events = velo([script(), cmdChild({ parentGuid: OTHER_GUID })]);
    expectKept(one(events, CMD), "Medium");
  });

  it("keeps a klist child of another inline collector script (rule 2d still claims that script alone)", () => {
    const events = velo([script({ cmd: OTHER_INLINE_SCRIPT }), cmdChild()]);
    expectKept(one(events, CMD), "Medium");
  });

  it("keeps a child with no parent GUID — there is no pid fallback", () => {
    const events = velo([script(), cmdChild({ parentGuid: "" })]);
    expectKept(one(events, CMD), "Medium");
  });

  it("keeps a child dated before the script", () => {
    const events = velo([script(), cmdChild({ time: plus(-60) })]);
    expectKept(one(events, CMD), "Medium");
  });

  it("keeps a child that did not run as SYSTEM", () => {
    const events = velo([script(), cmdChild({ user: `${HOST}\\vagrant` })]);
    expectKept(one(events, CMD), "Medium");
  });

  it("does not seed from a Critical script", () => {
    const events = velo([script({ severity: "critical" }), cmdChild()]);
    expectKept(one(events, CMD), "Medium");
  });

  it("keeps a Critical cmd.exe child Critical, and it vouches for nothing below it", () => {
    const events = velo([script(), cmdChild({ severity: "critical" }), klistLi()]);
    expectKept(one(events, CMD), "Critical");
    expectKept(one(events, KLIST, "-li 0x3009c"), "Low");
  });
});

describe("the klist lineage reads one envelope (#1699, Codex review)", () => {
  // A row whose top-level EventData links to the klist script while its embedded record says something
  // else. The ledger must not read the command from one record and the parent GUID from another.
  function forked(row: object, embedded: Record<string, unknown>): object {
    const r = row as { SystemData: Record<string, unknown>; EventData: Record<string, unknown> };
    return { ...r, _Event: { System: { ...r.SystemData }, EventData: { ...r.EventData, ...embedded } } };
  }

  it("keeps a klist child whose embedded record disagrees with its top-level EventData", () => {
    const events = velo([script(), forked(cmdChild(), { ParentProcessGuid: OTHER_GUID })]);
    expectKept(one(events, CMD), "Medium");
  });

  it("does not seed from a klist script whose envelope disagrees", () => {
    const events = velo([forked(script(), { ProcessGuid: OTHER_GUID }), cmdChild()]);
    expectKept(one(events, CMD), "Medium");
  });
});
