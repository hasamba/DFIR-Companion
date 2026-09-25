// Collector scripts and normal OS behaviour are not findings (#1593).
//
// The rows are INC-2026-005's shapes, as a Velociraptor Windows.Hayabusa.Rules hunt streams them
// (verdict fields + the parsed record under `_Event`), with synthetic values: the collector's inline
// klist script, powershell.exe's creation handle to its own cmd.exe child, dwm.exe's kernel callback
// thread into csrss.exe, and an App Installer update swapping its firewall rules. All four must grade
// Info and yield no High row. Every rule lowers a grade, so the negatives are the important half —
// first among them the one the issue names: an intruder's powershell.exe opening lsass.exe.
import { describe, expect, it } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { CollectorFootprintLedger } from "../../src/analysis/collectorChildren.js";
import {
  annotateBenignOsActivity,
  isDwmCsrssCallback,
  OS_BEHAVIOUR_MARKER,
} from "../../src/analysis/benignOsActivity.js";
import { isSetAsideRow } from "../../src/analysis/setAsideRows.js";
import { OWN_CHILD_MARKER } from "../../src/analysis/processParentage.js";
import { APPX_FIREWALL_NOTE } from "../../src/analysis/appxFirewallChurn.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";

const HOST = "WS01";
const FQDN = "WS01.example.com";
const SYSMON = "Microsoft-Windows-Sysmon/Operational";
const FIREWALL = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";
const VELO = "C:\\Program Files\\Velociraptor\\Velociraptor.exe";
const PWSH = "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const CMD = "C:\\WINDOWS\\system32\\cmd.exe";
const LSASS = "C:\\WINDOWS\\system32\\lsass.exe";
const DWM = "C:\\Windows\\System32\\dwm.exe";
const CSRSS = "C:\\Windows\\System32\\csrss.exe";
const SVCHOST = "C:\\WINDOWS\\System32\\svchost.exe";
const MPSSVC_SID = "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052";
const T0 = Date.parse("2026-01-15T10:00:00.000Z");

const G = {
  velo: "0A0B0C0D-E831-1111-5903-000000000B00",
  klist: "0A0B0C0D-F414-1111-BD03-000000000B00",
  pwsh: "0A0B0C0D-E4D0-1111-6901-000000000B00",
  cmd: "0A0B0C0D-E598-1111-BF01-000000000B00",
  other: "0A0B0C0D-1111-1111-0001-000000000B00",
  lsass: "0A0B0C0D-E2D1-1111-0C00-000000000B00",
  dwm: "0A0B0C0D-4594-1111-1300-000000000A00",
};

let record = 1;
const iso = (ms: number): string => new Date(ms).toISOString();
const utc = (ms: number): string => iso(ms).replace("T", " ").replace("Z", "");

function row(
  eid: number,
  at: number,
  title: string,
  level: string,
  eventData: Record<string, unknown>,
  channel = SYSMON,
): object {
  const id = record++;
  return {
    Timestamp: iso(at),
    Computer: HOST,
    Channel: channel,
    EID: eid,
    Level: level,
    Title: title,
    RecordID: id,
    Details: "",
    _Event: {
      System: {
        Provider: { Name: channel.split("/")[0] },
        EventID: { Value: eid },
        TimeCreated: { SystemTime: at / 1000 },
        EventRecordID: id,
        Channel: channel,
        Computer: HOST,
        Security: { UserID: "S-1-5-18" },
      },
      EventData: eventData,
    },
    _Source: "Windows.Sigma.Base",
    Fqdn: FQDN,
  };
}

function create(
  at: number,
  image: string,
  cmd: string,
  guid: string,
  parentGuid: string,
  parent: string,
  user: string,
) {
  return row(1, at, "Proc Exec", "informational", {
    UtcTime: utc(at),
    ProcessGuid: guid,
    ProcessId: 5680,
    Image: image,
    CommandLine: cmd,
    User: user,
    ParentProcessGuid: parentGuid,
    ParentProcessId: 5704,
    ParentImage: parent,
    ParentCommandLine: `"${parent}" service run`,
    IntegrityLevel: "System",
  });
}

function access(
  at: number,
  source: string,
  sourceGuid: string,
  target: string,
  targetGuid: string,
  title = "Proc Access",
) {
  return row(10, at, title, "low", {
    UtcTime: utc(at),
    SourceProcessGUID: sourceGuid,
    SourceProcessId: 6892,
    SourceImage: source,
    TargetProcessGUID: targetGuid,
    TargetProcessId: 6612,
    TargetImage: target,
    GrantedAccess: 2097151,
    CallTrace:
      "C:\\WINDOWS\\SYSTEM32\\ntdll.dll+1636d4|C:\\WINDOWS\\System32\\KERNELBASE.dll+96a8a|UNKNOWN(00007FFD677A9EF7)",
    SourceUser: `${HOST}\\vagrant`,
    TargetUser: `${HOST}\\vagrant`,
  });
}

function thread(
  at: number,
  start: { address: string; module?: string; fn?: string },
  source = DWM,
  target = CSRSS,
) {
  return row(8, at, "Proc Injection", "medium", {
    UtcTime: utc(at),
    SourceProcessGuid: G.dwm,
    SourceProcessId: 1076,
    SourceImage: source,
    TargetProcessGuid: G.other,
    TargetProcessId: 692,
    TargetImage: target,
    NewThreadId: 10792,
    StartAddress: start.address,
    StartModule: start.module ?? "-",
    StartFunction: start.fn ?? "-",
    SourceUser: "Window Manager\\DWM-1",
    TargetUser: "NT AUTHORITY\\SYSTEM",
  });
}

function firewall(
  eid: number,
  at: number,
  version: string,
  over: { app?: string; user?: string; ruleId?: string } = {},
) {
  const title =
    eid === 2052
      ? "A Rule Has Been Deleted From The Windows Firewall Exception List"
      : "Uncommon New Firewall Rule Added In Windows Firewall Exception List";
  const name = `@{Microsoft.DesktopAppInstaller_${version}_x64__8wekyb3d8bbwe?ms-resource://Microsoft.DesktopAppInstaller/Resources/appDisplayName}`;
  return row(
    eid,
    at,
    title,
    "medium",
    {
      RuleId: over.ruleId ?? "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe-Out-Allow-InternetClient",
      RuleName: name,
      EmbeddedContext: name,
      Protocol: 6,
      ModifyingUser: over.user ?? MPSSVC_SID,
      ModifyingApplication: over.app ?? SVCHOST,
      ErrorCode: 0,
    },
    FIREWALL,
  );
}

const KLIST_CMD =
  'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$sess=(& klist sessions 2>&1 | Out-String); $out | ConvertTo-Json -Compress"';

function parse(rows: object[]): MappedEvent[] {
  const r = parseVelociraptorJson(JSON.stringify({ "Windows.Hayabusa.Rules": rows }), {
    minSeverity: "Info",
    aggregate: false,
  });
  return r.events as unknown as MappedEvent[];
}

const find = (events: MappedEvent[], re: RegExp): MappedEvent[] =>
  events.filter((e) => re.test(e.description));

describe("#1593 — the INC-2026-005 rows grade Info", () => {
  const events = parse([
    create(T0, PWSH, KLIST_CMD, G.klist, G.velo, VELO, "NT AUTHORITY\\SYSTEM"),
    create(T0 + 5_000, CMD, "cmd.exe /c whoami", G.cmd, G.pwsh, PWSH, `${HOST}\\vagrant`),
    access(T0 + 5_050, PWSH, G.pwsh, CMD, G.cmd),
    thread(T0 + 10_000, { address: "0xFFFFF8076A07D040" }),
    firewall(2052, T0 + 20_000, "1.29.289.0"),
    firewall(2097, T0 + 20_030, "1.29.379.0"),
    // The negative the issue names: an intruder's powershell.exe opening lsass.exe.
    access(T0 + 30_000, PWSH, G.pwsh, LSASS, G.lsass, "Credential Dumping Tools Accessing LSASS Memory"),
  ]);

  it("the collector's inline klist script (SYSTEM, parent Velociraptor.exe) is Info", () => {
    const [klist] = find(events, /klist sessions/);
    expect(klist.severity).toBe("Info");
    expect(klist.origin).toBe("collector");
    expect(isSetAsideRow(klist)).toBe(true);
  });

  it("powershell.exe opening its own cmd.exe child at creation is Info, linked by GUID", () => {
    const [own] = find(events, /EID 10\).*TargetImage=\S*cmd\.exe/);
    expect(own.severity).toBe("Info");
    expect(own.description).toContain(OWN_CHILD_MARKER);
    expect(isSetAsideRow(own)).toBe(true);
  });

  it("dwm.exe's kernel callback thread into csrss.exe is Info", () => {
    const [dwm] = find(events, /EID 8\).*dwm\.exe/);
    expect(dwm.severity).toBe("Info");
    expect(isSetAsideRow(dwm)).toBe(true);
  });

  it("both halves of the App Installer firewall rule swap are Info", () => {
    const fw = find(events, /EID 20(52|97)\)/);
    expect(fw).toHaveLength(2);
    for (const e of fw) {
      expect(e.severity).toBe("Info");
      expect(e.description).toContain(`${OS_BEHAVIOUR_MARKER} ${APPX_FIREWALL_NOTE}]`);
      expect(isSetAsideRow(e)).toBe(true);
    }
  });

  it("NEGATIVE: an intruder's powershell.exe opening lsass.exe still grades High", () => {
    const [lsass] = find(events, /EID 10\).*lsass\.exe/);
    expect(lsass.severity).toBe("High");
  });

  it("nothing but the lsass access is High, so no auto finding comes from the four", () => {
    const high = events.filter((e) => e.severity === "High" || e.severity === "Critical");
    expect(high.map((e) => /lsass/.test(e.description))).toEqual([true]);
  });
});

describe("#1593 — parent-to-child access: the GUID link and its bounds", () => {
  const graded = (rows: object[]): string => find(parse(rows), /EID 10\)/)[0]?.severity ?? "missing";

  it("matches on the GUID link, never on image names: another powershell's cmd.exe keeps its grade", () => {
    expect(
      graded([
        create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.other, PWSH, `${HOST}\\vagrant`),
        access(T0 + 10, PWSH, G.pwsh, CMD, G.cmd),
      ]),
    ).toBe("High");
  });

  it("an access more than a second after the child's creation keeps its grade", () => {
    expect(
      graded([
        create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.pwsh, PWSH, `${HOST}\\vagrant`),
        access(T0 + 5_000, PWSH, G.pwsh, CMD, G.cmd),
      ]),
    ).toBe("High");
  });

  it("conflicting creation records for the child fail closed", () => {
    expect(
      graded([
        create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.pwsh, PWSH, `${HOST}\\vagrant`),
        create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.other, PWSH, `${HOST}\\vagrant`),
        access(T0 + 10, PWSH, G.pwsh, CMD, G.cmd),
      ]),
    ).toBe("High");
  });

  it("no creation record for the child keeps its grade", () => {
    expect(graded([access(T0, PWSH, G.pwsh, CMD, G.cmd)])).toBe("High");
  });

  it("a child that a remote thread or a tampering record in the same import targets keeps its grade", () => {
    const base = [
      create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.pwsh, PWSH, `${HOST}\\vagrant`),
      access(T0 + 10, PWSH, G.pwsh, CMD, G.cmd),
    ];
    const threadInto = row(8, T0 + 50, "Proc Injection", "medium", {
      SourceProcessGuid: G.pwsh,
      SourceImage: PWSH,
      TargetProcessGuid: G.cmd,
      TargetImage: CMD,
      StartAddress: "0x0000000000A10000",
    });
    const tamper = row(25, T0 + 50, "Process Tampering", "high", {
      ProcessGuid: G.cmd,
      Image: CMD,
      Type: "Image is replaced",
    });
    expect(graded([...base, threadInto])).toBe("High");
    expect(graded([tamper, ...base])).toBe("High");
  });

  it("the creation record may arrive after the access (order-independent)", () => {
    expect(
      graded([
        access(T0 + 10, PWSH, G.pwsh, CMD, G.cmd),
        create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.pwsh, PWSH, `${HOST}\\vagrant`),
      ]),
    ).toBe("Info");
  });
});

describe("#1593 — dwm.exe → csrss.exe: only the kernel-callback shape", () => {
  const graded = (rows: object[]): string => find(parse(rows), /EID 8\)/)[0]?.severity ?? "missing";

  it("keeps a user-mode unbacked start, a LoadLibrary start and a boundary-below address", () => {
    expect(graded([thread(T0, { address: "0x00007FF6A1B20000" })])).toMatch(/^(High|Medium)$/);
    expect(
      graded([
        thread(T0, {
          address: "0x00007FFD2C7AC120",
          module: "C:\\Windows\\System32\\KERNEL32.DLL",
          fn: "LoadLibraryW",
        }),
      ]),
    ).toMatch(/^(High|Medium)$/);
    expect(graded([thread(T0, { address: "0xFFFF7FFFFFFFFFFF" })])).toMatch(/^(High|Medium)$/);
    expect(graded([thread(T0, { address: "0xFFFF800000000000" })])).toBe("Info");
  });

  it("keeps a dwm.exe or csrss.exe outside System32, or a traversal path", () => {
    const k = { address: "0xFFFFF8076A07D040" };
    expect(graded([thread(T0, k, "C:\\Users\\Public\\dwm.exe")])).toMatch(/^(High|Medium)$/);
    expect(graded([thread(T0, k, DWM, "C:\\Users\\Public\\csrss.exe")])).toMatch(/^(High|Medium)$/);
    expect(graded([thread(T0, k, "C:\\Windows\\System32\\..\\..\\Users\\x\\dwm.exe")])).toMatch(
      /^(High|Medium)$/,
    );
    expect(graded([thread(T0, k, PWSH)])).toMatch(/^(High|Medium)$/);
  });

  it("is idempotent and never lowers a Critical", () => {
    const [m] = find(parse([thread(T0, { address: "0xFFFFF8076A07D040" })]), /EID 8\)/);
    const once = { ...m, severity: "High" as const, description: m.description, aggKey: m.aggKey };
    annotateBenignOsActivity(once);
    const after = { description: once.description, aggKey: once.aggKey };
    annotateBenignOsActivity(once);
    expect(once.description).toBe(after.description);
    expect(once.aggKey).toBe(after.aggKey);
    const critical = { ...m, severity: "Critical" as const };
    expect(isDwmCsrssCallback(critical)).toBe(true);
    annotateBenignOsActivity(critical);
    expect(critical.severity).toBe("Critical");
  });
});

describe("#1593 — AppX firewall churn: only an update pair", () => {
  const grades = (rows: object[]): string[] => find(parse(rows), /EID 20(52|97)\)/).map((e) => e.severity);

  it("a lone add (first install) or lone delete (uninstall) keeps its grade", () => {
    expect(grades([firewall(2097, T0, "1.29.379.0")])).toEqual(["Medium"]);
    expect(grades([firewall(2052, T0, "1.29.289.0")])).toEqual(["Medium"]);
  });

  it("a same-version pair, a pair far apart, or a different rule ID keeps its grade", () => {
    expect(grades([firewall(2052, T0, "1.29.289.0"), firewall(2097, T0 + 10, "1.29.289.0")])).toEqual([
      "Medium",
      "Medium",
    ]);
    expect(
      grades([firewall(2052, T0, "1.29.289.0"), firewall(2097, T0 + 11 * 60_000, "1.29.379.0")]),
    ).toEqual(["Medium", "Medium"]);
    expect(
      grades([
        firewall(2052, T0, "1.29.289.0"),
        firewall(2097, T0 + 10, "1.29.379.0", {
          ruleId: "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe-In-Allow-Intranet",
        }),
      ]),
    ).toEqual(["Medium", "Medium"]);
  });

  it("a rule changed by netsh, WmiPrvSE or a user SID keeps its grade", () => {
    for (const over of [
      { app: "C:\\Windows\\System32\\netsh.exe" },
      { app: "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" },
      { user: "S-1-5-21-1111111111-2222222222-3333333333-1001" },
      { user: "S-1-5-18" },
      { app: "C:\\Users\\Public\\svchost.exe" },
    ])
      expect(
        grades([firewall(2052, T0, "1.29.289.0", over), firewall(2097, T0 + 10, "1.29.379.0", over)]),
      ).toEqual(["Medium", "Medium"]);
  });

  it("a pair split across bulk batches still meets through the primed ledger", () => {
    const del = firewall(2052, T0, "1.29.289.0") as Record<string, unknown>;
    const add = firewall(2097, T0 + 10, "1.29.379.0") as Record<string, unknown>;
    const mapped = (sev: MappedEvent["severity"]): MappedEvent => ({
      timestamp: iso(T0),
      description: `firewall (EID 2052) @ ${FQDN}`,
      severity: sev,
      mitre: [],
      aggKey: "fw",
      asset: FQDN,
    });
    const ledger = new CollectorFootprintLedger({ servers: new Set() });
    const a = mapped("Medium");
    const b = { ...mapped("Medium"), timestamp: iso(T0 + 10) };
    ledger.prime(del, [a]);
    ledger.prime(add, [b]);
    ledger.offer(del, [a]);
    ledger.resolve(); // batch 1
    expect(a.severity).toBe("Info");
    ledger.offer(add, [b]);
    ledger.resolve(); // batch 2
    expect(b.severity).toBe("Info");
  });
});
