// The #1593 row shapes, shared by every path test (#1621): a Velociraptor Windows.Hayabusa.Rules
// hunt row — Hayabusa's verdict fields plus the parsed record under `_Event` — with synthetic values.
// `toEventXml` renders the same record as a Windows Event XML export.

export const HOST = "WS01";
export const FQDN = "WS01.example.com";
export const SYSMON = "Microsoft-Windows-Sysmon/Operational";
export const FIREWALL = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";
export const VELO = "C:\\Program Files\\Velociraptor\\Velociraptor.exe";
export const PWSH = "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
export const CMD = "C:\\WINDOWS\\system32\\cmd.exe";
export const LSASS = "C:\\WINDOWS\\system32\\lsass.exe";
export const DWM = "C:\\Windows\\System32\\dwm.exe";
export const CSRSS = "C:\\Windows\\System32\\csrss.exe";
export const SVCHOST = "C:\\WINDOWS\\System32\\svchost.exe";
export const MPSSVC_SID = "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052";
export const T0 = Date.parse("2026-01-15T10:00:00.000Z");

export const G = {
  velo: "0A0B0C0D-E831-1111-5903-000000000B00",
  klist: "0A0B0C0D-F414-1111-BD03-000000000B00",
  pwsh: "0A0B0C0D-E4D0-1111-6901-000000000B00",
  cmd: "0A0B0C0D-E598-1111-BF01-000000000B00",
  other: "0A0B0C0D-1111-1111-0001-000000000B00",
  lsass: "0A0B0C0D-E2D1-1111-0C00-000000000B00",
  dwm: "0A0B0C0D-4594-1111-1300-000000000A00",
};

let record = 1;
export const iso = (ms: number): string => new Date(ms).toISOString();
export const utc = (ms: number): string => iso(ms).replace("T", " ").replace("Z", "");

export function row(
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

export function create(
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

export function access(
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

export function thread(
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

export function firewall(
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

const xmlEscape = (v: unknown): string =>
  String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** The same records as a Windows Event XML export (`wevtutil qe /f:xml`). */
export function toEventXml(rows: object[]): string {
  const events = rows.map((r) => {
    const e = (r as { _Event: { System: Record<string, unknown>; EventData: Record<string, unknown> } })
      ._Event;
    const s = e.System;
    const at = new Date(Number((s.TimeCreated as { SystemTime: number }).SystemTime) * 1000).toISOString();
    const data = Object.entries(e.EventData)
      .map(([k, v]) => `<Data Name="${k}">${xmlEscape(v)}</Data>`)
      .join("");
    return (
      `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>` +
      `<Provider Name="${xmlEscape((s.Provider as { Name: string }).Name)}"/>` +
      `<EventID>${(s.EventID as { Value: number }).Value}</EventID><TimeCreated SystemTime="${at}"/>` +
      `<EventRecordID>${s.EventRecordID}</EventRecordID><Channel>${s.Channel}</Channel>` +
      `<Computer>${s.Computer}</Computer><Security UserID="S-1-5-18"/></System>` +
      `<EventData>${data}</EventData></Event>`
    );
  });
  return `<Events>${events.join("")}</Events>`;
}
