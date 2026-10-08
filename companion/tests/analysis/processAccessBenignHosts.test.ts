// #2026 — process access that is routine for the host it runs on: cloud guest agents reading
// lsass, wininit opening the lsass it starts, JIT code in a .NET host, kernel frames on a stack.
import { describe, expect, it } from "vitest";
import { processOverlay, readCallTrace, type OverlayInput } from "../../src/analysis/processAccess.js";

const LSASS = "C:\\windows\\system32\\lsass.exe";
const SVCHOST = "C:\\windows\\system32\\svchost.exe";
const BROKER = "C:\\Windows\\System32\\RuntimeBroker.exe";
const EXPLORER = "C:\\windows\\Explorer.EXE";
const WININIT = "C:\\windows\\system32\\wininit.exe";
const PS = "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe";
const PS_ISE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe";
const PWSH = "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
const WSMPROV = "C:\\windows\\system32\\wsmprovhost.exe";
const MIMI = "C:\\windows\\system32\\m.exe";
const SCR = "C:\\ProgramData\\victim\\cod.3aka3.scr";
const AZ_TELEMETRY = "C:\\WindowsAzure\\Packages\\Telemetry\\WindowsAzureTelemetryService.exe";
const AZ_GUEST = "C:\\WindowsAzure\\Packages\\GuestAgent\\WindowsAzureGuestAgent.exe";
const AZ_ANTIMALWARE =
  "C:\\Packages\\Plugins\\Microsoft.Azure.Security.IaaSAntimalware\\1.5.5.9\\AntimalwareConfig.exe";
const G1 = "{11111111-1111-1111-1111-111111111111}";
const G2 = "{22222222-2222-2222-2222-222222222222}";

// The shapes from the OTRF APT29 data: JIT frames sit between NGEN'd framework images; a shell's
// stack runs through a win32k callback, whose frames are kernel addresses no user module backs.
const CLR_TRACE =
  "C:\\windows\\SYSTEM32\\ntdll.dll+9c584|C:\\windows\\System32\\KERNELBASE.dll+2732e|" +
  "C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\abc\\System.ni.dll+1|" +
  "UNKNOWN(00007FFEF1D96620)|UNKNOWN(00007FFEF1DF3991)";
const JIT_ONLY_TRACE =
  "C:\\windows\\SYSTEM32\\ntdll.dll+9d934|C:\\windows\\System32\\KERNEL32.DLL+1be93|UNKNOWN(000001996D1EB1F1)";
const KERNEL_TRACE =
  "C:\\windows\\SYSTEM32\\ntdll.dll+9c584|C:\\windows\\System32\\KERNELBASE.dll+2732e|" +
  "C:\\Windows\\System32\\twinui.pcshell.dll+1|C:\\windows\\System32\\USER32.dll+2|" +
  "UNKNOWN(FFFFF8060928EA45)|UNKNOWN(FFFFEE1334896C84)|C:\\windows\\System32\\win32u.dll+3";
const BACKED_SYSTEM_TRACE =
  "C:\\windows\\SYSTEM32\\ntdll.dll+9d934|C:\\windows\\System32\\KERNELBASE.dll+5f42a|" +
  "C:\\windows\\System32\\KERNEL32.DLL+1be93|C:\\windows\\system32\\wininit.exe+260a7";

function access(source: string, target: string, rights: string, trace?: string) {
  const ed: Record<string, string> = {
    SourceProcessGuid: G1,
    SourceProcessId: "1001",
    SourceImage: source,
    TargetProcessGuid: G2,
    TargetProcessId: "612",
    TargetImage: target,
    GrantedAccess: rights,
    ...(trace !== undefined ? { CallTrace: trace } : {}),
  };
  const input: OverlayInput = {
    kind: "procaccess",
    field: (k) => ed[k] ?? "",
    has: (k) => k in ed,
    description: "Sysmon process access (EID 10)",
    severity: "Info",
    mitre: [],
    recordId: "4242",
    row: 7,
  };
  return processOverlay(input);
}

describe("readCallTrace — a kernel-address frame is not unbacked user code", () => {
  it("counts only user-mode UNKNOWN frames as unbacked", () => {
    expect(readCallTrace(KERNEL_TRACE).unbacked).toBe(0);
    expect(readCallTrace(CLR_TRACE).unbacked).toBe(2);
    expect(readCallTrace(`${KERNEL_TRACE}|UNKNOWN(00007FF612340000)`).unbacked).toBe(1);
    // an address that does not parse stays the conservative claim
    expect(readCallTrace("ntdll.dll+1|UNKNOWN(zz)").unbacked).toBe(1);
  });
});

describe("cloud guest agents in their install paths are benign lsass accessors", () => {
  it("Azure agents' query handles on lsass are not High, JIT frames and all", () => {
    for (const src of [AZ_TELEMETRY, AZ_GUEST, AZ_ANTIMALWARE]) {
      for (const rights of ["0x1400", "0x1000"]) {
        const o = access(src, LSASS, rights, CLR_TRACE);
        expect(o.severity, `${src} ${rights}`).toBe("Low");
        expect(o.mitre).toEqual([]);
      }
      expect(access(src, SVCHOST, "0x1400", CLR_TRACE).severity, `${src} svchost`).toBe("Info");
    }
  });
  it("a routine read of lsass by an Azure agent with a backed trace is Low", () => {
    expect(access(AZ_TELEMETRY, LSASS, "0x1410", BACKED_SYSTEM_TRACE).severity).toBe("Low");
  });
  it("the same names outside the install path borrow nothing", () => {
    const fake = "C:\\Users\\Public\\WindowsAzureTelemetryService.exe";
    expect(access(fake, LSASS, "0x1400", CLR_TRACE).severity).toBe("High");
    expect(access(fake, LSASS, "0x1410", BACKED_SYSTEM_TRACE).severity).toBe("High");
    const nested = "C:\\Staging\\WindowsAzure\\Packages\\Telemetry\\WindowsAzureTelemetryService.exe";
    expect(access(nested, LSASS, "0x1410", BACKED_SYSTEM_TRACE).severity).toBe("High");
  });
  it("trust never covers write/thread rights on lsass", () => {
    expect(access(AZ_GUEST, LSASS, "0x1FFFFF", CLR_TRACE).severity).toBe("High");
  });
});

describe("wininit.exe opening the lsass it starts", () => {
  it("is not graded up from the genuine System32 path with a system-only stack", () => {
    for (const rights of ["0x1FFFFF", "0x1000000", "0x1010"]) {
      const o = access(WININIT, LSASS, rights, BACKED_SYSTEM_TRACE);
      expect(o.severity, rights).toBe("Low");
      expect(o.mitre).toEqual([]);
    }
  });
  it("stays High from a masqueraded path, with an unbacked frame, or through a foreign module", () => {
    expect(access("C:\\Windows\\Temp\\wininit.exe", LSASS, "0x1FFFFF", BACKED_SYSTEM_TRACE).severity).toBe(
      "High",
    );
    expect(access(WININIT, LSASS, "0x1FFFFF", JIT_ONLY_TRACE).severity).toBe("High");
    expect(
      access(WININIT, LSASS, "0x1FFFFF", `${BACKED_SYSTEM_TRACE}|C:\\Users\\Public\\evil.dll+1`).severity,
    ).toBe("High");
  });
});

describe("JIT frames from a .NET host are not, alone, a High", () => {
  it("PowerShell / WinRM hosts opening ordinary processes grade on their rights", () => {
    for (const src of [PS, PS_ISE, PWSH, WSMPROV]) {
      const q = access(src, BROKER, "0x1000", CLR_TRACE);
      expect(q.severity, `${src} query`).toBe("Info");
      expect(q.description).toContain("unbacked");
      expect(access(src, EXPLORER, "0x40", JIT_ONLY_TRACE).severity, `${src} dup`).toBe("Medium");
      expect(access(src, SVCHOST, "0x1F3FFF", CLR_TRACE).severity, `${src} all`).toBe("Medium");
    }
  });
  it("a .NET host's query-only handle on lsass is not High", () => {
    expect(access(PS, LSASS, "0x1000", JIT_ONLY_TRACE).severity).toBe("Low");
  });
  it("a .NET host with credential-read or write rights on lsass stays High", () => {
    expect(access(PS, LSASS, "0x1FFFFF", JIT_ONLY_TRACE).severity).toBe("High");
    expect(access(PS, LSASS, "0x1010", CLR_TRACE).severity).toBe("High");
    expect(access(WSMPROV, LSASS, "0x1F3FFF", CLR_TRACE).mitre).toEqual(["T1003.001"]);
  });
  it("a host name from a user-writable path is not a .NET host", () => {
    expect(access("C:\\Users\\Public\\powershell.exe", BROKER, "0x1000", JIT_ONLY_TRACE).severity).toBe(
      "High",
    );
  });
});

describe("Explorer's kernel-callback frames versus real unbacked code", () => {
  it("a shell stack whose only UNKNOWN frames are kernel addresses grades on its rights", () => {
    expect(access(EXPLORER, BROKER, "0x40", KERNEL_TRACE).severity).toBe("Medium");
    expect(access(EXPLORER, PS, "0x1000", KERNEL_TRACE).severity).toBe("Info");
  });
  it("Explorer is not a .NET host: a user-mode unbacked frame is still High", () => {
    expect(access(EXPLORER, BROKER, "0x1000", `${KERNEL_TRACE}|UNKNOWN(000000001D1B1C53)`).severity).toBe(
      "High",
    );
  });
});

describe("the attacker rows stay High", () => {
  it("mimikatz reading lsass", () => {
    const o = access(MIMI, LSASS, "0x1010", `${BACKED_SYSTEM_TRACE}|C:\\windows\\system32\\m.exe+8a3ce`);
    expect(o.severity).toBe("High");
    expect(o.mitre).toEqual(["T1003.001"]);
  });
  it("a non-.NET process with an unbacked frame", () => {
    expect(access(SCR, "C:\\windows\\system32\\cmd.exe", "0x1FFFFF", JIT_ONLY_TRACE).severity).toBe("High");
  });
  it("PowerShell creating a remote thread in lsass outside any module", () => {
    const ed: Record<string, string> = {
      SourceProcessGuid: G1,
      SourceImage: PS,
      TargetProcessGuid: G2,
      TargetImage: LSASS,
      StartModule: "-",
      StartAddress: "0x000001996D1E0000",
    };
    const o = processOverlay({
      kind: "thread",
      field: (k) => ed[k] ?? "",
      has: (k) => k in ed,
      description: "Sysmon remote thread (EID 8)",
      severity: "Low",
      mitre: [],
      recordId: "1",
      row: 1,
    });
    expect(o.severity).toBe("High");
    expect(o.mitre).toEqual(["T1055"]);
  });
});
