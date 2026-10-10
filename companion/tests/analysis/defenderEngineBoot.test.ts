// #2084: Defender's own engine writing its policy just after the host starts is not tampering.
//
// No fixture in the repo shows a Defender-engine registry write, nor a Tamper-Protection-routed
// `Set-MpPreference`. The rows below follow the Sysmon EID 12/13 shape the SIEM importer renders
// (`Sysmon Registry value set (EID 13) - Image=… - TargetObject=… @ host`, the image on `path`, the
// key and value on `canonical.registry`), with the engine's real platform path as the existing
// process-access fixtures spell it (`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe`).
import { describe, it, expect } from "vitest";
import {
  ENGINE_BOOT_WINDOW_MS,
  isStartupRow,
  isDefenderEngineWrite,
  isAttackerDefenderTouch,
  isProtectionOnRow,
  stampEngineBoot,
  engineBootOf,
} from "../../src/analysis/defenderEngineBoot.js";
import { parseSiemExport as parseSiem } from "../../src/analysis/siemImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// The importer's rows, as the merge stores them.
const parseSiemExport = (text: string): { events: ForensicEvent[] } => ({
  events: parseSiem(text).events.map((e) => ({ relatedFindingIds: [], sourceScreenshots: [], ...e })),
});

const HOST = "HOST-A.lab.local";
const ENGINE = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe";
const RTP_KEY =
  "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring";
const EXCL_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Windows\\Temp";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-10-05T12:00:00Z",
    description: "x",
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: HOST,
    ...p,
  };
}

function regWrite(id: string, ts: string, image: string, key: string, data?: string): ForensicEvent {
  return ev({
    id,
    timestamp: ts,
    description: `Sysmon Registry value set (EID 13) - Image=${image} - TargetObject=${key} @ ${HOST}`,
    path: image,
    mitreTechniques: ["T1112"],
    canonical: {
      event: { category: "registry", type: "event" },
      registry: { key, ...(data ? { valueData: data } : {}) },
    } as ForensicEvent["canonical"],
  });
}

const boot = (id: string, ts: string, eid = 6005, asset = HOST): ForensicEvent =>
  ev({
    id,
    timestamp: ts,
    severity: "Info",
    asset,
    description: `Windows System Event log service started (EID ${eid}) @ ${asset}`,
    canonical: { event: { category: "other", type: "boot" } } as ForensicEvent["canonical"],
  });

describe("isStartupRow (#2084)", () => {
  it("is true for the start-up records the SIEM importer emits (6005, 4608, Kernel-General 12)", () => {
    const recs = [
      { "@timestamp": "2020-05-02T03:00:10Z", log_name: "System", computer_name: HOST, event_id: 6005 },
      { "@timestamp": "2020-05-02T03:00:08Z", log_name: "Security", computer_name: HOST, event_id: 4608 },
      {
        "@timestamp": "2020-05-02T03:00:09Z",
        log_name: "System",
        source_name: "Microsoft-Windows-Kernel-General",
        computer_name: HOST,
        event_id: 12,
        event_data: { StartTime: "2020-05-02T03:00:00Z" },
      },
    ];
    const rows = parseSiemExport(JSON.stringify(recs)).events;
    expect(rows).toHaveLength(3);
    for (const r of rows) expect(isStartupRow(r)).toBe(true);
  });
  it("is false for a shutdown record (6006, 1074, 6008) and an ordinary row", () => {
    expect(isStartupRow(boot("s", "2026-10-05T12:00:00Z", 6006))).toBe(false);
    expect(isStartupRow(boot("s", "2026-10-05T12:00:00Z", 1074))).toBe(false);
    expect(isStartupRow(boot("s", "2026-10-05T12:00:00Z", 6008))).toBe(false);
    expect(isStartupRow(ev({ description: "Process create (EID 1)" }))).toBe(false);
  });
});

describe("isDefenderEngineWrite (#2084)", () => {
  it("is true for the engine under its platform folder writing a Defender key", () => {
    expect(isDefenderEngineWrite(regWrite("r", "2026-10-05T12:00:00Z", ENGINE, RTP_KEY))).toBe(true);
    expect(isDefenderEngineWrite(regWrite("r", "2026-10-05T12:00:00Z", ENGINE, EXCL_KEY))).toBe(true);
    const progFiles = "C:\\Program Files\\Windows Defender\\MsMpEng.exe";
    expect(isDefenderEngineWrite(regWrite("r", "2026-10-05T12:00:00Z", progFiles, RTP_KEY))).toBe(true);
  });
  it("is true for the row the SIEM importer builds from a Sysmon 13 record", () => {
    const rec = {
      "@timestamp": "2020-05-02T03:04:00Z",
      log_name: "Microsoft-Windows-Sysmon/Operational",
      computer_name: HOST,
      event_id: 13,
      event_data: {
        EventType: "SetValue",
        Image: ENGINE,
        TargetObject: RTP_KEY,
        Details: "DWORD (0x00000001)",
      },
    };
    const [row] = parseSiemExport(JSON.stringify([rec])).events;
    expect(isDefenderEngineWrite(row)).toBe(true);
  });
  it("is false for an MsMpEng.exe outside the Defender folders (a masquerade)", () => {
    const fake = "C:\\Users\\Public\\MsMpEng.exe";
    expect(isDefenderEngineWrite(regWrite("r", "2026-10-05T12:00:00Z", fake, RTP_KEY))).toBe(false);
  });
  it("is false for an attacker tool writing the key, and for the engine writing a non-Defender key", () => {
    const ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    expect(isDefenderEngineWrite(regWrite("r", "2026-10-05T12:00:00Z", ps, RTP_KEY))).toBe(false);
    const other = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x";
    expect(isDefenderEngineWrite(regWrite("r", "2026-10-05T12:00:00Z", ENGINE, other))).toBe(false);
  });
});

describe("isAttackerDefenderTouch (#2084)", () => {
  it("is true for a Defender cmdlet, reg.exe / sc.exe on Defender, and a non-engine Defender write", () => {
    expect(
      isAttackerDefenderTouch(
        ev({ description: "powershell Set-MpPreference -DisableRealtimeMonitoring $true" }),
      ),
    ).toBe(true);
    expect(isAttackerDefenderTouch(ev({ commandLine: "Add-MpPreference -ExclusionPath C:\\x" }))).toBe(true);
    expect(
      isAttackerDefenderTouch(
        ev({
          processName: "reg.exe",
          commandLine: `reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /d 1`,
        }),
      ),
    ).toBe(true);
    expect(isAttackerDefenderTouch(ev({ commandLine: "sc.exe config WinDefend start= disabled" }))).toBe(
      true,
    );
    const ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    expect(isAttackerDefenderTouch(regWrite("r", "2026-10-05T12:00:00Z", ps, RTP_KEY))).toBe(true);
  });
  it("is false for the engine's own write, even of an exclusion naming powershell.exe", () => {
    const key = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\\powershell.exe";
    expect(isAttackerDefenderTouch(regWrite("r", "2026-10-05T12:00:00Z", ENGINE, key))).toBe(false);
    expect(isAttackerDefenderTouch(ev({ description: "Process create (EID 1) - Image=notepad.exe" }))).toBe(
      false,
    );
  });
});

describe("isProtectionOnRow (#2084, option B)", () => {
  it("is true for a Disable* value set to 0 and for Set-MpPreference -Disable* $false", () => {
    expect(isProtectionOnRow(regWrite("r", "t", ENGINE, RTP_KEY, "DWORD (0x00000000)"))).toBe(true);
    const ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    expect(isProtectionOnRow(regWrite("r", "t", ps, RTP_KEY, "DWORD (0x00000000)"))).toBe(true);
    expect(isProtectionOnRow(ev({ commandLine: "Set-MpPreference -DisableRealtimeMonitoring $false" }))).toBe(
      true,
    );
    expect(
      isProtectionOnRow(
        ev({ description: "Set-MpPreference -DisableRealtimeMonitoring 0 -DisableIOAVProtection $false" }),
      ),
    ).toBe(true);
  });
  it("is false for turning protection off, an exclusion, or an ON flag mixed with an exclusion", () => {
    expect(isProtectionOnRow(regWrite("r", "t", ENGINE, RTP_KEY, "DWORD (0x00000001)"))).toBe(false);
    expect(isProtectionOnRow(regWrite("r", "t", ENGINE, RTP_KEY))).toBe(false);
    expect(isProtectionOnRow(regWrite("r", "t", ENGINE, EXCL_KEY, "DWORD (0x00000000)"))).toBe(false);
    expect(isProtectionOnRow(ev({ commandLine: "Set-MpPreference -DisableRealtimeMonitoring $true" }))).toBe(
      false,
    );
    expect(
      isProtectionOnRow(
        ev({ commandLine: "Set-MpPreference -DisableRealtimeMonitoring $false -ExclusionPath C:\\x" }),
      ),
    ).toBe(false);
    expect(isProtectionOnRow(ev({ commandLine: "Add-MpPreference -ExclusionPath C:\\x" }))).toBe(false);
  });
});

describe("stampEngineBoot (#2084)", () => {
  // The APT29 Day 2 shape: the host restarts, then MsMpEng writes real-time-off and an exclusion.
  const apt29 = (): ForensicEvent[] => [
    boot("boot", "2026-10-05T12:00:00Z"),
    regWrite("rtp", "2026-10-05T12:03:00Z", ENGINE, RTP_KEY, "DWORD (0x00000001)"),
    regWrite("excl", "2026-10-05T12:04:00Z", ENGINE, EXCL_KEY, "DWORD (0x00000000)"),
  ];

  it("stamps the engine's writes inside the start-up window with the boot they follow", () => {
    const out = stampEngineBoot(apt29());
    expect(out.map((e) => e.id).sort()).toEqual(["excl", "rtp"]);
    for (const e of out) expect(engineBootOf(e)?.bootAt).toBe("2026-10-05T12:00:00.000Z");
  });
  it("returns new rows and never mutates its input", () => {
    const rows = apt29();
    const snapshot = JSON.stringify(rows);
    stampEngineBoot(rows);
    expect(JSON.stringify(rows)).toBe(snapshot);
  });
  it("does not stamp a write past the window, before the boot, or on another host", () => {
    const late = new Date(Date.parse("2026-10-05T12:00:00Z") + ENGINE_BOOT_WINDOW_MS + 60_000).toISOString();
    const rows = [
      boot("boot", "2026-10-05T12:00:00Z"),
      regWrite("late", late, ENGINE, RTP_KEY, "DWORD (0x00000001)"),
      regWrite("before", "2026-10-05T11:59:00Z", ENGINE, RTP_KEY, "DWORD (0x00000001)"),
      { ...regWrite("other", "2026-10-05T12:02:00Z", ENGINE, RTP_KEY), asset: "HOST-B" },
    ];
    expect(stampEngineBoot(rows)).toEqual([]);
  });
  it("does not stamp anything without a start-up record (no anchor, no cap)", () => {
    expect(stampEngineBoot(apt29().filter((e) => e.id !== "boot"))).toEqual([]);
  });
  it("does not stamp when an attacker tool touched Defender on that host inside the window", () => {
    const attacker = ev({
      id: "ps",
      timestamp: "2026-10-05T12:02:30Z",
      severity: "High",
      commandLine: "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
    });
    expect(stampEngineBoot([...apt29(), attacker])).toEqual([]);
  });
  it("still stamps when the attacker touch is on a different host", () => {
    const elsewhere = ev({
      id: "ps",
      timestamp: "2026-10-05T12:02:30Z",
      asset: "HOST-B",
      commandLine: "Set-MpPreference -DisableRealtimeMonitoring $true",
    });
    expect(
      stampEngineBoot([...apt29(), elsewhere])
        .map((e) => e.id)
        .sort(),
    ).toEqual(["excl", "rtp"]);
  });
  it("leaves an already-stamped row alone", () => {
    const once = stampEngineBoot(apt29());
    const rows = apt29().map((e) => once.find((x) => x.id === e.id) ?? e);
    expect(stampEngineBoot(rows)).toEqual([]);
  });
});
