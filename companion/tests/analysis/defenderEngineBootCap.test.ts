// #2084: the finding-level Defender tamper cap's start-up case (A) and protection-ON case (B),
// run through the grounding pass that applies it. The live scenario re-score is not part of this
// suite; these pin the two shapes deterministically.
import { describe, it, expect } from "vitest";
import { groundAndScoreFindings } from "../../src/analysis/findingGrounding.js";
import { stampEngineBoot, ENGINE_BOOT_WINDOW_MS } from "../../src/analysis/defenderEngineBoot.js";
import {
  tamperTimingOf,
  ENGINE_BOOT_REASON,
  PROTECTION_ON_REASON,
} from "../../src/analysis/defenderTamperCap.js";
import { findingCautionLine } from "../../src/reports/findingCaution.js";
import type { Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";

const HOST = "HOST-A.lab.local";
const ENGINE = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe";
const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const RTP_KEY =
  "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring";
const EXCL_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Windows\\Temp";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-10-05T12:00:00Z",
    description: "x",
    severity: "High",
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
    mitreTechniques: ["T1562.001"],
    canonical: {
      event: { category: "registry", type: "event" },
      registry: { key, ...(data ? { valueData: data } : {}) },
    } as ForensicEvent["canonical"],
  });
}
const boot = (id: string, ts: string): ForensicEvent =>
  ev({
    id,
    timestamp: ts,
    severity: "Info",
    description: `Windows System Event log service started (EID 6005) @ ${HOST}`,
    canonical: { event: { category: "other", type: "boot" } } as ForensicEvent["canonical"],
  });
function f(p: Partial<Finding>): Finding {
  return {
    id: "f1",
    severity: "Critical",
    title: "Defender disabled and broadly excluded",
    description: "Real-time monitoring turned off and exclusions added",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1562.001"],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
    confidence: 85,
    ...p,
  };
}

// What the import seam does (stamp from every imported row, boot rows included), then what the
// forensic timeline keeps (the Info boot rows are demoted, so the cap never sees them).
function imported(rows: ForensicEvent[]): ForensicEvent[] {
  const stamped = new Map(stampEngineBoot(rows).map((e) => [e.id, e] as const));
  return rows.map((e) => stamped.get(e.id) ?? e).filter((e) => e.severity !== "Info");
}
const grade = (finding: Finding, scoped: ForensicEvent[]): Finding =>
  groundAndScoreFindings({
    findings: [finding],
    scopedEvents: scoped,
    iocs: [],
    graphLinkedEventIds: new Set(),
  })[0];
const timing = (x: Finding): unknown => (x as Finding & { tamperTiming?: string }).tamperTiming;

describe("Defender tamper cap — engine start-up (#2084, option A)", () => {
  // APT29 Day 2: the host restarts; minutes later MsMpEng writes real-time-off and an exclusion.
  const apt29 = (): ForensicEvent[] =>
    imported([
      boot("boot", "2026-10-05T12:00:00Z"),
      regWrite("rtp", "2026-10-05T12:03:00Z", ENGINE, RTP_KEY, "DWORD (0x00000001)"),
      regWrite("excl", "2026-10-05T12:04:00Z", ENGINE, EXCL_KEY, "DWORD (0x00000000)"),
    ]);

  it("caps the Critical finding at Medium with the start-up caution, and keeps it visible", () => {
    const out = grade(f({ relatedEventIds: ["rtp", "excl"] }), apt29());
    expect(out.severity).toBe("Medium");
    expect(timing(out)).toBe("engine-boot");
    expect(out.confidenceReason).toContain(ENGINE_BOOT_REASON);
    expect(ENGINE_BOOT_REASON).toMatch(/Defender loading its own policy at start-up — kept as a lead/);
    expect(findingCautionLine(out)).toMatch(/Defender loading its own policy at start-up — kept as a lead/);
  });

  it("does not change the rows' own severity", () => {
    const scoped = apt29();
    grade(f({ relatedEventIds: ["rtp", "excl"] }), scoped);
    expect(scoped.map((e) => e.severity)).toEqual(["High", "High"]);
  });

  it("is idempotent: a second grading pass keeps the one note", () => {
    const once = grade(f({ relatedEventIds: ["rtp", "excl"] }), apt29());
    const twice = grade(once, apt29());
    expect(twice.severity).toBe("Medium");
    expect(twice.confidenceReason!.split(ENGINE_BOOT_REASON)).toHaveLength(2);
  });

  // SAFETY: a real attacker tamper must stay High/Critical, at any time, including after a reboot.
  it("keeps Critical when PowerShell Set-MpPreference ran right after the reboot (the Tamper Protection route)", () => {
    const attacker = ev({
      id: "ps",
      timestamp: "2026-10-05T12:02:30Z",
      description: `Sysmon Process create (EID 1) - Image=${PS}`,
      commandLine:
        "powershell.exe -c Set-MpPreference -DisableRealtimeMonitoring $true -ExclusionPath C:\\Windows\\Temp",
    });
    const rows = imported([
      boot("boot", "2026-10-05T12:00:00Z"),
      attacker,
      regWrite("rtp", "2026-10-05T12:03:00Z", ENGINE, RTP_KEY, "DWORD (0x00000001)"),
      regWrite("excl", "2026-10-05T12:04:00Z", ENGINE, EXCL_KEY, "DWORD (0x00000000)"),
    ]);
    // Cited only the engine's writes, and still Critical: the attacker row vetoes the window.
    expect(grade(f({ relatedEventIds: ["rtp", "excl"] }), rows).severity).toBe("Critical");
    expect(grade(f({ relatedEventIds: ["ps", "rtp", "excl"] }), rows).severity).toBe("Critical");
  });

  it("keeps Critical when the attacker row arrives in a later import than the stamped writes", () => {
    const attacker = ev({
      id: "ps",
      timestamp: "2026-10-05T12:02:30Z",
      commandLine:
        'reg.exe add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableRealtimeMonitoring /d 1',
    });
    const out = grade(f({ relatedEventIds: ["rtp", "excl"] }), [...apt29(), attacker]);
    expect(out.severity).toBe("Critical");
    expect(timing(out)).toBeUndefined();
  });

  it("keeps Critical when an attacker tool itself wrote the Defender key just after a reboot", () => {
    const rows = imported([
      boot("boot", "2026-10-05T12:00:00Z"),
      regWrite("rtp", "2026-10-05T12:03:00Z", PS, RTP_KEY, "DWORD (0x00000001)"),
    ]);
    expect(grade(f({ relatedEventIds: ["rtp"] }), rows).severity).toBe("Critical");
  });

  it("keeps Critical when the engine wrote the policy outside the start-up window", () => {
    const late = new Date(Date.parse("2026-10-05T12:00:00Z") + ENGINE_BOOT_WINDOW_MS + 60_000).toISOString();
    const rows = imported([
      boot("boot", "2026-10-05T12:00:00Z"),
      regWrite("rtp", late, ENGINE, RTP_KEY, "DWORD (0x00000001)"),
    ]);
    expect(grade(f({ relatedEventIds: ["rtp"] }), rows).severity).toBe("Critical");
  });

  it("keeps Critical when one cited row is not an engine start-up write", () => {
    const other = ev({
      id: "5001",
      timestamp: "2026-10-05T14:00:00Z",
      description: "EID 5001 Real-time Protection Disabled",
    });
    expect(grade(f({ relatedEventIds: ["rtp", "5001"] }), [...apt29(), other]).severity).toBe("Critical");
  });
});

// #2104 item 2 (option 2a, strict): a writer-less Defender Operational 5001 / 5007 row counts as
// covered only beside a cited stamped engine write on the same host, inside that write's start-up
// window, with no attacker touch of Defender there then.
describe("Defender tamper cap — writer-less 5001 / 5007 rows (#2104)", () => {
  const status = (id: string, ts: string, eid: 5001 | 5007, asset = HOST): ForensicEvent =>
    ev({
      id,
      timestamp: ts,
      asset,
      description:
        eid === 5001
          ? `Windows Event Log Microsoft Defender Antivirus Real-time Protection scanning for malware was disabled. (EID 5001) @ ${asset}`
          : `Windows Event Log Microsoft Defender Antivirus Configuration has changed. (EID 5007) @ ${asset}`,
    });
  const engineRows = (): ForensicEvent[] =>
    imported([
      boot("boot", "2026-10-05T12:00:00Z"),
      regWrite("rtp", "2026-10-05T12:03:00Z", ENGINE, RTP_KEY, "DWORD (0x00000001)"),
      regWrite("excl", "2026-10-05T12:04:00Z", ENGINE, EXCL_KEY, "DWORD (0x00000000)"),
    ]);
  const mixed = (): ForensicEvent[] => [
    ...engineRows(),
    status("s5001", "2026-10-05T12:03:01Z", 5001),
    status("s5007", "2026-10-05T12:04:01Z", 5007),
  ];

  it("caps a finding citing stamped engine writes plus 5001 / 5007 in the same window on the same host", () => {
    const out = grade(f({ relatedEventIds: ["rtp", "excl", "s5001", "s5007"] }), mixed());
    expect(out.severity).toBe("Medium");
    expect(timing(out)).toBe("engine-boot");
  });

  it("keeps Critical when the finding cites only 5001 / 5007 rows", () => {
    expect(grade(f({ relatedEventIds: ["s5001", "s5007"] }), mixed()).severity).toBe("Critical");
  });

  it("keeps Critical when the 5001 / 5007 row is on another host", () => {
    const rows = [...engineRows(), status("s5001", "2026-10-05T12:03:01Z", 5001, "HOST-B")];
    expect(grade(f({ relatedEventIds: ["rtp", "s5001"] }), rows).severity).toBe("Critical");
  });

  it("keeps Critical when the 5001 / 5007 row falls outside the start-up window", () => {
    const late = new Date(Date.parse("2026-10-05T12:00:00Z") + ENGINE_BOOT_WINDOW_MS + 60_000).toISOString();
    const before = "2026-10-05T11:59:00Z";
    expect(
      grade(f({ relatedEventIds: ["rtp", "s"] }), [...engineRows(), status("s", late, 5007)]).severity,
    ).toBe("Critical");
    expect(
      grade(f({ relatedEventIds: ["rtp", "s"] }), [...engineRows(), status("s", before, 5001)]).severity,
    ).toBe("Critical");
  });

  it("keeps Critical when an attacker tool touched Defender on that host in the window", () => {
    const attacker = ev({
      id: "ps",
      timestamp: "2026-10-05T12:02:30Z",
      commandLine: "powershell.exe -c Set-MpPreference -DisableRealtimeMonitoring $true",
    });
    const out = grade(f({ relatedEventIds: ["rtp", "excl", "s5001", "s5007"] }), [...mixed(), attacker]);
    expect(out.severity).toBe("Critical");
    expect(timing(out)).toBeUndefined();
  });
});

describe("Defender tamper cap — protection turned on (#2084, option B)", () => {
  const on = regWrite("on", "2026-10-05T15:00:00Z", PS, RTP_KEY, "DWORD (0x00000000)");
  const off = regWrite("off", "2026-10-05T15:01:00Z", PS, RTP_KEY, "DWORD (0x00000001)");

  it("caps a tamper finding whose only evidence turns protection on", () => {
    const out = grade(f({ relatedEventIds: ["on"] }), [on]);
    expect(out.severity).toBe("Medium");
    expect(timing(out)).toBe("protection-on");
    expect(out.confidenceReason).toContain(PROTECTION_ON_REASON);
    expect(findingCautionLine(out)).toMatch(/Protection turned on/);
  });

  it("an ON row does not hide a real OFF row beside it", () => {
    expect(grade(f({ relatedEventIds: ["on", "off"] }), [on, off]).severity).toBe("Critical");
    expect(tamperTimingOf(f({}), [on, off], undefined, [on, off])).toBeNull();
  });
});
