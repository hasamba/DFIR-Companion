import { describe, it, expect } from "vitest";
import {
  isConsoleHistoryRow,
  incidentBurst,
  isTamperFinding,
  tamperTimingOf,
  findingTamperTiming,
  BURST_MIN_ROWS,
} from "../../src/analysis/defenderTamperCap.js";
import type { Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";

function f(p: Partial<Finding>): Finding {
  return {
    id: "f1",
    severity: "High",
    title: "A finding",
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
    ...p,
  };
}
function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-10-05T12:00:00Z",
    description: "x",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const CMD = "Set-MpPreference -DisableRealtimeMonitoring $true";

// The INC-2026-028 shape: High/Critical rows by day 08-28 (2), 08-30 (2), 09-26 (1), 09-30 (10), 10-05 (45).
function burstShape(): ForensicEvent[] {
  const rows: ForensicEvent[] = [];
  const add = (day: string, n: number): void => {
    for (let i = 0; i < n; i++)
      rows.push(
        ev({ id: `${day}-${i}`, timestamp: `2026-${day}T10:${String(i % 60).padStart(2, "0")}:00Z` }),
      );
  };
  add("08-28", 2);
  add("08-30", 2);
  add("09-26", 1);
  add("09-30", 10);
  add("10-05", 45);
  return rows;
}

describe("isConsoleHistoryRow (#1941)", () => {
  it("is true for a Velociraptor PSReadline artifact row", () => {
    expect(
      isConsoleHistoryRow(
        ev({ artifactName: "DetectRaptor.Windows.Detection.Powershell.PSReadline", description: CMD }),
      ),
    ).toBe(true);
  });
  it("is true for a ConsoleHost_history.txt path, either slash and any case", () => {
    expect(
      isConsoleHistoryRow(
        ev({
          path: "C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        }),
      ),
    ).toBe(true);
    expect(isConsoleHistoryRow(ev({ path: "c:/users/a/psreadline/consolehost_history.txt" }))).toBe(true);
  });
  it("is true for a Shell history row that carries a Defender cmdlet", () => {
    expect(isConsoleHistoryRow(ev({ sources: ["Shell history"], description: CMD }))).toBe(true);
    expect(
      isConsoleHistoryRow(
        ev({ sources: ["Shell history"], description: "Add-MpPreference -ExclusionPath C:\\x" }),
      ),
    ).toBe(true);
  });
  it("is false for an EVTX 4104 row with the same cmdlet text", () => {
    expect(
      isConsoleHistoryRow(
        ev({
          sources: ["Hayabusa"],
          path: "c:/windows/system32/winevt/logs/powershell.evtx",
          description: `4104 ${CMD}`,
        }),
      ),
    ).toBe(false);
  });
});

describe("incidentBurst (#1941)", () => {
  it("picks the densest 24 h of High/Critical rows", () => {
    const b = incidentBurst(burstShape());
    expect(b).toBeDefined();
    expect(new Date(b!.start).toISOString().slice(0, 10)).toBe("2026-10-05");
    expect(b!.count).toBe(45);
  });
  it("is undefined below the minimum row count", () => {
    const rows = burstShape().slice(0, BURST_MIN_ROWS - 1);
    expect(
      incidentBurst(rows.map((r, i) => ({ ...r, timestamp: `2026-10-0${i + 1}T00:00:00Z` }))),
    ).toBeUndefined();
  });
  it("ignores Medium/Low rows, undated rows and console-history rows", () => {
    const two = [ev({ id: "h1" }), ev({ id: "h2" })];
    expect(incidentBurst([...two, ev({ id: "m1", severity: "Medium" })])).toBeUndefined();
    expect(incidentBurst([...two, ev({ id: "l1", severity: "Low" })])).toBeUndefined();
    expect(incidentBurst([...two, ev({ id: "bad", timestamp: "not a date" })])).toBeUndefined();
    expect(incidentBurst([...two, ev({ id: "ps", artifactName: "Generic.PSReadline" })])).toBeUndefined();
    expect(incidentBurst([...two, ev({ id: "h3", severity: "Critical" })])).toBeDefined();
  });
});

describe("isTamperFinding (#1941)", () => {
  it("is true for a T1562.001 tag", () => {
    expect(isTamperFinding(f({ mitreTechniques: ["T1562.001"] }))).toBe(true);
  });
  it("is true when the text names Defender tampering", () => {
    expect(isTamperFinding(f({ title: "Attacker disabled Microsoft Defender real-time protection" }))).toBe(
      true,
    );
  });
  it("is false for an unrelated finding", () => {
    expect(isTamperFinding(f({ title: "LSASS memory dumped", mitreTechniques: ["T1003.001"] }))).toBe(false);
  });
});

describe("tamperTimingOf (#1941)", () => {
  const tamper = f({ mitreTechniques: ["T1562.001"] });
  const burst = incidentBurst(burstShape());
  const history = ev({ id: "ps", artifactName: "DetectRaptor.Windows.Detection.Powershell.PSReadline" });

  it("says date-unknown when every cited row is console history", () => {
    expect(tamperTimingOf(tamper, [history], burst)).toBe("date-unknown");
  });
  it("says date-unknown even when no burst exists", () => {
    expect(tamperTimingOf(tamper, [history], undefined)).toBe("date-unknown");
  });
  it("says before-incident when every cited row is more than 48 h before the burst", () => {
    const early = ev({ id: "5001", timestamp: "2026-09-30T10:00:00Z" });
    expect(tamperTimingOf(tamper, [early], burst)).toBe("before-incident");
  });
  it("is null when a cited row is inside the 48 h margin or the burst", () => {
    const near = ev({ id: "near", timestamp: "2026-10-04T10:00:00Z" });
    const inside = ev({ id: "in", timestamp: "2026-10-05T10:30:00Z" });
    expect(tamperTimingOf(tamper, [near], burst)).toBeNull();
    expect(tamperTimingOf(tamper, [inside], burst)).toBeNull();
  });
  it("is null for mixed console-history and in-burst evidence", () => {
    const inside = ev({ id: "in", timestamp: "2026-10-05T10:30:00Z" });
    expect(tamperTimingOf(tamper, [history, inside], burst)).toBeNull();
  });
  it("is null for an undated row, a non-tamper finding, or no evidence", () => {
    expect(tamperTimingOf(tamper, [ev({ timestamp: "" })], burst)).toBeNull();
    expect(tamperTimingOf(f({}), [history], burst)).toBeNull();
    expect(tamperTimingOf(tamper, [], burst)).toBeNull();
  });
});

describe("findingTamperTiming (#1941)", () => {
  it("reads the marker, and nothing else", () => {
    expect(findingTamperTiming({ ...f({}), tamperTiming: "date-unknown" } as Finding)).toBe("date-unknown");
    expect(findingTamperTiming({ ...f({}), tamperTiming: "bogus" } as unknown as Finding)).toBeUndefined();
    expect(findingTamperTiming(f({}))).toBeUndefined();
  });
});
