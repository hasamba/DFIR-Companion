import { describe, it, expect } from "vitest";
import { parseCrowdstrikeExport } from "../../src/analysis/crowdstrikeImport.js";
import { isCrowdstrikeAlert } from "../../src/analysis/crowdstrikeAlert.js";
import { falconSeverity } from "../../src/analysis/crowdstrikeFields.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

// #2592 Part 2 — Falcon API alerts (v2) and legacy detects. Synthetic: WS-01, example.com.
const alertV2 = (extra: Record<string, unknown> = {}) => ({
  composite_id: "cid:ind:aaa:bbb",
  severity: 4,
  tactic: "Execution",
  technique: "PowerShell",
  technique_id: "T1059.001",
  display_name: "SuspiciousPowerShell",
  filename: "powershell.exe",
  cmdline: "powershell.exe -nop -w hidden",
  sha256: "d".repeat(64),
  pattern_disposition_description: "Process blocked",
  timestamp: "2024-11-12T08:26:39.456Z",
  device: { hostname: "WS-01", device_id: "abc" },
  user_name: "alice",
  ...extra,
});
const legacyDetect = {
  detection_id: "ldt:abc:1",
  max_severity_displayname: "Critical",
  device: { hostname: "WS-02" },
  behaviors: [
    {
      behavior_id: "1",
      tactic: "Credential Access",
      technique: "OS Credential Dumping",
      technique_id: "T1003",
      filename: "procdump.exe",
      cmdline: "procdump -ma lsass.exe",
      timestamp: "2024-11-12T09:00:00Z",
    },
    {
      behavior_id: "2",
      tactic: "Execution",
      technique: "Command and Scripting Interpreter",
      technique_id: "T1059",
      severity_name: "Medium",
      filename: "cmd.exe",
      timestamp: "2024-11-12T09:01:00Z",
    },
  ],
};

describe("Falcon API alerts", () => {
  it("numeric severity 4 imports as High with MITRE, disposition, host and hash (AC16, AC18)", () => {
    const r = parseCrowdstrikeExport(JSON.stringify([alertV2()]));
    const e = r.events[0];
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1059.001");
    expect(e.description).toContain("Process blocked");
    expect(e.description).toContain("CrowdStrike Falcon detection: SuspiciousPowerShell");
    expect(e.asset).toBe("WS-01");
    expect(e.timestamp).toBe("2024-11-12T08:26:39.456Z");
    expect(e.sources).toEqual(["CrowdStrike Falcon"]);
    expect(r.iocs.map((i) => i.value)).toContain("d".repeat(64));
  });
  it("severity_name wins over the number; Informational stays Info (AC17)", () => {
    const r = parseCrowdstrikeExport(
      JSON.stringify([alertV2({ severity_name: "Informational", severity: 90 })]),
    );
    expect(r.events[0].severity).toBe("Info");
  });
  it("reads the API resources envelope and detects it", () => {
    const text = JSON.stringify({
      meta: { query_time: 0.1 },
      resources: [alertV2(), alertV2({ composite_id: "cid:ind:x:y" })],
      errors: [],
    });
    expect(detectImportKind("alerts.json", text)).toBe("crowdstrike");
    expect(parseCrowdstrikeExport(text).events).toHaveLength(2);
  });
  it("legacy detects: one event per behavior, detect-level severity as fallback", () => {
    const r = parseCrowdstrikeExport(JSON.stringify(legacyDetect));
    expect(r.events).toHaveLength(2);
    const bySev = Object.fromEntries(r.events.map((e) => [e.mitreTechniques[0], e.severity]));
    expect(bySev).toEqual({ T1003: "Critical", T1059: "Medium" });
    expect(r.events.every((e) => e.asset === "WS-02")).toBe(true);
  });
  it("signature needs an alert id and a tactic/technique/behaviors", () => {
    expect(isCrowdstrikeAlert(alertV2())).toBe(true);
    expect(isCrowdstrikeAlert({ composite_id: "x" })).toBe(false);
    expect(isCrowdstrikeAlert({ tactic: "Execution" })).toBe(false);
  });
  it("falconSeverity maps names, 1–5 and the 0–100 scale", () => {
    expect(falconSeverity("High", "")).toBe("High");
    expect(falconSeverity("", "5")).toBe("Critical");
    expect(falconSeverity("", "1")).toBe("Info");
    expect(falconSeverity("", "70")).toBe("High");
    expect(falconSeverity("", "x")).toBe("Info");
  });
});
