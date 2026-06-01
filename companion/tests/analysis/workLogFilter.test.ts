import { describe, it, expect } from "vitest";
import { isAnalystWorkLog, partitionWorkLog } from "../../src/analysis/workLogFilter.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Real lines the user reported as wrongly appearing in the forensic timeline.
const WORK_LOG = [
  "Velociraptor hunt created with ID H.D89D7UCLKN4CA",
  "Hunt H.D89D7UCLKN4CA started",
  "NotebookManager detected notebook cell NC.D89D80673BHK2 canceled.",
  "Hunt H.D89D7UCLKN4CA expired",
  "Velociraptor Response logged new notebook access.",
  "Velociraptor Response executing VQL command.",
  "Velociraptor EventLog analysis performed",
  "Velociraptor EventLog search completed",
  "Velociraptor notebook accessed.",
  "Velociraptor EventLog search executed for anomalies.",
  "Velociraptor Response and Monitoring accessed",
  "Velociraptor Response and Monitoring notebook accessed.",
];

// Genuine host/attacker events that MUST survive the filter.
const REAL_EVENTS = [
  "Outbound RDP connection initiated from AICLIENT02.adatum.lab.local to 192.168.1.121",
  "RDP Logon for TGuise\\DESKTOP-KFRB86$\\defaultuser1. SessionID: 1. SrcIP: LOCAL",
  "powershell.exe spawned encoded command",
  "Microsoft Defender real-time protection disabled",
  "velociraptor.exe process created on the host",
  "Scheduled task 'Updater' created to run payload.exe",
];

function ev(description: string): ForensicEvent {
  return { id: "e", timestamp: "2026-01-01T00:00:00Z", description, severity: "Info",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] };
}

describe("workLogFilter", () => {
  it("flags analyst/tool-usage lines as work log", () => {
    for (const d of WORK_LOG) expect(isAnalystWorkLog(d), d).toBe(true);
  });

  it("does NOT flag genuine host/attacker events", () => {
    for (const d of REAL_EVENTS) expect(isAnalystWorkLog(d), d).toBe(false);
  });

  it("partitions a mixed timeline into keep vs removed", () => {
    const events = [...WORK_LOG, ...REAL_EVENTS].map(ev);
    const { keep, removed } = partitionWorkLog(events);
    expect(removed).toHaveLength(WORK_LOG.length);
    expect(keep).toHaveLength(REAL_EVENTS.length);
  });
});
