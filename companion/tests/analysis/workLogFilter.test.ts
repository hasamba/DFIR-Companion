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
  "Velociraptor Response and Monitoring session initiated.",
  "Velociraptor Response and Monitoring session continued.",
  // Investigation-process narration the model stamped with capture time (reported again
  // by the user). The tool noun comes AFTER the verb, or there is no concrete artifact.
  "Surveying the DFIR Companion Dashboard for investigation context.",
  "Performed initial data collection with Velociraptor.",
  "Continued data collection with Velociraptor.",
  "Data collection continued with Velociraptor.",
  "Further data analyzed in Velociraptor.",
  "Ongoing analysis completed in Velociraptor.",
  "Final analysis stages reached in Velociraptor.",
  // Tool/UI navigation narration (latest report): "Access to <tool>" / "<tool> access observed".
  "DFIR Companion dashboard access observed",
  "Access to DFIR Companion Dashboard",
  "Access to Syslog Dashboard - Elastic",
  "Access to VolWeb",
  "VolWeb access observed",
  "Access to VolWeb observed",
  "Kibana dashboard opened",
  "Timesketch timeline viewed",
];

// Genuine host/attacker events that MUST survive the filter.
const REAL_EVENTS = [
  "Outbound RDP connection initiated from AICLIENT02.adatum.lab.local to 192.168.1.121",
  "RDP Logon for TGuise\\DESKTOP-KFRB86$\\defaultuser1. SessionID: 1. SrcIP: LOCAL",
  "powershell.exe spawned encoded command",
  "Microsoft Defender real-time protection disabled",
  "velociraptor.exe process created on the host",
  "Scheduled task 'Updater' created to run payload.exe",
  // Genuine "access" events that name a concrete artifact must SURVIVE (no viewer-tool noun).
  "Unauthorized access to \\\\FILESERVER\\HR share by user jdoe",
  "Successful network logon to DC01 from 192.168.1.50",
  "cmd.exe console opened by SYSTEM",
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
