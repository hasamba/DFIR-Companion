import { describe, it, expect } from "vitest";
import { isAnalystWorkLog, partitionWorkLog, hasIncidentSignal } from "../../src/analysis/workLogFilter.js";
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
  // Real threats must survive EVEN IF the model phrases them with the tool name /
  // "observed" — the incident-signal allowlist overrides the work-log filter.
  "Microsoft Defender flagged VirTool:Win32/Kekeo (Rubeus.exe) for ADATUMLAB\\srv",
  "Velociraptor EventLog shows Defender alert for Rubeus.exe, observed at 12:25",
  "VolWeb shows lsass.exe memory dump created at 12:30",
  "Antivirus Password Dumper Detection: Rubeus.exe flagged on ALClient022",
  // CrowdStrike Falcon EDR detections — real malicious findings, must survive.
  "CrowdStrike flagged ShadowMark.exe (High, Malicious File / AI IOA) run by ADATUMLAB\\Srv on ALCLIENT04: /action:add /target:sac1$; parent process killed",
  "CrowdStrike High detection: powershell.exe on ALCLIENT04 by Srv, AI Powered IOA via Malicious File",
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

  it("incident signal (malware/exe/IP/logon/Defender) overrides the work-log filter", () => {
    expect(hasIncidentSignal("Rubeus.exe flagged by Defender")).toBe(true);
    expect(hasIncidentSignal("logon to DC01 from 10.0.0.5")).toBe(true);
    expect(hasIncidentSignal("Surveying the DFIR Companion Dashboard")).toBe(false);
    // A real threat phrased with the tool name + "observed" is NOT work log.
    expect(isAnalystWorkLog("Velociraptor EventLog shows Defender flagged Rubeus.exe, observed")).toBe(false);
  });

  it("partitions a mixed timeline into keep vs removed", () => {
    const events = [...WORK_LOG, ...REAL_EVENTS].map(ev);
    const { keep, removed } = partitionWorkLog(events);
    expect(removed).toHaveLength(WORK_LOG.length);
    expect(keep).toHaveLength(REAL_EVENTS.length);
  });
});
