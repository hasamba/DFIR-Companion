import type { Severity } from "./stateTypes.js";
import {
  DNS_CLIENT_EVENTS,
  SYSMON_22_DNS,
  dnsOverlay,
  type DnsEventSchema,
  type DnsOverlay,
} from "./dnsRecord.js";
import { dnsServerOverlay, isDnsServerAnalyticEid, type DnsServerOverlay } from "./dnsServerRecord.js";

// The Windows event tables mapWindows reads (siemImport.ts): what an Event ID is called and how it
// grades before any signal adjudicates it. Kept apart from the mapper so the mapper stays within its
// size freeze — the knowledge did not change when it moved.

export interface WinEventDef {
  label: string;
  severity: Severity;
  mitre?: string[];
  kind?: "process" | "network" | "dns" | "procaccess" | "file" | "service" | "stream" | "thread" | "tamper";
  /** For `kind: "file"`: what the record says happened to the file it names (its TargetFilename). */
  fileAction?: "create" | "delete";
  dns?: DnsEventSchema; // the DNS fields THIS event defines (dnsRecord.ts)
}

// Security + System channel events keyed by Event ID. Exported so a CONDENSED summary artifact
// (one that reports an EID without the parsed record) reads its label and base grade from the same
// table as a parsed event, instead of growing a second, drifting copy of the same knowledge.
export const WIN_EVENTS: Record<number, WinEventDef> = {
  // Authentication / logon
  4624: { label: "Successful logon", severity: "Low" },
  4625: { label: "Failed logon", severity: "Medium", mitre: ["T1110"] },
  4634: { label: "Logoff", severity: "Info" },
  4647: { label: "User-initiated logoff", severity: "Info" },
  4648: { label: "Logon with explicit credentials", severity: "Medium", mitre: ["T1078"] },
  4672: { label: "Special privileges assigned to new logon", severity: "Low" },
  4768: { label: "Kerberos TGT requested (AS-REQ)", severity: "Low" },
  4769: { label: "Kerberos service ticket requested (TGS-REQ)", severity: "Low" },
  4771: { label: "Kerberos pre-authentication failed", severity: "Medium", mitre: ["T1110"] },
  4776: { label: "NTLM credential validation", severity: "Low" },
  // Account / group management
  4720: { label: "User account created", severity: "Medium", mitre: ["T1136.001"] },
  4722: { label: "User account enabled", severity: "Medium" },
  4723: { label: "Password change attempt", severity: "Low" },
  4724: { label: "Password reset attempt", severity: "Medium", mitre: ["T1098"] },
  4725: { label: "User account disabled", severity: "Medium" },
  4726: { label: "User account deleted", severity: "Medium" },
  4728: { label: "Member added to global security group", severity: "Medium", mitre: ["T1098"] },
  4732: { label: "Member added to local security group", severity: "Medium", mitre: ["T1098"] },
  4756: { label: "Member added to universal security group", severity: "Medium", mitre: ["T1098"] },
  4738: { label: "User account changed", severity: "Low" },
  4740: { label: "User account locked out", severity: "Medium" },
  4767: { label: "User account unlocked", severity: "Low" },
  // Persistence / execution
  4697: { label: "Service installed (Security)", severity: "Medium", kind: "service", mitre: ["T1543.003"] },
  4698: { label: "Scheduled task created", severity: "Medium", mitre: ["T1053.005"] },
  4699: { label: "Scheduled task deleted", severity: "Medium", mitre: ["T1053.005"] },
  4700: { label: "Scheduled task enabled", severity: "Low", mitre: ["T1053.005"] },
  4702: { label: "Scheduled task updated", severity: "Medium", mitre: ["T1053.005"] },
  4688: { label: "Process created", severity: "Low", kind: "process", mitre: ["T1059"] },
  4689: { label: "Process exited", severity: "Info" },
  // Object / share / policy
  4663: { label: "Object access attempt", severity: "Low" },
  4670: { label: "Permissions on object changed", severity: "Medium" },
  5140: { label: "Network share accessed", severity: "Low", mitre: ["T1021.002"] },
  5142: { label: "Network share added", severity: "Medium" },
  5143: { label: "Network share modified", severity: "Medium" },
  5145: { label: "Network share object checked", severity: "Low", mitre: ["T1021.002"] },
  4946: { label: "Windows Firewall rule added", severity: "Medium", mitre: ["T1562.004"] },
  4947: { label: "Windows Firewall rule modified", severity: "Medium", mitre: ["T1562.004"] },
  5156: { label: "Connection permitted (WFP)", severity: "Low", kind: "network" }, // #996 — the firewall audit's own Sysmon-3-equivalent
  5058: { label: "Key file operation", severity: "Low" },
  5059: { label: "Key migration operation", severity: "Low" },
  // Defense evasion
  1102: { label: "Security audit log cleared", severity: "High", mitre: ["T1070.001"] },
  4719: { label: "System audit policy changed", severity: "High", mitre: ["T1562.002"] },
  // System channel
  7045: { label: "Service installed", severity: "Medium", kind: "service", mitre: ["T1543.003"] },
  7034: { label: "Service crashed unexpectedly", severity: "Low" },
  7036: { label: "Service state changed", severity: "Info" },
  7040: { label: "Service start type changed", severity: "Low" },
  104: { label: "Event log cleared", severity: "High", mitre: ["T1070.001"] },
  6005: { label: "Event log service started", severity: "Info" },
  6006: { label: "Event log service stopped", severity: "Low" },
};

// PowerShell/Operational events, keyed separately from WIN_EVENTS because that table is looked up
// by EVENT ID ALONE: an unrelated Application-channel event that happens to be 4104 would otherwise
// be labelled a script block. The TABLE severity stays Info deliberately — script-block logging is
// telemetry, not a verdict, and Info is exactly the floor the forensic gate uses to keep raw
// telemetry out of the AI's timeline. A script block that IS suspicious is promoted off this floor
// by scriptBlockSignal below, or by whatever else adjudicated it (a Sigma or DetectRaptor verdict,
// a tagger rule) — the table states the default, not the verdict.
// The label is the whole point of the entry: without it a parsed script block read as "Event 4104"
// or as the rendered message's boilerplate first line ("Creating Scriptblock text (1 of 1):").
export const POWERSHELL_EVENTS: Record<number, WinEventDef> = {
  4104: { label: "Script block logged", severity: "Info" },
  4103: { label: "Module/pipeline execution", severity: "Info" },
};

// Sysmon (Microsoft-Windows-Sysmon/Operational) events — keyed separately because the
// EID numbering overlaps the Security channel (Sysmon 1 ≠ Security 1).
export const SYSMON_EVENTS: Record<number, WinEventDef> = {
  1: { label: "Process create", severity: "Low", kind: "process", mitre: ["T1059"] },
  2: { label: "File creation time changed (timestomp)", severity: "Medium", mitre: ["T1070.006"] },
  3: { label: "Network connection", severity: "Low", kind: "network" },
  4: { label: "Sysmon service state changed", severity: "Info" },
  5: { label: "Process terminated", severity: "Info" },
  6: { label: "Driver loaded", severity: "Medium", mitre: ["T1543.003"] },
  7: { label: "Image (DLL) loaded", severity: "Low", mitre: ["T1574.002"] },
  8: { label: "CreateRemoteThread", severity: "Low", kind: "thread" },
  9: { label: "RawAccessRead", severity: "Medium", mitre: ["T1006"] },
  10: { label: "Process accessed", severity: "Info", kind: "procaccess" },
  11: { label: "File created", severity: "Low", kind: "file", fileAction: "create" },
  12: { label: "Registry object created/deleted", severity: "Low", mitre: ["T1112"] },
  13: { label: "Registry value set", severity: "Low", mitre: ["T1112"] },
  14: { label: "Registry object renamed", severity: "Low", mitre: ["T1112"] },
  15: { label: "Alternate data stream created", severity: "Info", kind: "stream" },
  17: { label: "Named pipe created", severity: "Low" },
  18: { label: "Named pipe connected", severity: "Low" },
  19: { label: "WMI event filter registered", severity: "Medium", mitre: ["T1546.003"] },
  20: { label: "WMI event consumer registered", severity: "Medium", mitre: ["T1546.003"] },
  21: { label: "WMI consumer-to-filter binding", severity: "Medium", mitre: ["T1546.003"] },
  22: { label: "DNS query", severity: "Low", kind: "dns", dns: SYSMON_22_DNS },
  23: {
    label: "File deleted (archived)",
    severity: "Low",
    mitre: ["T1070.004"],
    kind: "file",
    fileAction: "delete",
  },
  24: { label: "Clipboard changed", severity: "Low" },
  25: { label: "Process image tampering", severity: "High", kind: "tamper", mitre: ["T1055.012"] },
  26: {
    label: "File delete logged",
    severity: "Low",
    mitre: ["T1070.004"],
    kind: "file",
    fileAction: "delete",
  },
};

// The DNS Server's own Analytical log (dnsServerRecord.ts, #996) — 257/258/259 branch on the eid
// inside windowsDnsOverlay below, same as WFP 5156 above, so no `dns:` schema sits on these entries.
export const DNS_SERVER_EVENTS: Record<number, WinEventDef> = {
  257: { label: "DNS Server: response sent", severity: "Info", kind: "dns" },
  258: { label: "DNS Server: response failed", severity: "Low", kind: "dns" },
  259: { label: "DNS Server: query ignored", severity: "Low", kind: "dns" },
};

/** The channel's own table: the DNS Client's / Server's (dnsRecord.ts), Sysmon's, PowerShell's, else Security's. */
export function channelTable(channel: string): Record<number, WinEventDef> {
  if (/dns[ -]?client/i.test(channel)) return DNS_CLIENT_EVENTS;
  if (/dns[ -]?server/i.test(channel)) return DNS_SERVER_EVENTS;
  if (/sysmon/i.test(channel)) return SYSMON_EVENTS;
  if (/powershell/i.test(channel)) return POWERSHELL_EVENTS;
  return WIN_EVENTS;
}

/**
 * The single DNS overlay decision siemImport.ts's `mapWindows` needs, kept off that file's own
 * tight size budget: the event's own endpoint-vantage schema when it has one (Sysmon 22 /
 * DNS-Client), else dnsServerRecord.ts's resolver-vantage overlay when the eid is 257/258/259,
 * else none.
 */
export function windowsDnsOverlay(
  dnsSchema: DnsEventSchema | undefined,
  eid: number,
  read: (key: string) => unknown,
  description: string,
): DnsOverlay | DnsServerOverlay | null {
  if (dnsSchema) return dnsOverlay(read, dnsSchema, description);
  if (isDnsServerAnalyticEid(eid)) return dnsServerOverlay(read, eid, description);
  return null;
}
