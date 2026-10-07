// Canonical Windows event-log channel names (#1996).
//
// Hayabusa abbreviates channels in its output ("Sysmon", "Sec", "Sys", "App", ...). Every other
// EVTX reader writes the long name. Two places compare or key on the channel — the record identity
// that dedups one record across parsers, and the act check that reads a Sysmon or 4688 launch — and
// both need the long form, or a short name silently loses the envelope and doubles the timeline row.
//
// Pure. A name that is not a known abbreviation passes through unchanged.

const SHORT_TO_LONG: Readonly<Record<string, string>> = {
  sec: "Security",
  sys: "System",
  app: "Application",
  sysmon: "Microsoft-Windows-Sysmon/Operational",
  pwsh: "Microsoft-Windows-PowerShell/Operational",
  pwshclassic: "Windows PowerShell",
  winrm: "Microsoft-Windows-WinRM/Operational",
  tasksch: "Microsoft-Windows-TaskScheduler/Operational",
  defender: "Microsoft-Windows-Windows Defender/Operational",
  firewall: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
  "dhcp-svr": "Microsoft-Windows-DHCP-Server/Operational",
  "dns-svr": "DNS Server",
  bits: "Microsoft-Windows-Bits-Client/Operational",
  wmi: "Microsoft-Windows-WMI-Activity/Operational",
  ntlm: "Microsoft-Windows-NTLM/Operational",
};

/** The long channel name for a Hayabusa abbreviation, else the input unchanged (trimmed). */
export function canonicalChannel(name: string): string {
  const trimmed = name.trim();
  return SHORT_TO_LONG[trimmed.toLowerCase()] ?? trimmed;
}
