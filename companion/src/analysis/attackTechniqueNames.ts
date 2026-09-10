// Dependency-free ATT&CK reference data and the pure helpers over it.
//
// Split out of reconTechniques.ts so the foundational half can sit at the lowest analysis tier.
// The id -> name table is reference data with no imports, and BOTH analysis/timeline (stateMerge,
// building the case's MITRE aggregate) and analysis/intel (reconTechniques, classifying command
// lines) need it. Matching command lines to techniques is intel work and stays there; naming a
// technique is not, and a tier-0 module is the only place a tier-0 caller may reach. #878.

// ATT&CK technique names — the recon set plus the techniques the deterministic importers commonly
// emit, so the MITRE table built from event tags reads with real names (falls back to the bare id).
const TECHNIQUE_NAMES: Readonly<Record<string, string>> = {
  T1033: "System Owner/User Discovery",
  T1016: "System Network Configuration Discovery",
  T1082: "System Information Discovery",
  "T1069.002": "Permission Groups Discovery: Domain Groups",
  "T1087.002": "Account Discovery: Domain Account",
  T1018: "Remote System Discovery",
  T1083: "File and Directory Discovery",
  "T1552.004": "Unsecured Credentials: Private Keys",
  "T1552.001": "Unsecured Credentials: Credentials in Files",
  T1003: "OS Credential Dumping",
  "T1003.001": "OS Credential Dumping: LSASS Memory",
  T1055: "Process Injection",
  T1059: "Command and Scripting Interpreter",
  "T1059.004": "Command and Scripting Interpreter: Unix Shell",
  T1071: "Application Layer Protocol",
  "T1071.001": "Application Layer Protocol: Web Protocols",
  T1105: "Ingress Tool Transfer",
  T1041: "Exfiltration Over C2 Channel",
  T1005: "Data from Local System",
  "T1560.001": "Archive Collected Data: Archive via Utility",
  "T1070.003": "Indicator Removal: Clear Command History",
  "T1070.002": "Indicator Removal: Clear Linux or Mac System Logs",
  "T1070.001": "Indicator Removal: Clear Windows Event Logs",
  T1036: "Masquerading",
  "T1204.002": "User Execution: Malicious File",
  "T1566.002": "Phishing: Spearphishing Link",
  "T1021.004": "Remote Services: SSH",
  T1140: "Deobfuscate/Decode Files or Information",
  "T1053.003": "Scheduled Task/Job: Cron",
  "T1543.002": "Create or Modify System Process: Systemd Service",
  "T1548.001": "Abuse Elevation Control Mechanism: Setuid and Setgid",
  // ── discovery + tradecraft techniques added from the DFIR Report corpus ──
  T1482: "Domain Trust Discovery",
  T1046: "Network Service Discovery",
  T1135: "Network Share Discovery",
  "T1518.001": "Security Software Discovery",
  "T1003.002": "OS Credential Dumping: Security Account Manager",
  "T1003.003": "OS Credential Dumping: NTDS",
  "T1003.006": "OS Credential Dumping: DCSync",
  T1555: "Credentials from Password Stores",
  "T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting",
  "T1114.002": "Email Collection: Remote Email Collection",
  "T1562.001": "Impair Defenses: Disable or Modify Tools",
  T1112: "Modify Registry",
  "T1548.002": "Abuse Elevation Control Mechanism: Bypass User Account Control",
  T1490: "Inhibit System Recovery",
  T1486: "Data Encrypted for Impact",
  T1489: "Service Stop",
  "T1021.002": "Remote Services: SMB/Windows Admin Shares",
  T1047: "Windows Management Instrumentation",
  T1572: "Protocol Tunneling",
  T1090: "Proxy",
  "T1567.002": "Exfiltration to Cloud Storage",
  T1219: "Remote Access Software",
  T1068: "Exploitation for Privilege Escalation",
  // ── discovery + tradecraft techniques added from the Huntress Rapid Response corpus ──
  "T1543.003": "Create or Modify System Process: Windows Service",
  "T1564.002": "Hide Artifacts: Hidden Users",
  "T1098.007": "Account Manipulation: Additional Local or Domain Groups",
  "T1222.002":
    "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification",
  "T1559.001": "Inter-Process Communication: Component Object Model",
  T1218: "System Binary Proxy Execution",
  "T1218.007": "System Binary Proxy Execution: Msiexec",
  "T1555.003": "Credentials from Password Stores: Credentials from Web Browsers",
};

// Best-effort ATT&CK technique name for a given id (falls back to the bare id).
export function techniqueName(id: string): string {
  return TECHNIQUE_NAMES[id] ?? id;
}

// Union the ATT&CK techniques carried by (in-scope) forensic events into the synthesized MITRE
// table, so deterministically-identified techniques the model didn't echo (esp. the Info/Low
// discovery phase) still appear in the case's MITRE table / report. Operates over the SAME
// scope/legitimate-filtered events synthesis saw, so it never reintroduces out-of-scope techniques.
// Pure + idempotent.
export function unionEventTechniques(
  table: ReadonlyArray<{ id: string; name: string; findingIds: string[] }>,
  events: ReadonlyArray<{ mitreTechniques: string[] }>,
): Array<{ id: string; name: string; findingIds: string[] }> {
  const have = new Set(table.map((t) => t.id));
  const out = table.map((t) => ({ ...t }));
  for (const e of events) {
    for (const id of e.mitreTechniques) {
      if (!id || have.has(id)) continue;
      have.add(id);
      out.push({ id, name: techniqueName(id), findingIds: [] });
    }
  }
  return out;
}
