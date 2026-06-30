// Discovery / credential-access technique tagging for process command lines (recon-burst tagging).
// Individually-benign recon commands (whoami, ipconfig, net group, dir /s, findstr password, cat .env)
// rarely earn a finding on their own, but they ARE the attacker's host/domain/credential enumeration,
// and tagging each with its ATT&CK technique lets the case identify the discovery phase instead of
// leaving it as untyped Info noise. Pure + table-driven; shared by the Windows/Sysmon, ECAR and bash
// importers so the same command grades the same regardless of source. No AI.

export interface ReconRule { re: RegExp; ids: string[]; }

// Worst-first is irrelevant here — every matching rule's techniques are unioned. Patterns cover both
// Windows (whoami/ipconfig/net/systeminfo/arp/dir/findstr) and *nix (id/uname/find/grep/cat .env).
const RECON_RULES: ReconRule[] = [
  // T1033 System Owner/User Discovery
  { re: /\bwhoami\b|\bquser\b|\bquery\s+user\b|(?:^|[\\/\s"'])id(?:\s|$|\.exe)|\bwho\s|\bgetent\s+passwd\b/i, ids: ["T1033"] },
  // T1016 System Network Configuration Discovery
  { re: /\bipconfig\b|\bifconfig\b|\bip\s+(?:addr|a|route|link)\b|\broute\s+print\b|\bnetsh\b|\bnetstat\b|\bip\s+neigh\b/i, ids: ["T1016"] },
  // T1082 System Information Discovery
  { re: /\bsysteminfo\b|\buname\b|\bhostnamectl\b|get-computerinfo|\blscpu\b|\/etc\/os-release|\bsysctl\b\s+-a/i, ids: ["T1082"] },
  // T1069.002 Permission Groups Discovery: Domain Groups
  { re: /\bnet\s+group\b[^\n]*\/domain|\bnet\s+group\s+"?domain admins"?|\bget-adgroup\b|\bnet\s+localgroup\b[^\n]*\/domain/i, ids: ["T1069.002"] },
  // T1087.002 Account Discovery: Domain Account
  { re: /\bnet\s+user\b[^\n]*\/domain|\bnet\s+accounts\b[^\n]*\/domain|\bget-aduser\b|\bdsquery\b|\bnet\s+group\b[^\n]*\/domain/i, ids: ["T1087.002"] },
  // T1018 Remote System Discovery
  { re: /\barp\s+-a\b|\bnet\s+view\b|\bnltest\b[^\n]*(?:dclist|dsgetdc)|\bnmap\b|\bping\b[^\n]*-n\s|for\s+\/l[^\n]*ping/i, ids: ["T1018"] },
  // T1083 File and Directory Discovery
  { re: /\bdir\b\s+[^\n]*\/s\b|\bwhere\b\s+\/r\b|\bfind\b\s+[\\/][^\n]*-name|\bfind\b\s+\/[a-z]\b|get-childitem[^\n]*-recurse|\bls\s+-r\b|\btree\b|\blocate\b/i, ids: ["T1083"] },
  // T1552.004 Unsecured Credentials: Private Keys
  { re: /\.ssh(?:\b|[\\/])|\bid_rsa\b|\bid_dsa\b|\bid_ecdsa\b|\bid_ed25519\b|\.pem\b|\.ppk\b|authorized_keys\b/i, ids: ["T1552.004"] },
  // T1552.001 Unsecured Credentials: Credentials In Files
  { re: /\bfindstr\b[^\n]*password|\bselect-string\b[^\n]*password|\bgrep\b[^\n]*password|(?:cat|type)\b[^\n]*\.env\b|\.env\b|stripe_secret|aws_secret|database_url|\bfindstr\b[^\n]*secret/i, ids: ["T1552.001"] },
];

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
  T1036: "Masquerading",
  "T1204.002": "User Execution: Malicious File",
  "T1566.002": "Phishing: Spearphishing Link",
  "T1021.004": "Remote Services: SSH",
  T1140: "Deobfuscate/Decode Files or Information",
  "T1053.003": "Scheduled Task/Job: Cron",
  "T1543.002": "Create or Modify System Process: Systemd Service",
  "T1548.001": "Abuse Elevation Control Mechanism: Setuid and Setgid",
};

// Best-effort ATT&CK technique name for a given id (falls back to the bare id).
export function techniqueName(id: string): string {
  return TECHNIQUE_NAMES[id] ?? id;
}

// The discovery / credential-access ATT&CK technique ids a process command line indicates (deduped).
export function reconTechniques(image: string, cmd: string): string[] {
  const blob = `${image} ${cmd}`;
  const out = new Set<string>();
  for (const rule of RECON_RULES) if (rule.re.test(blob)) for (const id of rule.ids) out.add(id);
  return [...out];
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
