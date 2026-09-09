import { techniqueName, unionEventTechniques } from "./attackTechniqueNames.js";
import { matchableCommand } from "./commandNormalize.js";
// Re-exported so existing importers keep one entry point for technique naming.
export { techniqueName, unionEventTechniques };

// Discovery / credential-access technique tagging for process command lines (recon-burst tagging).
// Individually-benign recon commands (whoami, ipconfig, net group, dir /s, findstr password, cat .env)
// rarely earn a finding on their own, but they ARE the attacker's host/domain/credential enumeration,
// and tagging each with its ATT&CK technique lets the case identify the discovery phase instead of
// leaving it as untyped Info noise. Pure + table-driven; shared by the Windows/Sysmon, ECAR and bash
// importers so the same command grades the same regardless of source. No AI.

export interface ReconRule {
  re: RegExp;
  ids: string[];
}

// Worst-first is irrelevant here — every matching rule's techniques are unioned. Patterns cover both
// Windows (whoami/ipconfig/net/systeminfo/arp/dir/findstr) and *nix (id/uname/find/grep/cat .env).
const RECON_RULES: ReconRule[] = [
  // T1033 System Owner/User Discovery
  {
    re: /\bwhoami\b|\bquser\b|\bquery\s+user\b|(?:^|[\\/\s"'])id(?:\s|$|\.exe)|\bwho\s|\bgetent\s+passwd\b/i,
    ids: ["T1033"],
  },
  // T1016 System Network Configuration Discovery
  {
    re: /\bipconfig\b|\bifconfig\b|\bip\s+(?:addr|a|route|link)\b|\broute\s+print\b|\bnetsh\b|\bnetstat\b|\bip\s+neigh\b/i,
    ids: ["T1016"],
  },
  // T1082 System Information Discovery
  {
    re: /\bsysteminfo\b|\buname\b|\bhostnamectl\b|get-computerinfo|\blscpu\b|\/etc\/os-release|\bsysctl\b\s+-a/i,
    ids: ["T1082"],
  },
  // T1069.002 Permission Groups Discovery: Domain Groups
  {
    re: /\bnet\s+group\b[^\n]*\/domain|\bnet\s+group\s+"?domain admins"?|\bget-adgroup\b|\bnet\s+localgroup\b[^\n]*\/domain/i,
    ids: ["T1069.002"],
  },
  // T1087.002 Account Discovery: Domain Account
  {
    re: /\bnet\s+user\b[^\n]*\/domain|\bnet\s+accounts\b[^\n]*\/domain|\bget-aduser\b|\bdsquery\b|\bnet\s+group\b[^\n]*\/domain/i,
    ids: ["T1087.002"],
  },
  // T1018 Remote System Discovery
  {
    re: /\barp\s+-a\b|\bnet\s+view\b|\bnltest\b[^\n]*(?:dclist|dsgetdc)|\bping\b[^\n]*-n\s|for\s+\/l[^\n]*ping/i,
    ids: ["T1018"],
  },
  // T1482 Domain Trust Discovery (nltest trust enum, AdFind trust dump — incl. renamed AdFind)
  {
    re: /\bnltest\b[^\n]*(?:domain_trusts|trusted_domains)|-sc\s+trustdmp\b|\bnltest\b\s+\/finduser/i,
    ids: ["T1482"],
  },
  // T1087.002 Account Discovery via AD-recon tooling (AdFind / BloodHound / PingCastle / ADRecon)
  {
    re: /\badfind(?:\.exe)?\b|-sc\s+trustdmp\b|\bsharphound\b|\bbloodhound\b|\bping\s*castle\b|\bpingcastle\b|\badrecon\b|\bseatbelt\b|\b\[adsisearcher\]/i,
    ids: ["T1087.002"],
  },
  // T1046 Network Service Discovery (port/host scanners — Advanced IP Scanner, SoftPerfect, masscan…)
  {
    re: /\badvanced\s*(?:ip|port)\s*scanner\b|\bsoftperfect\b|\bnetscan(?:\.exe)?\b|\bmasscan\b|\brustscan\b|\bkportscan\b|\bangryip\b|\bnmap\b/i,
    ids: ["T1046"],
  },
  // T1518.001 Security Software Discovery (AV-product enumeration)
  {
    re: /securitycenter2[^\n]*antivirusproduct|antivirusproduct[^\n]*get|get-mpcomputerstatus|get-mpthreat|\bsc\b[^\n]*query[^\n]*windefend/i,
    ids: ["T1518.001"],
  },
  // T1135 Network Share Discovery (share enumeration tooling)
  {
    re: /\binvoke-sharefinder\b|\bsharpshares\b|\bfinduncommonshares\b|\bnet\s+share\b|find-domainshare|get-netshare/i,
    ids: ["T1135"],
  },
  // T1083 File and Directory Discovery
  {
    re: /\bdir\b\s+[^\n]*\/s\b|\bwhere\b\s+\/r\b|\bfind\b\s+[\\/][^\n]*-name|\bfind\b\s+\/[a-z]\b|get-childitem[^\n]*-recurse|\bls\s+-r\b|\btree\b|\blocate\b/i,
    ids: ["T1083"],
  },
  // T1552.004 Unsecured Credentials: Private Keys
  {
    re: /\.ssh(?:\b|[\\/])|\bid_rsa\b|\bid_dsa\b|\bid_ecdsa\b|\bid_ed25519\b|\.pem\b|\.ppk\b|authorized_keys\b/i,
    ids: ["T1552.004"],
  },
  // T1552.001 Unsecured Credentials: Credentials In Files
  {
    re: /\bfindstr\b[^\n]*password|\bselect-string\b[^\n]*password|\bgrep\b[^\n]*password|(?:cat|type)\b[^\n]*\.env\b|\.env\b|stripe_secret|aws_secret|database_url|\bfindstr\b[^\n]*secret/i,
    ids: ["T1552.001"],
  },
  // ── Action techniques (collection / exfil / anti-forensics / transfer / lateral) — these survive
  // in EDR/Sysmon process telemetry even when the shell history that would carry them is cleared. ──
  // T1105 Ingress Tool Transfer (download-to-disk tooling — specific patterns, not a bare curl)
  {
    re: /downloadfile|invoke-webrequest[^\n]*-outfile|\bcertutil\b[^\n]*-urlcache|\bbitsadmin\b[^\n]*\/transfer|\bwget\b[^\n]*\s-O\b|\bcurl\b[^\n]*\s-o\b/i,
    ids: ["T1105"],
  },
  // T1005 Data from Local System (bulk DB dump)
  { re: /\bmysqldump\b|\bpg_dump(?:all)?\b|\bmongodump\b/i, ids: ["T1005"] },
  // T1560.001 Archive Collected Data: Archive via Utility
  {
    re: /\btar\b[^\n]*\s-[a-z]*c[a-z]*f|\bzip\b\s+-r\b|\bgzip\b\s+\S|\b7z\b\s+a\b|compress-archive|\brar\b\s+a\b/i,
    ids: ["T1560.001"],
  },
  // T1041 Exfiltration Over C2 Channel (file upload via web client)
  { re: /(?:curl|wget)\b[^\n]*(?:--data-binary|--upload-file|\s-T\b|\s-F\b|--form|-d\s+@)/i, ids: ["T1041"] },
  // T1070.003 Indicator Removal: Clear Command History
  {
    re: /\bhistory\s+-c\b|unset\s+histfile|histfile=\/dev\/null|histsize=0\b|histignore=\*|(?:rm|truncate|>\s*)\s*[^\n]*\.bash_history|clear-history/i,
    ids: ["T1070.003"],
  },
  // T1070.001 Indicator Removal: Clear Windows Event Logs
  { re: /\bwevtutil\b\s+cl\b|clear-eventlog|remove-eventlog|wevtutil\b[^\n]*clear-log/i, ids: ["T1070.001"] },
  // T1021.004 Remote Services: SSH
  { re: /\bssh\b\s+[^\n]*@|\bscp\b\s+[^\n]*@[^\n]*:/i, ids: ["T1021.004"] },
];

// The ATT&CK technique ids a process command line indicates (deduped) — discovery / credential
// access plus the action techniques (collection / exfil / anti-forensics / transfer / SSH) that
// survive in EDR/Sysmon telemetry even when the shell history is cleared.
export function reconTechniques(image: string, cmd: string): string[] {
  // Original first, de-escaped copy second (#908 item 1) — see commandNormalize.ts.
  const blob = matchableCommand(`${image} ${cmd}`);
  const out = new Set<string>();
  for (const rule of RECON_RULES) if (rule.re.test(blob)) for (const id of rule.ids) out.add(id);
  return [...out];
}
