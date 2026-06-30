// Deterministic "attacker tradecraft" grading for Windows process command lines, harvested from a
// corpus of real intrusions (The DFIR Report public reports, 2020–2026). This COMPLEMENTS
// `isSuspiciousCmd` (siemImport) — which grades the classic credential-dump / log-clear patterns and
// hardcodes a T1003 tag on a strong hit — by covering the OTHER high-confidence behaviours seen
// across dozens of intrusions (Defender/AV tampering, recovery inhibition, reverse-tunnel C2,
// Impacket-style lateral movement, cloud exfil, RMM/C2 tooling) AND carrying the CORRECT ATT&CK
// technique per match, so a Defender-disable is tagged T1562.001 rather than mislabelled credential
// access.
//
// Tiering mirrors this project's signal-to-noise discipline (the benign-LSASS / benign-Defender
// fixes): only behaviour that is almost never benign on a server earns "strong" (→ High); dual-use
// tooling that is suspicious in an incident context is "weak" (→ Medium). PURE host *discovery* /
// enumeration (nltest, AdFind queries, BloodHound, port scanners) is deliberately NOT here — it is
// tag-only in `reconTechniques.ts` so it never manufactures a false High/Medium.
//
// Pure + table-driven + unit-tested; reused by the Windows/Sysmon/EVTX/Chainsaw/Velociraptor path
// (siemImport), the ECAR EDR feed and the memory-forensics importer. No AI.

export interface TradecraftRule {
  re: RegExp;
  weight: "strong" | "weak";
  ids: string[];
}

// Worst-first is irrelevant — a command may match several rules; their techniques are unioned and
// the strongest weight wins. Every `re` is anchored on literal tokens with bounded `[^\n]*` runs (no
// nested quantifiers) so there is no catastrophic backtracking.
export const TRADECRAFT_RULES: TradecraftRule[] = [
  // ───────────── Defense Evasion: impair Microsoft Defender / AV (T1562.001) ─────────────
  // Recurs in nearly every ransomware intrusion in the corpus.
  { re: /\bset-mppreference\b[^\n]*-disable(?:realtimemonitoring|behaviormonitoring|scriptscanning|ioavprotection|blockatfirstseen|archivescanning)/i, weight: "strong", ids: ["T1562.001"] },
  { re: /\bset-mppreference\b[^\n]*(?:-mapsreporting\s+0|-submitsamplesconsent\s+[2-4]|-severethreatdefaultaction)/i, weight: "strong", ids: ["T1562.001"] },
  { re: /\badd-mppreference\b[^\n]*-exclusion(?:path|process|extension)/i, weight: "strong", ids: ["T1562.001"] },
  { re: /\bset-mppreference\b[^\n]*-exclusion(?:path|process|extension)/i, weight: "strong", ids: ["T1562.001"] },
  { re: /\buninstall-windowsfeature\b[^\n]*windows-defender/i, weight: "strong", ids: ["T1562.001"] },
  { re: /\b(?:net|net1|sc)(?:\.exe)?\b[^\n]*\b(?:stop|config|delete|disabled)\b[^\n]*\b(?:windefend|wdnissvc|wdfilter|wdboot|sense|securityhealthservice|wscsvc|mpssvc)\b/i, weight: "strong", ids: ["T1562.001"] },
  { re: /\bdisableantispyware\b|\bdisableantivirus\b|\bdisablerealtimemonitoring\b|\btamperprotection\b[^\n]*\b0\b/i, weight: "strong", ids: ["T1562.001"] },
  { re: /\bdefender\s*control\b|\bdefendercontrol\b|\bdis_defender\b|\bdefendermalwar/i, weight: "strong", ids: ["T1562.001"] },
  // BYOVD: known vulnerable / AV-killer drivers dropped and loaded.
  { re: /\b(?:rwdrv|hlpdrv|winring0x?64|aswarpot|truesight|kArtos|gdrv|dbutil_?2_?3|msio64|procexp1?[56]?\d?)\.sys\b/i, weight: "strong", ids: ["T1562.001"] },
  // AV/EDR-killer GUI tools (PowerTool/GMER/IObit Unlocker); ProcessHacker is dual-use → weak.
  { re: /\b(?:powertool64?|gmer(?:64)?|iobit\s*unlocker)\b/i, weight: "strong", ids: ["T1562.001"] },
  { re: /\bprocess\s*hacker\b|\bprocesshacker\b/i, weight: "weak", ids: ["T1562.001"] },

  // ───────────── Defense Evasion: weaken auth / UAC policy via registry ─────────────
  { re: /\brunasppl\b[^\n]*\b0\b/i, weight: "strong", ids: ["T1562.001"] }, // disable LSA Protection (PPL)
  { re: /\buselogoncredential\b[^\n]*\b1\b/i, weight: "strong", ids: ["T1003.001"] }, // WDigest plaintext creds
  { re: /\bdisablerestrictedadmin\b[^\n]*\b0\b/i, weight: "strong", ids: ["T1112"] }, // enable RDP pass-the-hash
  { re: /\benablelua\b[^\n]*\b0\b|\bconsentpromptbehavioradmin\b[^\n]*\b0\b/i, weight: "strong", ids: ["T1548.002"] },
  { re: /ms-settings\\shell\\open\\command/i, weight: "strong", ids: ["T1548.002"] }, // fodhelper/computerdefaults hijack
  { re: /\b(?:fodhelper|computerdefaults|wsreset|slui)\.exe\b/i, weight: "weak", ids: ["T1548.002"] },

  // ───────────── Credential Access not covered by isSuspiciousCmd ─────────────
  { re: /lsadump::(?:dcsync|sam|lsa|secrets)/i, weight: "strong", ids: ["T1003.006"] },
  { re: /\bdcsync\b|\bsecretsdump(?:\.py|\.exe)?\b/i, weight: "strong", ids: ["T1003.006"] },
  { re: /\blsassy\b/i, weight: "strong", ids: ["T1003.001"] },
  { re: /\b(?:nxc|netexec|crackmapexec|cme)\b[^\n]*(?:--ntds|-m\s+lsassy|--sam|--lsa|--dpapi)/i, weight: "strong", ids: ["T1003"] },
  { re: /\besentutl(?:\.exe)?\b[^\n]*(?:\/vss|\/y)[^\n]*ntds|\bntdsutil\b[^\n]*\bac\s+i(?:n)?\s+ntds\b/i, weight: "strong", ids: ["T1003.003"] },
  // SAM is already covered by isSuspiciousCmd; the SECURITY/SYSTEM hive companions are not.
  { re: /\breg(?:\.exe)?\b[^\n]*\bsave\b[^\n]*hk(?:lm|ey_local_machine)\\?(?:security|system)\b/i, weight: "strong", ids: ["T1003.002"] },
  { re: /\b(?:lazagne|donpapi|invoke-powerdump|invoke-sessiongopher|credentialsfileview|webbrowserpassview|chromepass|vncpassview|mailpv|netpass|wirelesskeyview|passrecenc|ntdsaudit)\b/i, weight: "strong", ids: ["T1555"] },
  { re: /\b(?:rubeus|orpheus)\b|\bget-?userspns(?:\.py)?\b|\binvoke-kerberoast\b/i, weight: "strong", ids: ["T1558.003"] },
  { re: /\bnew-mailboxexportrequest\b/i, weight: "strong", ids: ["T1114.002"] },
  { re: /\bpsql(?:\.exe)?\b[^\n]*from\s+credentials|\bveeam-get-creds/i, weight: "strong", ids: ["T1555"] },
  { re: /\bcmdkey\b\s+\/list\b/i, weight: "weak", ids: ["T1555"] },
  { re: /\bsetspn(?:\.exe)?\b\s+-/i, weight: "weak", ids: ["T1558.003"] },

  // ───────────── Impact: inhibit system recovery (T1490) ─────────────
  { re: /\bwmic(?:\.exe)?\b[^\n]*shadowcopy\s+delete|win32_shadowcopy[^\n]*(?:remove-wmiobject|remove-ciminstance|delete)/i, weight: "strong", ids: ["T1490"] },
  { re: /\bbcdedit(?:\.exe)?\b[^\n]*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/i, weight: "strong", ids: ["T1490"] },
  { re: /\bwbadmin(?:\.exe)?\b[^\n]*delete\s+(?:catalog|systemstatebackup)|\bvssadmin\b[^\n]*resize\s+shadowstorage/i, weight: "strong", ids: ["T1490"] },
  { re: /\bget-vm\b[^\n]*stop-vm|\bdisable-computerrestore\b/i, weight: "strong", ids: ["T1490"] },
  // Forced reboot to Safe Mode so EDR/AV is offline during encryption (REvil/Snatch et al.).
  { re: /\bbcdedit(?:\.exe)?\b[^\n]*safeboot|\bbootcfg\b[^\n]*safeboot|\s-smode\b/i, weight: "strong", ids: ["T1490"] },

  // ───────────── Impact: stop backup/DB services before encryption (T1489) — dual-use → weak ──────
  { re: /\b(?:net|net1)\s+stop\b[^\n]*\b(?:veeam|sqlserveragent|mssql|msexchange|backupexec|acronis|sophos)/i, weight: "weak", ids: ["T1489"] },
  { re: /\btaskkill\b[^\n]*\/im\b[^\n]*\b(?:veeam|sqlservr|sqlagent|sqlwriter|msexchange)/i, weight: "weak", ids: ["T1489"] },

  // ───────────── Lateral Movement / remote exec (T1047 / T1021.002) ─────────────
  { re: /\b(?:wmiexec|smbexec|atexec|dcomexec|psexec)\.py\b/i, weight: "strong", ids: ["T1021.002"] },
  { re: /\\\\127\.0\.0\.1\\admin\$\\__/i, weight: "strong", ids: ["T1047"] }, // Impacket exec output redirect
  { re: /\bwmic(?:\.exe)?\b[^\n]*\/node:[^\n]*process\s+call\s+create/i, weight: "strong", ids: ["T1047"] },
  { re: /\binvoke-(?:smbexec|wmiexec|psexec|dcom)\b/i, weight: "strong", ids: ["T1021.002"] },
  { re: /\bpsexec(?:\.exe)?\b[^\n]*@\S+\.(?:txt|list)\b/i, weight: "weak", ids: ["T1021.002"] }, // mass push via host-list

  // ───────────── Command & Control: tunneling / proxy (T1572 / T1090) ─────────────
  { re: /\bssh(?:\.exe)?\b[^\n]*\s-R\b|\bplink(?:\.exe)?\b[^\n]*(?:\s-R\b|-no-antispoof)|\bportfwd\b[^\n]*\s-R\b/i, weight: "strong", ids: ["T1572"] },
  { re: /\bssh(?:\.exe)?\b[^\n]*\s-D\b/i, weight: "strong", ids: ["T1090"] }, // SSH SOCKS proxy
  { re: /\bnc(?:\.exe)?\b[^\n]*\s-e\b[^\n]*(?:\/bin\/(?:ba)?sh|cmd(?:\.exe)?)/i, weight: "strong", ids: ["T1059.004"] }, // netcat reverse shell
  { re: /\bngrok\b|\bcloudflared\b|\bfrpc?\b(?:\.exe|\.ini)?|\bpowercat\b|\bproxychains\b|\bgost(?:\.exe)?\b/i, weight: "weak", ids: ["T1572"] },

  // ───────────── Exfiltration tooling (T1567.002 / T1560.001) ─────────────
  { re: /\brclone(?:\.exe)?\b[^\n]*\b(?:mega|wasabi|dropbox|gdrive|drive|s3|b2|backblaze|onedrive|pcloud|ftp|sftp|swift|box|azureblob):/i, weight: "strong", ids: ["T1567.002"] },
  { re: /\brclone(?:\.exe)?\b[^\n]*\b(?:copy|sync|move|lsd)\b/i, weight: "weak", ids: ["T1567.002"] },
  { re: /\brestic(?:\.exe)?\b[^\n]*(?:\bbackup\b|rest:http)/i, weight: "strong", ids: ["T1567.002"] },
  { re: /\b(?:megacmd|megasync)\b|\bmega\.nz\b/i, weight: "weak", ids: ["T1567.002"] },
  { re: /\b(?:winrar|rar)(?:\.exe)?\b[^\n]*\s-(?:ep1|scul|iext|imon1)\b/i, weight: "weak", ids: ["T1560.001"] }, // WinRAR staging fingerprint

  // ───────────── Remote-access (RMM) tooling abused for access / persistence (T1219) ─────────────
  // Unattended-install flags are the attacker fingerprint → strong; bare presence is dual-use → weak.
  { re: /\b(?:anydesk|rustdesk)\b[^\n]*(?:--set-password|--start-with-win|--tray|--silent)/i, weight: "strong", ids: ["T1219"] },
  { re: /\b(?:anydesk|rustdesk|screenconnect|connectwise|atera|splashtop|meshagent|tacticalrmm|gotoresolve|goto\s*resolve|netsupport|client32\.ini|dwagent|remoteutilities|pulseway|action1|level\.io|supremo)/i, weight: "weak", ids: ["T1219"] },

  // ───────────── Named offensive C2 / exploitation tooling (dual-use → weak) ─────────────
  { re: /\bcobalt\s*strike\b|\bbrute\s*ratel\b|\bbruteratel\b|\bposh\s*c2\b|\bkoadic\b|\badaptixc2\b|\bmeterpreter\b|\bmetasploit\b|\bsliver\b/i, weight: "weak", ids: ["T1071"] },
  { re: /\bcertipy\b|\bnopac\b|\bpachine\b|\bzerologon\b|\bzer0dump\b|\bsharpprintnightmare\b|\bpetitpotam\b|\bcoercer\b|\bnoPac\b/i, weight: "weak", ids: ["T1068"] },
];

// The weight + ATT&CK techniques a process command line indicates, or null. Strong wins over weak;
// techniques across all matching rules are unioned. `image` and `cmd` are concatenated so a rule can
// anchor on either the binary or its arguments.
export function tradecraftSignal(image: string, cmd: string): { weight: "strong" | "weak"; mitre: string[] } | null {
  const blob = `${image} ${cmd}`;
  let strong = false;
  let weak = false;
  const mitre = new Set<string>();
  for (const rule of TRADECRAFT_RULES) {
    if (!rule.re.test(blob)) continue;
    if (rule.weight === "strong") strong = true;
    else weak = true;
    for (const id of rule.ids) mitre.add(id);
  }
  if (!strong && !weak) return null;
  return { weight: strong ? "strong" : "weak", mitre: [...mitre] };
}
