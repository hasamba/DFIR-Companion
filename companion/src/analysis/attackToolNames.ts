// The project's named attack-tool lists, in one place so every pass that keys on a tool name reads
// the same names (#1970 part 1).
//
// OFFENSIVE_TOOLS and DUAL_USE grade a Prefetch / Amcache execution (prefetchExecution.ts). The AD
// recon tool names tag a command line (reconTechniques.ts). toolStoreFolder.ts reads all three to
// find one user-writable folder that holds several attack tools. They live here, in the timeline
// layer, because that pass runs at merge time and may not import the ingest or intel layers.
//
// Pure data. No I/O.

// Named offensive tooling — credential dumpers, token-theft frameworks, and the service-account
// → SYSTEM "Potato" family (RogueWinRM abuses the BITS/WinRM loopback the same way JuicyPotato
// abuses DCOM). A prefetch entry proves one of these RAN, which needs no argument to be a finding.
// Substring-matched on the executable name so `mimikatz_x64.exe`, `SafetyKatz.exe` and
// `RogueWinRM_v2.exe` all hit; each token is long and distinctive enough not to collide with a
// real product name.
export const OFFENSIVE_TOOLS: readonly { re: RegExp; ids: string[] }[] = [
  { re: /mimikatz|mimilib|safetykatz|kekeo/i, ids: ["T1003.001", "T1003.006"] },
  {
    re: /pwdump|gsecdump|\bwce(?:aux)?\b|secretsdump|nanodump|dumpert|handlekatz|sharpdump/i,
    ids: ["T1003"],
  },
  { re: /lazagne|donpapi|sessiongopher/i, ids: ["T1555"] },
  { re: /rubeus|kerbrute/i, ids: ["T1558.003"] },
  // Local privilege escalation from a service account to SYSTEM. RogueWinRM binds port 5985 and
  // coerces a BITS/WinRM authentication; the Potato family coerces DCOM/print-spooler the same way.
  {
    re: /roguewinrm|rogue_winrm|juicypotato|juicy_potato|sweetpotato|godpotato|badpotato|rottenpotato|hotpotato|printspoofer|efspotato|localpotato/i,
    ids: ["T1068", "T1134.002"],
  },
  // WinPwn — a PowerShell offensive framework whose loader drops a compiled helper; see the
  // matching command-line rule in tradecraftRules.ts (Add-Type AdjPriv token manipulation).
  { re: /winpwn|powerup|sharpup/i, ids: ["T1134.001", "T1068"] },
];

// Dual-use binaries whose EXECUTION is worth a look, with the technique each one indicates. Members
// of LOLBINS get their technique here; the rest are utilities that are not "LOLBins" in the
// process-create sense but whose appearance in an execution artifact is itself uncommon.
export const DUAL_USE: Readonly<Record<string, readonly string[]>> = {
  // Compile-after-delivery: the .NET/C# toolchain running on an endpoint. csc.exe + cvtres.exe fire
  // together when a payload is built in memory (PowerShell `Add-Type`, an MSBuild inline task).
  "csc.exe": ["T1027.004"],
  "cvtres.exe": ["T1027.004"],
  "vbc.exe": ["T1027.004"],
  "jsc.exe": ["T1027.004"],
  "ilasm.exe": ["T1027.004"],
  "msbuild.exe": ["T1027.004", "T1127.001"],
  // Application Compatibility shim database installation — a persistence + escalation primitive
  // with very little legitimate use outside application packaging.
  "sdbinst.exe": ["T1546.011"],
  // WMI MOF compilation — the file-based route to a permanent event subscription.
  "mofcomp.exe": ["T1546.003"],
  // Anti-forensics / defense tampering.
  "wevtutil.exe": ["T1070.001"],
  "taskkill.exe": ["T1562.001"],
  "vssadmin.exe": ["T1490"],
  "bcdedit.exe": ["T1490"],
  "wbadmin.exe": ["T1490"],
  // Ingress transfer + signed-binary proxy execution.
  "certutil.exe": ["T1105", "T1140"],
  "bitsadmin.exe": ["T1197", "T1105"],
  "mshta.exe": ["T1218.005"],
  // The PARENT technique only. A Prefetch entry shows regsvr32 ran and carries no command line, so
  // it cannot show whether the scriptlet sub-technique (T1218.010) applies — that needs the /i:
  // switch and a remote source, which tradecraftRules.ts matches on the command line.
  "regsvr32.exe": ["T1218"],
  "installutil.exe": ["T1218.004"],
  "regasm.exe": ["T1218.009"],
  "regsvcs.exe": ["T1218.009"],
  "cmstp.exe": ["T1218.003"],
  "odbcconf.exe": ["T1218.008"],
  "hh.exe": ["T1218.001"],
  "rundll32.exe": ["T1218.011"],
  "ftp.exe": ["T1105"],
  "curl.exe": ["T1105"],
  // Script hosts + remote execution.
  "wscript.exe": ["T1059.005"],
  "cscript.exe": ["T1059.007"],
  "psexec.exe": ["T1569.002", "T1021.002"],
  "psexesvc.exe": ["T1569.002"],
  "paexec.exe": ["T1569.002"],
  "at.exe": ["T1053.002"],
  // Cloud/bulk exfil tools (T1567.002). tradecraftRules maps these from a COMMAND LINE, but on a
  // prefetch/amcache row there is no command line — the execution name is all there is, and rclone
  // running on a workstation at all is worth a Medium. (A renamed rclone is caught by BinaryRename.)
  "rclone.exe": ["T1567.002"],
  "restic.exe": ["T1567.002"],
  "megasync.exe": ["T1567.002"],
  "megacmd.exe": ["T1567.002"],
};

// Remote-access (RMM) tools, by executable name. tradecraftRules.ts grades them from a COMMAND LINE;
// a Prefetch or Amcache row has none, so the name is all there is. Installing one is the most common
// operator persistence path, and admins install the same tools every day — so a bare execution is a
// Medium lead (prefetchExecution.ts), never a finding. Matched on the WHOLE leaf name so a
// `myteamviewer.exe` or a `.bak` copy stays silent. ScreenConnect's names are longer than the 29
// characters a Prefetch file keeps, so they also match truncated. The Amcache rule in
// data/tags.yaml (`amcache_remote_access_tool`) carries the same names; remoteAccessTools.test.ts
// keeps the two in step.
export const REMOTE_ACCESS_TOOLS: { readonly re: RegExp; readonly ids: readonly string[] } = {
  re: /^(?:(?:anydesk|rustdesk|teamviewer|teamviewer_service|logmein|lmiguardiansvc|ateraagent|meshagent|tacticalrmm|dwagent|rutserv|rfusclient|supremo)\.exe|screenconnect\.(?:clientservice|windowsclient)\.e(?:xe?)?)$/i,
  ids: ["T1219"],
};

// AD reconnaissance tooling, by the token its file and command names carry. reconTechniques.ts
// builds its T1087.002 command-line rule from this list; `ping castle` (with a space) is a
// command-line spelling only and stays there.
export const AD_RECON_TOOLS: readonly string[] = [
  "adfind",
  "sharphound",
  "bloodhound",
  "pingcastle",
  "adrecon",
  "seatbelt",
];
