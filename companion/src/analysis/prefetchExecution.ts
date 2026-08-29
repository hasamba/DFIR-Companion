// What a Prefetch entry says about the binary that ran — the only grading signal an execution
// artifact can carry.
//
// Prefetch (and the Timeline.Prefetch.Improved variant) records that a binary EXECUTED, how many
// times, and when. It records no command line, no parent, and no user. Every row therefore arrived
// at Info, and Info sits below the forensic floor, so AI synthesis never read a single one. On a
// three-hour ransomware intrusion that dropped the whole execution chain — sdbinst.exe (6 runs),
// csc.exe + cvtres.exe (6 runs each), certutil.exe (5), wevtutil.exe (10), taskkill.exe, mofcomp.exe
// — while the same binaries would have graded Medium/High the moment a 4688 named them.
//
// The grade this module hands back is deliberately CONSERVATIVE, because the missing command line is
// the whole difficulty: `wevtutil qe` (routine) and `wevtutil cl` (log destruction) leave identical
// prefetch entries. So:
//
//   • Medium — the binary is dual-use. Attackers reach for it constantly, admins use it too, and
//     without arguments neither reading can be ruled out. Medium is this project's "a lead to
//     triage", which is exactly what an unargumented LOLBin execution is. It is visible to
//     synthesis; it is not a verdict.
//   • High — the binary is named offensive tooling with essentially no legitimate use (mimikatz,
//     the Potato family, RogueWinRM). The name alone IS the finding.
//   • null — everything else stays Info, as before. Prefetch is mostly a list of the programs a
//     person uses, and grading that list is how a real signal gets buried.
//
// Two entries in the corpus that prompted this module are NOT graded on the name, on purpose:
//
//   • `vssvc.exe` — the Volume Shadow Copy Service. It executes on every backup, every restore
//     point, and every Windows Update. Grading it as T1490 would mark a routine OS service on
//     virtually every host in every case.
//   • `cookie_exporter.exe` / `identity_helper.exe` — both are STOCK Microsoft Edge components
//     shipped inside the Edge application directory, not attacker tools. They are graded only when
//     the recorded path is outside a browser install directory, which is the shape that actually
//     matters: the Edge cookie exporter copied elsewhere and run to dump a session.
//
// Pure + table-driven + unit-tested. No I/O, no mutation. Companion to tradecraftRules.ts, which
// grades a COMMAND LINE; this grades a bare execution, and the two never see the same evidence.

import type { Severity } from "./stateTypes.js";
import { LOLBINS, NOISY_LOLBINS } from "./winProcessBaseline.js";

export interface PrefetchSignal {
  severity: Severity;
  mitre: string[];
}

// Named offensive tooling — credential dumpers, token-theft frameworks, and the service-account
// → SYSTEM "Potato" family (RogueWinRM abuses the BITS/WinRM loopback the same way JuicyPotato
// abuses DCOM). A prefetch entry proves one of these RAN, which needs no argument to be a finding.
// Substring-matched on the executable name so `mimikatz_x64.exe`, `SafetyKatz.exe` and
// `RogueWinRM_v2.exe` all hit; each token is long and distinctive enough not to collide with a
// real product name.
const OFFENSIVE_TOOLS: { re: RegExp; ids: string[] }[] = [
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
const DUAL_USE: Record<string, string[]> = {
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
  "regsvr32.exe": ["T1218.010"],
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

// A binary that ships INSIDE a browser and is only itself there. Both are ordinary Edge/Chromium
// components; run from anywhere else, `cookie_exporter.exe` is the documented way to lift another
// profile's cookie store and `identity_helper.exe` is a plausible masquerade host.
const BROWSER_HELPERS = /^(?:cookie_exporter|identity_helper|msedge_identity_helper)\.exe$/i;
const BROWSER_INSTALL_PATH =
  /\\(?:microsoft\\edge(?:core|webview|dev|beta)?|google\\chrome(?:\s*beta|\s*dev)?|brave(?:software)?|mozilla firefox|chromium|vivaldi|opera(?:\s*software)?)\\/i;

// The bare lowercase filename of an executable, from either the name column or a device path.
function leafName(value: string): string {
  const parts = String(value ?? "")
    .trim()
    .replace(/["']/g, "")
    .split(/[\\/]/);
  return (parts[parts.length - 1] ?? "").trim().toLowerCase();
}

/**
 * Grade one Prefetch execution, or null to leave it at Info.
 *
 * `exe` is the executable name the artifact recorded (`Executable`); `exePath` is its recorded path
 * (`ExecutablePath` — usually a `\DEVICE\HARDDISKVOLUMEn\...` form), used only for the browser-helper
 * location test. Either may be empty.
 */
export function prefetchSignal(exe: string, exePath = ""): PrefetchSignal | null {
  const name = leafName(exe) || leafName(exePath);
  if (!name) return null;

  for (const rule of OFFENSIVE_TOOLS) {
    if (rule.re.test(name)) return { severity: "High", mitre: [...rule.ids] };
  }

  if (BROWSER_HELPERS.test(name)) {
    const where = String(exePath ?? "").trim();
    // An ABSENT path is not evidence of anything, and many Windows.Forensics.Prefetch exports ship
    // the Executable column with no ExecutablePath beside it. Reading an empty path as "not in the
    // browser directory" would grade every stock Edge helper on those collections — the exact false
    // positive this guard exists to prevent — so an unknown location stays silent.
    if (!where) return null;
    // Inside a browser install this is the browser doing its job — say nothing.
    if (BROWSER_INSTALL_PATH.test(where)) return null;
    return { severity: "Medium", mitre: ["T1539", "T1036.005"] };
  }

  const ids = DUAL_USE[name];
  if (ids) return { severity: "Medium", mitre: [...ids] };

  // Any remaining LOLBin, minus the ones that run constantly on a stock host (cmd/powershell/
  // rundll32/… — see NOISY_LOLBINS), whose presence in prefetch says nothing at all. The named
  // entries above already override this for the LOLBins worth a specific technique.
  if (LOLBINS.has(name) && !NOISY_LOLBINS.has(name)) return { severity: "Medium", mitre: [] };

  return null;
}
