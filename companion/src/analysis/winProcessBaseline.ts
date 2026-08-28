// What a normal Windows host looks like — the baseline the SIEM/Sysmon grader measures against.
//
// Everything here answers "is this ordinary?", which is a different question from "is this attacker
// tradecraft?" (STRONG_CMD / SUSP_CMD / tradecraftRules.ts, which stay beside the grader). Keeping
// the two apart matters because they fail in opposite directions: a gap in the tradecraft lists
// costs a detection, a gap HERE costs signal-to-noise across every event the importer emits.

// LOLBins — the binaries attackers reach for because they are already on the box. Appearing as
// the image (Sysmon 1 / 4688) bumps a process-create, EXCEPT for the everyday ones listed in
// NOISY_LOLBINS below, which need a command-line or path signal to go with the name.
export const LOLBINS = new Set([
  "powershell.exe",
  "pwsh.exe",
  "cmd.exe",
  "wscript.exe",
  "cscript.exe",
  "mshta.exe",
  "rundll32.exe",
  "regsvr32.exe",
  "wmic.exe",
  "certutil.exe",
  "bitsadmin.exe",
  "msiexec.exe",
  "installutil.exe",
  "regasm.exe",
  "regsvcs.exe",
  "msbuild.exe",
  "cmstp.exe",
  "schtasks.exe",
  "at.exe",
  "sc.exe",
  "net.exe",
  "net1.exe",
  "psexec.exe",
  "psexesvc.exe",
  "vssadmin.exe",
  "bcdedit.exe",
  "wevtutil.exe",
  "reg.exe",
  "curl.exe",
  "ftp.exe",
  "hh.exe",
  "odbcconf.exe",
]);
// The LOLBins above that are ALSO ordinary. Each of these runs constantly on a stock managed
// endpoint — every installer shells out to cmd.exe, every logon script calls net.exe, Intune/SCCM
// live in powershell.exe, the shell itself is a rundll32.exe caller — so the image name alone
// carries no information. Grading them Medium on the name put thousands of benign process
// creations above the forensic gate's Low floor, which is how the genuinely rare malicious row
// (an encoded command out of \Temp\) ends up indistinguishable from a printer driver loading.
//
// They are NOT removed from LOLBINS: paired with a command-line or path signal they still grade,
// and they still carry their ATT&CK context. They simply stop being a verdict on their own.
// The rest of LOLBINS keeps the standalone bump, because mshta.exe / certutil.exe / bitsadmin.exe /
// installutil.exe appearing at all on an endpoint IS the anomaly.
export const NOISY_LOLBINS = new Set([
  "cmd.exe",
  "powershell.exe",
  "pwsh.exe",
  "msiexec.exe",
  "rundll32.exe",
  "net.exe",
  "net1.exe",
  "sc.exe",
  "reg.exe",
  "schtasks.exe",
  "wmic.exe",
  "curl.exe",
]);

// Core OS processes that legitimately CreateRemoteThread as routine session/service setup, PLUS
// Windows Defender / Defender-for-Endpoint, which inject monitoring threads into user processes as
// part of behavioral scanning — a benign EID 8 source, not injection tradecraft. Also the desktop/
// shell brokers that routinely inject as part of ordinary UI plumbing: Windows Search indexing its
// own protocol host, dllhost.exe (COM Surrogate) loading shell-extension/COM objects, and the UWP
// app-model brokers taskhostw/RuntimeBroker — all fire constantly on a stock, uncompromised desktop
// and otherwise drown real injection signal in noise (see the fairhaven-rdp-takeover benchmark,
// where this exact pairing on unrelated hosts got escalated into a fabricated finding).
export const BENIGN_THREAD_SOURCES = new Set([
  "csrss.exe",
  "wininit.exe",
  "services.exe",
  "smss.exe",
  "svchost.exe",
  "wmiprvse.exe",
  "lsm.exe",
  "winlogon.exe",
  "msmpeng.exe",
  "mpdefendercoreservice.exe",
  "mssense.exe",
  "sensendr.exe",
  "mpcmdrun.exe", // Defender / MDE
  "searchindexer.exe",
  "searchprotocolhost.exe",
  "dllhost.exe",
  "taskhostw.exe",
  "runtimebroker.exe", // shell/UI brokers
]); // Windows-native processes that access LSASS constantly as part of normal operation (#198). A
// Sysmon EID 10 ProcessAccess to lsass.exe from one of these is NOT credential dumping — Defender /
// Defender-for-Endpoint scan it on every boot, and core OS processes open it routinely. Keyed on the
// SourceImage basename; still graded High when the source runs from a SUSPICIOUS path (a masqueraded
// "svchost.exe" in \Temp\ is not benign), and a non-listed accessor (e.g. a renamed dumper) stays High.
export const BENIGN_LSASS_ACCESSORS = new Set([
  "msmpeng.exe",
  "mpdefendercoreservice.exe",
  "mssense.exe",
  "sensendr.exe",
  "mpcmdrun.exe", // Defender / MDE
  "svchost.exe",
  "services.exe",
  "csrss.exe",
  "wininit.exe",
  "lsass.exe",
  "wmiprvse.exe",
  "smss.exe",
  "lsm.exe",
]); // Execution from a user-writable / staging directory is itself a weak masquerade/tradecraft signal
// (#199) — a non-system binary launched from Temp / AppData / Downloads / Public / ProgramData, or
// /tmp,/dev/shm,/var/tmp on *nix. Tested against the IMAGE path (not the whole command) to avoid
// matching a path that merely appears as an argument. ProgramData recurs across the DFIR Report and
// Huntress corpora as ransomware/dropper staging ground (msidxsvc.exe, locker.exe, sc-created
// payloads, renamed PowerShell) — same Medium-bump tier as the other user-writable paths, not High.
// EXCEPTION: `\ProgramData\Microsoft\Windows Defender\` is Defender's own legitimate install path
// (MsMpEng.exe et al. really live there), so it's carved out — otherwise every benign Defender
// EID 8/10 event would trip the masquerade override in BENIGN_THREAD_SOURCES/BENIGN_LSASS_ACCESSORS.
export const SUSP_PATH =
  /\\(?:appdata|temp|downloads)\\|\\users\\public\\|\\programdata\\(?!microsoft\\windows defender\\)|(?:^|[\s"])\/(?:tmp|var\/tmp|dev\/shm)\//i;

// Where a trusted Windows binary actually lives. The benign sets above are keyed on the image
// BASENAME, and a basename is the one thing an attacker controls for free: dropping a DLL-hijack
// payload named svchost.exe into a directory SUSP_PATH does not cover (C:\Windows\, a subdirectory
// of an installed product) inherited the full benign downgrade. Checking that the path is a system
// path turns that denylist into an allowlist — the name must match AND the binary must live where
// that name belongs.
const SYSTEM_IMAGE_PATH =
  /\\windows\\(?:system32|syswow64|winsxs)\\|\\program files(?: \(x86\))?\\|\\programdata\\microsoft\\windows defender\\/i;

// True when `image` may be trusted on the strength of its name. A path that is present must be a
// system path; a path that is ABSENT keeps the old name-based trust, because plenty of SIEM
// normalizations forward only the basename and tightening that case would regrade every Defender
// LSASS access on those feeds as credential dumping (#198) — a much worse trade than the
// masquerade this closes.
export function isTrustedSystemImage(image: string): boolean {
  const p = image.trim();
  if (!p || !/[\\/]/.test(p)) return true; // nothing to judge / no path to check
  // Plenty of SIEMs normalize `C:\Windows\System32\svchost.exe` to `C:/Windows/System32/svchost.exe`.
  // Both path regexes are written with backslashes, so on those feeds every benign Defender and
  // core-OS event would have failed the allowlist and been regraded as credential dumping or
  // injection. Fold the separator before either test — that also closes the mirror-image hole,
  // where a masquerade at `C:/Users/Public/` slipped past SUSP_PATH for the very same reason.
  const win = p.replace(/\//g, "\\");
  return !SUSP_PATH.test(win) && SYSTEM_IMAGE_PATH.test(win);
}
