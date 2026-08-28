// Which processes are ALLOWED to do an alarming thing. The inverse of tradecraftRules: that table
// asks "does this payload look like an attack", this one asks "is this actor the one the OS and the
// security stack expect". Split out of siemImport (#385) because the answer is a per-vendor list
// that grows with every EDR a customer runs, and it has to be readable and testable on its own.
//
// The pairing that makes it safe is NAME plus LOCATION. A name alone is a masquerade invitation:
// an attacker who calls their dumper CSFalconService.exe would be waved through. So a third-party
// agent is only benign from ITS OWN install directory; a Windows-native process is only benign
// from a path that is not user-writable. Get this wrong in either direction and you either drown
// real injection signal in EDR telemetry, or you hand an attacker a filename that grades Low.

import { SUSP_PATH } from "./tradecraftRules.js";

// Third-party EDR / AV agents that legitimately read LSASS (Sysmon 10) and inject inspection
// threads (Sysmon 8) — the same behaviours Defender performs, from vendors Defender's own allowlist
// naturally omits. On a CrowdStrike or SentinelOne estate EVERY endpoint produces this telemetry
// continuously, so without them the highest-volume events in the case are graded credential access
// and process injection. Keyed to an install directory each: the name alone is not the evidence.
const EDR_AGENTS: { name: string; dir: RegExp }[] = [
  { name: "csfalconservice.exe", dir: /\\crowdstrike\\/i },
  { name: "csfalconcontainer.exe", dir: /\\crowdstrike\\/i },
  { name: "csagent.exe", dir: /\\crowdstrike\\/i },
  { name: "sentinelagent.exe", dir: /\\sentinel\s?one\\/i },
  { name: "sentinelstaticengine.exe", dir: /\\sentinel\s?one\\/i },
  { name: "sentinelstaticenginescanner.exe", dir: /\\sentinel\s?one\\/i },
  { name: "sophosedr.exe", dir: /\\sophos\b/i },
  { name: "sophosfilescanner.exe", dir: /\\sophos\b/i },
  { name: "ssphealthcheck.exe", dir: /\\sophos\b/i },
  { name: "taniumclient.exe", dir: /\\tanium\b/i },
  { name: "taniumdetectengine.exe", dir: /\\tanium\b/i },
  { name: "cb.exe", dir: /\\(?:carbonblack|confer)\b/i },
  { name: "repmgr.exe", dir: /\\(?:carbonblack|confer)\b/i },
  { name: "repux.exe", dir: /\\(?:carbonblack|confer)\b/i },
  { name: "cyserver.exe", dir: /\\(?:palo\s?alto|cortex|traps)\b/i },
  { name: "cytray.exe", dir: /\\(?:palo\s?alto|cortex|traps)\b/i },
  { name: "mfeesp.exe", dir: /\\(?:mcafee|trellix)\b/i },
  { name: "mfemactl.exe", dir: /\\(?:mcafee|trellix)\b/i },
  { name: "masvc.exe", dir: /\\(?:mcafee|trellix)\b/i },
  { name: "elastic-agent.exe", dir: /\\elastic\b/i },
  { name: "elastic-endpoint.exe", dir: /\\elastic\b/i },
  { name: "qualysagent.exe", dir: /\\qualys\b/i },
  { name: "rtvscan.exe", dir: /\\symantec\b/i },
  { name: "ccsvchst.exe", dir: /\\symantec\b/i },
  { name: "wdatpagent.exe", dir: /\\windows defender advanced threat protection\\/i },
];

// Core OS processes that legitimately call CreateRemoteThread (Sysmon EID 8) during normal
// session/process setup — csrss/wininit/services injecting is routine, so we downgrade those
// from the default High (they stay in the timeline; synthesis/legit-marking can still act).
// Core OS processes that legitimately CreateRemoteThread as routine session/service setup, PLUS
// Windows Defender / Defender-for-Endpoint, which inject monitoring threads into user processes as
// part of behavioral scanning — a benign EID 8 source, not injection tradecraft. Also the desktop/
// shell brokers that routinely inject as part of ordinary UI plumbing: Windows Search indexing its
// own protocol host, dllhost.exe (COM Surrogate) loading shell-extension/COM objects, and the UWP
// app-model brokers taskhostw/RuntimeBroker — all fire constantly on a stock, uncompromised desktop
// and otherwise drown real injection signal in noise (see the fairhaven-rdp-takeover benchmark,
// where this exact pairing on unrelated hosts got escalated into a fabricated finding).
const BENIGN_THREAD_SOURCES = new Set([
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
]);
// Windows-native processes that access LSASS constantly as part of normal operation (#198). A
// Sysmon EID 10 ProcessAccess to lsass.exe from one of these is NOT credential dumping — Defender /
// Defender-for-Endpoint scan it on every boot, and core OS processes open it routinely. Keyed on the
// SourceImage basename; still graded High when the source runs from a SUSPICIOUS path (a masqueraded
// "svchost.exe" in \Temp\ is not benign), and a non-listed accessor (e.g. a renamed dumper) stays High.
const BENIGN_LSASS_ACCESSORS = new Set([
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
]);

// Where software that is allowed to read LSASS or inject threads actually lives. An attacker can
// create a folder called CrowdStrike anywhere; what they cannot do is write into Program Files or
// System32 without already owning the box. Anchored at the drive root, so a vendor name appearing
// mid-path (C:\\Users\\Public\\CrowdStrike\\) does not qualify.
const INSTALL_ROOT = /^[a-z]:\\(?:program files(?: \(x86\))?|windows\\(?:system32|syswow64))\\/i;

// Is `sourceImage` a benign actor for this behaviour? A staging path disqualifies anything, whatever
// it is called. Beyond that a Windows-native name passes on its own, while a third-party agent must
// ALSO sit under a real install root AND inside its own vendor directory — so neither a dumper
// renamed csagent.exe in \Windows\System32 nor one parked in an attacker-made \CrowdStrike\ folder
// is waved through. Name, root and vendor directory together; no one of them is the evidence. Pure.
function isBenign(sourceImage: string, native: ReadonlySet<string>): boolean {
  const image = String(sourceImage ?? "");
  const name = (image.split(/[\\/]/).pop() ?? "").toLowerCase();
  if (!name || SUSP_PATH.test(image)) return false;
  const agent = EDR_AGENTS.find((a) => a.name === name);
  if (agent) return INSTALL_ROOT.test(image) && agent.dir.test(image);
  return native.has(name);
}

/** A Sysmon 10 ProcessAccess to lsass.exe from this source is routine, not credential dumping. */
export function isBenignLsassAccessor(sourceImage: string): boolean {
  return isBenign(sourceImage, BENIGN_LSASS_ACCESSORS);
}

/** A Sysmon 8 CreateRemoteThread from this source is routine, not injection. */
export function isBenignThreadSource(sourceImage: string): boolean {
  return isBenign(sourceImage, BENIGN_THREAD_SOURCES);
}
