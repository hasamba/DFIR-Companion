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
import { DUAL_USE, OFFENSIVE_TOOLS } from "./attackToolNames.js";

export interface PrefetchSignal {
  severity: Severity;
  mitre: string[];
}

// The named offensive tools (High) and the dual-use binaries (Medium) live in attackToolNames.ts, so
// the merge-time tool-store pass (#1970) reads the same names.

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
