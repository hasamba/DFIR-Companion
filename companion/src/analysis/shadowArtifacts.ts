import type { ForensicEvent } from "./stateTypes.js";
import type { TimelineGap } from "./gapDetect.js";

// Shadow-artifact catalog (issue #96 — the "reconstruct the missing time frame" half).
//
// When the timeline goes silent (cleared Windows Event Logs, a stopped collector, disabled EDR),
// the obvious sources are gone — but Windows keeps a constellation of SECONDARY forensic artifacts
// that an attacker rarely thinks to (or can) clean: the USN journal, SRUM, Prefetch, Amcache,
// ShimCache, BAM, the MFT, UserAssist, LNK/JumpLists. These are "shadow artifacts" — they record
// program execution, file activity, and network usage as a side effect of normal OS bookkeeping,
// independent of the audit log that was tampered with. Collecting them is the standard way to
// rebuild what happened during a blackout.
//
// This module is a PURE, deterministic, unit-tested catalog of those artifacts, each mapped to a
// deployable Velociraptor collection. It does NOT run detection (per the product principle) — it
// suggests COLLECTIONS the analyst reviews and deploys through the existing Velociraptor hunt flow
// (launchHunt / POST /velociraptor/hunt), exactly like the AI hunt suggestions (#57). Pairing a
// curated catalog with the deploy path keeps the VQL correct (real built-in artifacts, not an AI
// guess) while the AI half (gapHypothesis.ts) explains WHICH artifacts matter for a given gap and
// WHY. No AI, no network — referenced by `shadowArtifactsForGap` to attach to each detected gap.
//
// CRUCIAL FRAMING: like the gap itself, a shadow-artifact collection is a LEAD-GENERATOR, not proof.
// It reconstructs candidate activity for the silent window; the analyst still correlates and confirms.

// Which kind of missing activity a shadow artifact helps reconstruct. A gap can hide any of these,
// so the selector returns the full set — the categories drive display grouping and the AI's
// "prioritize these for this gap" reasoning, not a hard filter.
export type ShadowCategory = "execution" | "file-activity" | "network" | "persistence" | "general";

export interface ShadowArtifact {
  id: string;                    // stable kebab id, e.g. "usn-journal" (referenced by the AI hypothesis)
  name: string;                  // display name, e.g. "USN Journal ($UsnJrnl:$J)"
  reconstructs: string;          // what missing activity it can rebuild
  whyResilient: string;          // why attackers rarely clean it (the reason it survives a wipe)
  velociraptorArtifact: string;  // the built-in Velociraptor CLIENT artifact this collects
  vql: string;                   // a single, deployable CLIENT-side VQL statement (review-then-deploy)
  categories: ShadowCategory[];  // which gap signatures it addresses
  os: "windows" | "linux";       // platform the artifact lives on
}

// The catalog. Windows-focused because the silent-period signatures the gap detector flags (cleared
// Security.evtx, stopped Sysmon/EDR) are Windows tradecraft and the issue names Windows artifacts.
// Every `velociraptorArtifact` is a real, standard Velociraptor built-in; every `vql` runs
// parameterless on a client. Ordered roughly execution → file-activity → network so the most
// commonly useful reconstruction artifacts surface first.
export const SHADOW_ARTIFACTS: readonly ShadowArtifact[] = [
  {
    id: "prefetch",
    name: "Prefetch",
    reconstructs:
      "Program execution — each .pf records an executable's name, run count, and its last 8 run times, " +
      "so binaries run during the silence are still dated.",
    whyResilient:
      "Written by the OS on execution to a separate directory (C:\\Windows\\Prefetch); clearing the event " +
      "log does not touch it, and attackers seldom scrub individual .pf files.",
    velociraptorArtifact: "Windows.Forensics.Prefetch",
    vql: "SELECT * FROM Artifact.Windows.Forensics.Prefetch()",
    categories: ["execution"],
    os: "windows",
  },
  {
    id: "amcache",
    name: "Amcache (Amcache.hve)",
    reconstructs:
      "Program presence and execution — the Amcache registry hive records executables (with SHA-1) that " +
      "ran or were installed, recovering tooling dropped during the blackout.",
    whyResilient:
      "A registry hive flushed by the OS, distinct from the audit log; survives event-log clearing and is " +
      "rarely targeted by anti-forensics.",
    velociraptorArtifact: "Windows.Forensics.Amcache",
    vql: "SELECT * FROM Artifact.Windows.Forensics.Amcache()",
    categories: ["execution"],
    os: "windows",
  },
  {
    id: "shimcache",
    name: "ShimCache (AppCompatCache)",
    reconstructs:
      "Program presence and execution order — the Application Compatibility Cache records executables the " +
      "system encountered, with path and (often) last-modified time.",
    whyResilient:
      "Held in the SYSTEM registry hive and only flushed at shutdown; an attacker who clears logs mid-intrusion " +
      "usually leaves it intact.",
    velociraptorArtifact: "Windows.Registry.AppCompatCache",
    vql: "SELECT * FROM Artifact.Windows.Registry.AppCompatCache()",
    categories: ["execution"],
    os: "windows",
  },
  {
    id: "bam",
    name: "BAM/DAM (Background Activity Moderator)",
    reconstructs:
      "Last execution time per user — BAM records the full path and last-run timestamp of executables run " +
      "by each user SID, pinning activity to the silent window.",
    whyResilient:
      "A SYSTEM-hive registry key maintained by the OS power manager; unrelated to the audit subsystem the " +
      "attacker tampered with.",
    velociraptorArtifact: "Windows.Forensics.Bam",
    vql: "SELECT * FROM Artifact.Windows.Forensics.Bam()",
    categories: ["execution"],
    os: "windows",
  },
  {
    id: "userassist",
    name: "UserAssist",
    reconstructs:
      "GUI program execution per user — UserAssist records interactively-launched programs with run count and " +
      "last-execution time, recovering hands-on-keyboard activity.",
    whyResilient:
      "Stored ROT13-encoded in the user's NTUSER.DAT registry hive; survives event-log clearing and is rarely " +
      "scrubbed.",
    velociraptorArtifact: "Windows.Registry.UserAssist",
    vql: "SELECT * FROM Artifact.Windows.Registry.UserAssist()",
    categories: ["execution"],
    os: "windows",
  },
  {
    id: "usn-journal",
    name: "USN Journal ($UsnJrnl:$J)",
    reconstructs:
      "File create / delete / rename activity — the NTFS change journal logs every file change with a timestamp, " +
      "so files written and DELETED during the silence still leave a dated trace.",
    whyResilient:
      "A low-level NTFS metadata stream the OS maintains for indexing/replication; deleting a file does not " +
      "remove its journal record, and clearing the event log leaves it untouched.",
    velociraptorArtifact: "Windows.Forensics.Usn",
    vql: "SELECT * FROM Artifact.Windows.Forensics.Usn()",
    categories: ["file-activity"],
    os: "windows",
  },
  {
    id: "mft",
    name: "Master File Table ($MFT)",
    reconstructs:
      "File metadata and timestamps — every file/directory has an MFT record with $STANDARD_INFORMATION and " +
      "$FILE_NAME timestamps; deleted entries often persist until overwritten.",
    whyResilient:
      "The core NTFS file index; independent of the audit log, and timestomping the $SI times still leaves the " +
      "$FN times for comparison.",
    velociraptorArtifact: "Windows.NTFS.MFT",
    vql: "SELECT * FROM Artifact.Windows.NTFS.MFT()",
    categories: ["file-activity", "general"],
    os: "windows",
  },
  {
    id: "lnk-files",
    name: "LNK shortcuts / JumpLists",
    reconstructs:
      "File and document access — auto-generated .lnk shortcuts and JumpLists record opened files with their " +
      "original path, volume, and timestamps, recovering what was accessed or staged.",
    whyResilient:
      "Created automatically by the shell as a usability side effect; unrelated to the security log and rarely " +
      "cleaned per-file.",
    velociraptorArtifact: "Windows.Forensics.Lnk",
    vql: "SELECT * FROM Artifact.Windows.Forensics.Lnk()",
    categories: ["file-activity"],
    os: "windows",
  },
  {
    id: "srum",
    name: "SRUM (System Resource Usage Monitor)",
    reconstructs:
      "Per-application network bytes and execution windows — SRUM aggregates ~30-60 days of per-process network " +
      "I/O and CPU, exposing exfiltration or beaconing that ran while logging was off.",
    whyResilient:
      "An ESE database written hourly by the OS diagnostics service, separate from the audit log; survives a " +
      "log wipe and is almost never targeted.",
    velociraptorArtifact: "Windows.Forensics.SRUM",
    vql: "SELECT * FROM Artifact.Windows.Forensics.SRUM()",
    categories: ["network", "execution"],
    os: "windows",
  },
];

// All distinct shadow-artifact ids, exposed for validation/sanitization in gapHypothesis.ts (the AI
// may only reference an id that actually exists in the catalog).
export const SHADOW_ARTIFACT_IDS: ReadonlySet<string> = new Set(SHADOW_ARTIFACTS.map((a) => a.id));

// Look up a catalog entry by id (case-insensitive on the kebab id). Returns undefined for an unknown id.
export function shadowArtifactById(id: string): ShadowArtifact | undefined {
  const key = String(id ?? "").trim().toLowerCase();
  return SHADOW_ARTIFACTS.find((a) => a.id === key);
}

export interface GapShadowArtifacts {
  targetHosts: string[];               // hosts to collect from, derived from the gap's surrounding events
  artifacts: readonly ShadowArtifact[]; // the catalog entries to collect (reconstruct the silent window)
}

// The host(s) a gap concerns: the `asset` of the events that bound and surround it. A complete gap
// flagged on the full timeline has no single owner, so we read the affected hosts off the
// neighbouring events (deduped, sorted, capped). Empty when no surrounding event names an asset —
// the analyst then targets the collection manually (or runs it fleet-wide).
export function gapAffectedAssets(surrounding: readonly ForensicEvent[], cap = 10): string[] {
  const hosts = new Set<string>();
  for (const e of surrounding ?? []) {
    const asset = (e?.asset ?? "").trim();
    if (asset) hosts.add(asset);
  }
  return [...hosts].sort((a, b) => a.localeCompare(b)).slice(0, Math.max(0, cap));
}

// Shadow-artifact collections to reconstruct a gap's silent window. The artifact set is constant (any
// of these can rebuild a blackout, so we offer them all, execution-first), while `targetHosts` is
// derived from the events around the gap. Pure — deterministic, no I/O. `_gap` is accepted for a
// stable, gap-aware signature (and future per-gap weighting) even though the current set is uniform.
export function shadowArtifactsForGap(_gap: TimelineGap, surrounding: readonly ForensicEvent[]): GapShadowArtifacts {
  return {
    targetHosts: gapAffectedAssets(surrounding),
    artifacts: SHADOW_ARTIFACTS,
  };
}
