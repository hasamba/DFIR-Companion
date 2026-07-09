import { readFile, readdir, mkdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { atomicWrite } from "../storage/atomicWrite.js";

// A "triage bundle" (a.k.a. blueprint / triage pack) is a named, reusable selection of Velociraptor
// CLIENT artifacts. The analyst picks one, runs it as a hunt, and the collected results auto-import +
// synthesize. Bundles are GLOBAL (shared across cases, like case templates), not per-case: built-ins
// ship with the app and custom ones are saved as JSON in a global bundles dir. Mirrors TemplateStore.

export interface ArtifactBundle {
  id: string;
  name: string;                 // e.g. "Fast Triage"
  description: string;
  builtIn: boolean;
  artifacts: string[];          // Velociraptor CLIENT artifact names
  defaultWaitMinutes?: number;  // optional per-bundle default collect delay
  timeoutSeconds?: number;      // optional per-collection timeout override (Velociraptor default 600s) — some artifacts run longer
  expirySeconds?: number;       // optional per-bundle hunt expiry (relative, seconds); unset → the one-hour default
  // Per-artifact parameter overrides passed to the hunt's `spec`, so a heavy artifact emits less at the
  // source (e.g. {"Windows.Hayabusa.Rules": {"RuleLevel": "Critical, High, and Medium"}} narrows Hayabusa).
  // Only the params you set are sent; everything else uses the artifact's own defaults.
  params?: Record<string, Record<string, string>>;
  // Per-artifact VQL WHERE filter applied to that artifact's hunt_results BEFORE the row cap, so noisy
  // rows are dropped at the source (e.g. {"DetectRaptor.Generic.Detection.YaraFile": "NOT OSPath =~ 'pagefile'"}).
  // Analyst-authored VQL boolean expression (no "WHERE" keyword).
  filters?: Record<string, string>;
  customized?: boolean;         // a built-in that has a saved override on disk (so the UI can offer "reset to default"); derived, not persisted
  // When true, this bundle's collected results go to the SUPER-TIMELINE ONLY (never the forensic
  // timeline) — for raw host-triage artifacts (MFT/USN/Prefetch) that would otherwise flood the
  // forensic timeline + IOC list. The analyst promotes individual events up when they matter.
  superTimelineOnly?: boolean;
}

// Per-artifact VQL WHERE filters: keep string values, strip newlines/trailing ';', cap length.
function sanitizeBundleFilters(raw: unknown): Record<string, string> | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const out: Record<string, string> = {};
  for (const [artifact, where] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof where !== "string") continue;
    const w = where.replace(/[\r\n]+/g, " ").replace(/;+\s*$/, "").trim().slice(0, 1000);
    if (w) out[artifact] = w;
  }
  return Object.keys(out).length ? out : undefined;
}

// Keep only object-of-string-ish params; drop nested objects/null. Returns undefined when empty.
function sanitizeBundleParams(raw: unknown): Record<string, Record<string, string>> | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const out: Record<string, Record<string, string>> = {};
  for (const [artifact, params] of Object.entries(raw as Record<string, unknown>)) {
    if (!params || typeof params !== "object") continue;
    const inner: Record<string, string> = {};
    for (const [k, v] of Object.entries(params as Record<string, unknown>)) {
      if (v == null || typeof v === "object") continue;
      inner[String(k)] = String(v);
    }
    if (Object.keys(inner).length) out[artifact] = inner;
  }
  return Object.keys(out).length ? out : undefined;
}

// The single shipped default. A cross-platform "quick wins" detection sweep (DetectRaptor + Velociraptor
// detection/triage artifacts, plus collectors like ThorZIP / Hayabusa whose JSON upload is ingested).
// Editable in place (an edit saves an override; Reset to default restores this). Analysts add their own
// bundles via the dashboard's artifact picker.
export const BUILT_IN_BUNDLES: readonly ArtifactBundle[] = [
  {
    id: "best-practice",
    name: "Best Practice",
    description: "Quick Wins",
    builtIn: true,
    artifacts: [
      "Windows.Detection.Yara.Process",
      "Windows.Detection.Malfind",
      "Windows.Hayabusa.Rules",
      "Windows.EventLogs.Chainsaw",
      "DetectRaptor.Generic.Detection.BrowserExtensions",
      "DetectRaptor.Generic.Detection.YaraFile",
      "DetectRaptor.Generic.Detection.YaraWebshell",
      "DetectRaptor.Linux.Detection.YaraProcessLinux",
      "DetectRaptor.Macos.Detection.YaraProcessMacos",
      "DetectRaptor.Windows.Detection.Amcache",
      "DetectRaptor.Windows.Detection.Applications",
      "DetectRaptor.Windows.Detection.BinaryRename",
      "DetectRaptor.Windows.Detection.Bootloaders",
      "DetectRaptor.Windows.Detection.Evtx",
      "DetectRaptor.Windows.Detection.HijackLibsEnv",
      "DetectRaptor.Windows.Detection.HijackLibsMFT",
      "DetectRaptor.Windows.Detection.LolDrivers",
      "DetectRaptor.Windows.Detection.LolDriversMalicious",
      "DetectRaptor.Windows.Detection.LolDriversVulnerable",
      "DetectRaptor.Windows.Detection.LolRMM",
      "DetectRaptor.Windows.Detection.MFT",
      "DetectRaptor.Windows.Detection.NamedPipes",
      "DetectRaptor.Windows.Detection.Powershell.ISEAutoSave",
      "DetectRaptor.Windows.Detection.Powershell.PSReadline",
      "DetectRaptor.Windows.Detection.Webhistory",
      "DetectRaptor.Windows.Detection.Yara.LolDrivers",
      "DetectRaptor.Windows.Detection.ZoneIdentifier",
      "DetectRaptor.Windows.Detection.YaraProcessWin",
      "DetectRaptor.Windows.Registry.NetworkProvider",
      "Windows.Analysis.EvidenceOfDownload",
      "Windows.Sys.StartupItems",
      "Windows.System.TaskScheduler",
      "Windows.Persistence.PermanentWMIEvents",
      "Windows.Analysis.SuspiciousWMIConsumers",
      "Linux.Sigma.Triage",
      "Generic.Scanner.ThorZIP",
      "Custom.Windows.System.Powershell.PSReadline.QuickWins",
      "Windows.System.DNSCache",
      "Generic.System.Pstree",
      "Linux.Network.NetstatEnriched",
      "MacOS.Network.Netstat",
      "Windows.Network.NetstatEnriched",
      "Windows.System.UntrustedBinaries",
      "Windows.Attack.UnexpectedImagePath",
      "Custom.DFIR.RDPLateralMovementDetection",
    ],
    defaultWaitMinutes: 10,
    timeoutSeconds: 6000,   // the sweep includes slow artifacts (THOR/Hayabusa) — well past the 600s default
    // Hayabusa emits 10k+ rows at its defaults; constrain it at the source (Critical/High/Medium rules,
    // Stable+Experimental status) so the import stays signal-rich. Tune via Advanced → parameters.
    params: { "Windows.Hayabusa.Rules": { RuleLevel: "Critical, High, and Medium", RuleStatus: "Stable and Experimental" } },
    // Drop known-noisy rows at the source: YaraFile pagefile hits, and an in-development Evtx rule.
    // (The Evtx column name is inferred — adjust in the editor if your results use a different one.)
    filters: {
      "DetectRaptor.Generic.Detection.YaraFile": "NOT OSPath =~ 'pagefile'",
      "DetectRaptor.Windows.Detection.Evtx": "NOT Detection =~ 'Powershell large Base64 blob'",
    },
  },
  {
    id: "super-timeline-triage",
    name: "Super-Timeline Triage",
    description: "Raw host artifacts (MFT/USN/registry/execution) for the super-timeline",
    builtIn: true,
    superTimelineOnly: true,
    // A broad host-triage super-timeline sweep (file activity, registry, execution, user interaction,
    // event logs). Names the analyst can verify/trim against their server via the bundle editor — the
    // run-bundle route drops any artifact the server doesn't have (so a missing one won't fail the hunt).
    artifacts: [
      "Windows.NTFS.MFT",
      "Windows.Registry.UserAssist",
      "Windows.Registry.AppCompatCache",
      "Windows.Forensics.Shellbags",
      "Windows.Forensics.Prefetch",
      "Windows.Forensics.Amcache",
      "Windows.Forensics.Lnk",
      "Windows.Applications.Chrome.History",
      "Windows.Applications.Edge.History",
      "Windows.Forensics.RecycleBin",
      "Windows.System.TaskScheduler",
      "Windows.Forensics.ActivitiesCache",
      "Windows.Forensics.Bam",
      "Windows.Forensics.CertUtil",
      "Windows.Forensics.Clipboard",
      "Windows.Forensics.JumpLists",
      "Windows.Forensics.NotepadParser",
      "Windows.Forensics.RecentApps",
      "Windows.Forensics.RecentFileCache",
      "Windows.Forensics.SAM",
      "Windows.Forensics.SRUM",
      "Windows.Forensics.Timeline",
      "Windows.Forensics.UserAccessLogs",
      "Windows.Forensics.Usn",
      "Windows.Timeline.Prefetch.Improved",
      "Windows.Office.MRU",
      "Windows.Registry.RDP",
      "Windows.Registry.ScheduledTasks",
      "Windows.Registry.Sysinternals.Eulacheck",
      "Windows.Registry.RecentDocs",
      "Windows.Registry.TaskCache.HiddenTasks",
      "Windows.Sys.AllUsers",
      "Windows.Sys.Programs",
      "Windows.Sys.Users",
      "Windows.Timeline.Registry.RunMRU",
      "Windows.Registry.Hunter",
      "Windows.EventLogs.Evtx",
      "Windows.EventLogs.ScheduledTasks",
      "Windows.System.AppCompatPCAExtend",
      "Generic.Forensic.SQLiteHunter",
    ],
    defaultWaitMinutes: 10,
    timeoutSeconds: 6000,   // a broad forensic sweep (MFT/SRUM/SQLiteHunter) runs well past the 600s default
  },
  {
    id: "linux-triage",
    name: "Linux Triage",
    description: "Linux host triage: users, persistence, network, packages, and detection artifacts",
    builtIn: true,
    artifacts: [
      "Generic.System.HostsFile",
      "Linux.Applications.Chrome.Extensions",
      "Linux.Applications.Docker.Info",
      "Linux.Carving.SSHLogs",
      "Linux.Collection.Autoruns",
      "Linux.Collection.BrowserExtensions",
      "Linux.Collection.BrowserHistory",
      "Linux.Collection.CatScale",
      "Linux.Collection.DBConfig",
      "Linux.Collection.History",
      "Linux.Collection.NetworkConfig",
      "Linux.Collection.SysConfig",
      "Linux.Collection.SysLogs",
      "Linux.Collection.UserConfig",
      "Linux.Debian.AptSources",
      "Linux.Detection.AnomalousFiles",
      "Linux.Detection.BruteForce",
      "Linux.Detection.IncorrectPermissions",
      "Linux.Detection.SSHKeyFileCmd",
      "Linux.Detection.Yara.Glob",
      "Linux.Detection.Yara.Process",
      "Linux.Forensics.EnvironmentVariables",
      "Linux.Forensics.ImmutableFiles",
      "Linux.Forensics.Journal",
      "Linux.Forensics.ProcFD",
      "Linux.Forensics.RecentlyUsed",
      "Linux.Forensics.Targets",
      "Linux.LogAnalysis.ChopChopGo",
      "Linux.Mounts",
      "Linux.Network.Nethogs",
      "Linux.Network.Netstat",
      "Linux.Network.NetstatEnriched",
      "Linux.Proc.Arp",
      "Linux.Sigma.Triage",
      "Linux.Ssh.AuthorizedKeys",
      "Linux.Ssh.KnownHosts",
      "Linux.Ssh.PrivateKeys",
      "Linux.Sys.BashHistory",
      "Linux.Sys.BashShell",
      "Linux.Sys.Crontab",
      "Linux.Sys.Getcap",
      "Linux.Sys.Groups",
      "Linux.Sys.JournalCtl",
      "Linux.Sys.LastUserLogin",
      "Linux.Sys.Modinfo",
      "Linux.Sys.Pslist",
      "Linux.Sys.SUID",
      "Linux.Sys.Services",
      "Linux.Sys.Users",
      "Linux.Syslog.SSHLogin",
      "Linux.System.BashLogout",
      "Linux.Triage.UAC",
      "Linux.Users.RootUsers",
      "DetectRaptor.Generic.Detection.BrowserExtensions",
      "DetectRaptor.Generic.Detection.YaraFile",
      "DetectRaptor.Linux.Detection.YaraProcessLinux",
    ],
    defaultWaitMinutes: 10,
    // CatScale and UAC are broad host-triage collectors that can run well past the 600s default;
    // Yara/filesystem-walking artifacts (Yara.Glob/Process, ImmutableFiles, AnomalousFiles) add to that.
    timeoutSeconds: 6000,
  },
];

export class ArtifactBundleStore {
  constructor(private readonly root: string) {}

  private path(id: string): string {
    return join(this.root, `${id}.json`);
  }

  // True when an id belongs to a shipped built-in (vs. a purely custom bundle). Built-ins are
  // editable: an edit saves an override file under the same id; deleting it resets to the default.
  isBuiltIn(id: string): boolean {
    return BUILT_IN_BUNDLES.some((b) => b.id === id);
  }

  // Read one saved bundle file (an override for a built-in, or a custom bundle), or null.
  private async readSaved(id: string): Promise<ArtifactBundle | null> {
    try {
      return JSON.parse(await readFile(this.path(id), "utf8")) as ArtifactBundle;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  // All saved bundle files keyed by id (overrides + custom). Malformed files are skipped.
  private async loadSavedMap(): Promise<Map<string, ArtifactBundle>> {
    const map = new Map<string, ArtifactBundle>();
    let entries: string[];
    try {
      entries = await readdir(this.root);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return map;
      throw err;
    }
    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      try {
        const raw = JSON.parse(await readFile(join(this.root, entry), "utf8")) as ArtifactBundle;
        if (raw && typeof raw.id === "string" && raw.id) map.set(raw.id, raw);
      } catch {
        // skip malformed files
      }
    }
    return map;
  }

  // Built-ins first (a saved override replaces the shipped default, flagged `customized`), then
  // purely custom bundles.
  async list(): Promise<ArtifactBundle[]> {
    const saved = await this.loadSavedMap();
    const out: ArtifactBundle[] = [];
    for (const b of BUILT_IN_BUNDLES) {
      const override = saved.get(b.id);
      out.push(override ? { ...override, id: b.id, builtIn: true, customized: true } : { ...b, customized: false });
    }
    for (const [id, b] of saved) {
      if (this.isBuiltIn(id)) continue;   // already merged above as an override
      out.push({ ...b, builtIn: false, customized: false });
    }
    return out;
  }

  async get(id: string): Promise<ArtifactBundle | null> {
    const saved = await this.readSaved(id);
    if (this.isBuiltIn(id)) {
      const builtin = BUILT_IN_BUNDLES.find((b) => b.id === id)!;
      return saved ? { ...saved, id, builtIn: true, customized: true } : { ...builtin, customized: false };
    }
    return saved ? { ...saved, builtIn: false, customized: false } : null;
  }

  // Save a bundle. A built-in id writes an OVERRIDE (the built-in becomes editable in place);
  // any other id creates/updates a custom bundle. `customized`/`builtIn` are derived from the id,
  // not trusted from input.
  async save(input: Omit<ArtifactBundle, "id" | "builtIn" | "customized"> & { id?: string }): Promise<ArtifactBundle> {
    const id = input.id && String(input.id).trim() ? String(input.id).trim() : randomUUID();
    const builtIn = this.isBuiltIn(id);
    const bundle: ArtifactBundle = {
      id,
      name: String(input.name ?? "").trim(),
      description: String(input.description ?? "").trim(),
      builtIn,
      artifacts: Array.isArray(input.artifacts) ? input.artifacts.map(String).map((a) => a.trim()).filter(Boolean) : [],
      defaultWaitMinutes: typeof input.defaultWaitMinutes === "number" ? input.defaultWaitMinutes : undefined,
      timeoutSeconds: typeof input.timeoutSeconds === "number" ? input.timeoutSeconds : undefined,
      // Relative hunt expiry (seconds); the API layer clamps/defaults, so here we just persist a positive int.
      expirySeconds: typeof input.expirySeconds === "number" && input.expirySeconds > 0 ? Math.floor(input.expirySeconds) : undefined,
      params: sanitizeBundleParams(input.params),
      filters: sanitizeBundleFilters(input.filters),
      // Carry the super-timeline routing flag through an edit/override; only `true` persists (a missing
      // field stays undefined, not `false` noise) — mirrors the other optionals above.
      superTimelineOnly: input.superTimelineOnly === true ? true : undefined,
    };
    await mkdir(this.root, { recursive: true });
    await atomicWrite(this.path(id), JSON.stringify(bundle, null, 2));
    return { ...bundle, customized: builtIn };
  }

  // Remove the saved file: a custom bundle is deleted; a built-in's override is reset to the shipped
  // default. Returns true when a file was removed, false when there was nothing on disk (ENOENT).
  async delete(id: string): Promise<boolean> {
    try {
      await unlink(this.path(id));
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw err;
    }
  }
}
