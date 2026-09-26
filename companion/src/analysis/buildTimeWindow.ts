// A machine building itself is not an intrusion (#1529).
//
// Scenario 018 scored its own lab VM: the case's only Critical was a Security log clear during the
// Vagrant/Chocolatey provisioning run, the "rogue account created and added to admin groups" was
// Packer's first boot creating `vagrant` from the machine account, the "masquerading hardware-driver
// services" were the real VMware and Intel guest drivers, and the "remote access tool staging" was
// three Chocolatey packages. Seven of 23 findings described the build. The narrative then opened
// nine months before a three-minute scenario and asked for pre-provisioning logs.
//
// #1503 taught the case to stop reporting the SILENCES between those events. This module grades the
// events themselves: inside a provisioning window a log clear, an account creation, a driver-service
// install or a firewall change is baseline, and the row is capped at Low with a note the analyst and
// the model both read. Nothing is deleted, nothing is hidden, and the cap only ever LOWERS.
//
// HOW A WINDOW IS FOUND. Not from the rename ledger alone: a rename bound is an identity bound, and
// a build whose bound happens to sit outside the burst would be missed while an ordinary rename
// would open a window over real activity. So the windows are discovered from the build's own
// fingerprints and the ledger only corroborates:
//
//   1. MARKERS   — rows whose path / process / text names a provisioning tool (packer, Vagrant,
//                  Chocolatey, Autounattend, sysprep, OOBE), OS servicing, or an account-management
//                  record whose SUBJECT is the machine account (`WIN-0NNTB2RTNB1$`), on a host in
//                  the rename chain. A row naming no asset is never a marker.
//   2. CLUSTERS  — consecutive markers no more than CLUSTER_GAP_MS apart, spanning no more than
//                  MAX_MARKER_SPAN_MS in total. A cluster that runs longer than that is not a build
//                  and is discarded rather than grown, so growth cannot walk across a busy host.
//   3. CORROBORATION — a cluster becomes a window only when it holds at least one PROVISIONER marker
//                  (not just servicing), AND either an observed rename bound falls inside it or it
//                  holds at least MIN_MARKERS rows naming at least two different provisioners.
//                  Windows Update and servicing run on every live host, so they add to a window but
//                  never open one (#1695). One stray `\Windows\Installer\` row never opens a window.
//   4. VETO      — a window holding a hard attacker signal (NTDS.dit, an LSASS dump, recovery
//                  inhibition, coercion tooling, a ransomware signal, an analyst-promoted row) is
//                  dropped whole, the same way gapHostHistory.ts leaves a host whole when its
//                  pre-boundary rows are graded. An intrusion during the build beats the cap.
//
// The window is then padded by WINDOW_MARGIN_MS on both sides: the marker rows date the build, the
// rows the build produced (the 7045 driver install, the 1102 log clear) sit beside them.
//
// PURE. capBuildTimeRows recomputes from the state it is handed and is reversible: a row whose
// window is gone gets its recorded severity back and its note removed, so a contradicted ledger or
// a narrowed pattern set does not leave a permanent downgrade behind.

import { appendDerivedNote, splitDerivedNotes, DESCRIPTION_BASE_MAX } from "./derivedNote.js";
import { hostBuildMarkers, type HostHistoryMarker } from "./gapHostHistory.js";
import { assetKey } from "./gapEdgeClass.js";
import type { HostRenameRecord } from "./hostRenameRecord.js";
import { ransomwareSignal } from "./ransomwareDetect.js";
import { BUILD_TIME_MARKER } from "./buildTimeMerge.js";
import {
  SEVERITY_RANK,
  worstSeverity,
  type ForensicEvent,
  type InvestigationState,
  type Severity,
} from "./stateTypes.js";

// The derived note this module writes lives in buildTimeMerge.ts (analysis/timeline), where
// correlation reads it too; re-exported so every existing reader keeps its import.
export { BUILD_TIME_MARKER };
const BUILD_TIME_NOTE_RE = /\s*\[build-time:[^\]]*\]/gu;
const HAS_BUILD_TIME_NOTE = /\[build-time:[^\]]*\]/u;

/** The severity a row inside a provisioning window is capped at. Never a raise, never below Low. */
export const BUILD_TIME_SEVERITY_CAP: Severity = "Low";

const MINUTE = 60_000;
// Markers further apart than this start a new cluster: a build is a burst of minutes, not a day.
const CLUSTER_GAP_MS = 30 * MINUTE;
// The padding around a cluster — far enough to hold the rows the build produced between markers.
const WINDOW_MARGIN_MS = 30 * MINUTE;
// A "build" that runs longer than this is not a build. The cluster is discarded, never trimmed.
const MAX_MARKER_SPAN_MS = 6 * 60 * MINUTE;
// How far from a row its window's evidence can sit: a window's markers lie within one span of each
// other plus the margin, and one more span on either side is what it takes to see that a longer burst
// is NOT a build (a cluster over MAX_MARKER_SPAN_MS is discarded). A caller that reads only part of the
// record reads this far around the rows it asks about (#1700).
export const BUILD_WINDOW_REACH_MS = 2 * MAX_MARKER_SPAN_MS + WINDOW_MARGIN_MS;
// Markers needed to corroborate a cluster that contains no rename bound.
const MIN_MARKERS = 3;
const MIN_MARKER_KINDS = 2;

// ───────────────────────────── markers ─────────────────────────────

// Deliberately narrow and anchored on names a build writes and an intruder gains nothing by faking:
// the provisioner's own tool tree and the servicing stack. gapEdgeClass.provisioningReason is NOT
// reused — it refuses any row graded above Low, and recognising a Medium Chocolatey script block as
// a build marker is exactly what this needs.
const MARKER_PATTERNS: ReadonlyArray<{ kind: string; re: RegExp }> = [
  // Anchored on what the provisioner writes, never a bare word: on a Vagrant box the interactive
  // account IS `vagrant` (and could be `packer`), so a user name or profile path matched the whole
  // user session as "build" (#1695). Packer's temp tree and build names; Vagrant's synced folder and
  // the shell provisioner's upload path.
  { kind: "packer", re: /\\temp\\packer\\|\bpacker-[0-9a-f]{8}\b|\bautounattend\b|autounattend-first-logon/ },
  { kind: "vagrant", re: /c:\\vagrant\\|\\tmp\\vagrant-(?:elevated-)?shell\.ps1\b/ },
  { kind: "chocolatey", re: /\\programdata\\chocolatey\\|\bchoco(?:latey)?(?:\.exe)?\b/ },
  { kind: "sysprep/unattend", re: /\bsysprep\b|\\windows\\panther\\|\bunattend\.xml\b|\boobe\b/ },
  {
    kind: "windows-update",
    re: /\\windows\\softwaredistribution\\|\bwuauclt\.exe\b|\bwusa\.exe\b|\bmousocoreworker\.exe\b|\busoclient\.exe\b/,
  },
  {
    kind: "servicing",
    re: /\\windows\\servicing\\|\\windows\\winsxs\\|\btiworker\.exe\b|\btrustedinstaller\.exe\b|\\windows\\installer\\|\\windows\\system32\\driverstore\\/,
  },
];

// Kinds every live host produces on its own. They extend a window but never open one (#1695).
const SERVICING_KINDS: ReadonlySet<string> = new Set(["windows-update", "servicing"]);

// Account-management records. A build creates its own accounts, and Windows records the machine
// account as the SUBJECT when it does.
const ACCOUNT_EID_RE = /\(EID (?:4720|4722|4724|4726|4728|4732|4738)\)/;
const MACHINE_SUBJECT_RE = /\b[A-Za-z0-9][A-Za-z0-9-]{0,62}\$(?!\w)/;

// The row's own text, WITHOUT the notes earlier passes appended. This pass writes `[build-time:
// packer, …]` onto the rows it caps, and reading that back would make every capped row a marker on
// the next settle: the cluster would grow by a margin each import and walk into real activity.
// splitDerivedNotes is the registry-aware split, so every derived note is excluded, not just ours.
function haystack(e: ForensicEvent): string {
  const base = splitDerivedNotes(e.description).base;
  return `${e.path ?? ""} ${e.processName ?? ""} ${e.parentName ?? ""} ${e.commandLine ?? ""} ${base} ${e.message ?? ""}`.toLowerCase();
}

// Is the SUBJECT of an account-management record the machine's own account? Read from the canonical
// envelope when the importer built one (the subject is a field there, not prose), else from the
// rendered `WORKGROUP\WIN-0NNTB2RTNB1$` the Windows mapper writes into the description.
function machineAccountSubject(e: ForensicEvent): boolean {
  const base = splitDerivedNotes(e.description).base;
  if (!ACCOUNT_EID_RE.test(base)) return false;
  const subject = e.canonical?.subject;
  if (subject && typeof subject.name === "string" && subject.name.trim())
    return MACHINE_SUBJECT_RE.test(subject.name.trim());
  return MACHINE_SUBJECT_RE.test(base);
}

/** Why this row reads as provisioning, or null. Pure string/field tests — no state. */
export function buildMarkerKind(e: ForensicEvent): string | null {
  if (machineAccountSubject(e)) return "machine-account provisioning";
  const hay = haystack(e);
  for (const p of MARKER_PATTERNS) if (p.re.test(hay)) return p.kind;
  return null;
}

// ───────────────────────────── the escape hatch ─────────────────────────────

// Signals no build produces. A row carrying one is never capped, and a window containing one is
// never applied at all — a real intrusion that overlaps the build beats the whole rule, the same
// way gapHostHistory.ts leaves a host whole when its pre-boundary rows are graded.
const HARD_SIGNAL_PATTERNS: ReadonlyArray<{ reason: string; re: RegExp }> = [
  { reason: "credential store", re: /\bntds\.dit\b|\bntdsutil\b|\\system32\\config\\sam\b/ },
  { reason: "LSASS dump", re: /\blsass\.dmp\b|\blsass\.dump\b|\blsass_dump\b|\bprocdump\b[^\n]{0,40}lsass/ },
  {
    reason: "recovery inhibition",
    re: /vssadmin delete shadows|wmic shadowcopy delete|wbadmin delete|recoveryenabled no|bootstatuspolicy ignoreallfailures/,
  },
  {
    reason: "coercion tooling",
    re: /roguewinrm|rogue_winrm|juicypotato|sweetpotato|godpotato|badpotato|rottenpotato|hotpotato|localpotato|efspotato|printspoofer/,
  },
];

/**
 * A signal no build produces, or null. CONTENT ONLY — this is what vetoes a whole window, so it must
 * name something a provisioning run cannot write. A promoted row is handled separately: promotion is
 * a decision about ONE row (and the second-look loop makes most of them, on Info telemetry), so it
 * protects that row's grade without telling us anything about the burst around it. Reading promotion
 * as a veto emptied every window on the real case — 135 machine-promoted Info rows sat inside them.
 */
export function hardAttackerSignal(e: ForensicEvent): string | null {
  const hay = haystack(e);
  for (const p of HARD_SIGNAL_PATTERNS) if (p.re.test(hay)) return p.reason;
  if (e.path && ransomwareSignal(e.path)) return "ransomware signal";
  return null;
}

/** Why this ROW keeps its grade inside a window, or null: a hard signal, or the analyst's own pull. */
export function protectedFromCap(e: ForensicEvent): string | null {
  return e.promotedAt ? "promoted row" : hardAttackerSignal(e);
}

// ───────────────────────────── windows ─────────────────────────────

export interface BuildTimeWindow {
  host: string; // the host's current short name
  names: string[]; // every short name in its rename chain
  start: string; // UTC ISO, margin included
  end: string; // UTC ISO, margin included
  marker: string; // the dominant marker kind, for the note and the block
  markerCount: number;
}

interface Cluster {
  chain: HostHistoryMarker;
  first: number;
  last: number;
  kinds: Map<string, number>;
}

const iso = (ms: number): string => new Date(ms).toISOString();

function dominant(kinds: Map<string, number>): string {
  return [...kinds.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0][0];
}

function chainOf(chains: readonly HostHistoryMarker[], e: ForensicEvent): HostHistoryMarker | undefined {
  const key = assetKey(e);
  return key ? chains.find((c) => c.names.includes(key)) : undefined;
}

// The rename bounds each chain owns, from OBSERVED bases only. `analyst` is one import's manual
// attribution, not something the machine or a collector wrote (#1496), so it never corroborates a
// build window — the same rule gapHostHistory.ts applies to the history cut.
const shortKey = (name: string): string => name.trim().split(".")[0].toUpperCase();

function observedBoundsByHost(
  chains: readonly HostHistoryMarker[],
  renames: readonly HostRenameRecord[],
): Map<string, number[]> {
  const out = new Map<string, number[]>();
  for (const r of renames) {
    if (r.basis === "analyst") continue;
    const ms = Date.parse(r.until);
    if (Number.isNaN(ms)) continue;
    const chain = chains.find(
      (c) => c.names.includes(shortKey(r.formerName)) || c.names.includes(shortKey(r.currentName)),
    );
    if (!chain) continue;
    const list = out.get(chain.host);
    if (list) list.push(ms);
    else out.set(chain.host, [ms]);
  }
  return out;
}

/**
 * The provisioning windows this case's evidence supports. `chains` comes from the rename ledger
 * (hostBuildMarkers), so a case that never learned a rename has no chain, no host identity to bound
 * a window with, and therefore no windows — the conservative direction.
 */
export function buildTimeWindows(
  events: readonly ForensicEvent[],
  renames: readonly HostRenameRecord[] = [],
): BuildTimeWindow[] {
  const chains = hostBuildMarkers(renames);
  if (chains.length === 0) return [];
  const bounds = observedBoundsByHost(chains, renames);

  // 1–2. Markers, per chain, in time order → clusters.
  const marked = events
    .map((e) => ({ e, ms: Date.parse(e.timestamp), kind: buildMarkerKind(e), chain: chainOf(chains, e) }))
    .filter((m) => m.kind && m.chain && !Number.isNaN(m.ms))
    .sort((a, b) => a.ms - b.ms);
  const clusters: Cluster[] = [];
  for (const m of marked) {
    const open = clusters.find((c) => c.chain.host === m.chain!.host && m.ms - c.last <= CLUSTER_GAP_MS);
    if (open) {
      open.last = m.ms;
      open.kinds.set(m.kind!, (open.kinds.get(m.kind!) ?? 0) + 1);
    } else {
      clusters.push({ chain: m.chain!, first: m.ms, last: m.ms, kinds: new Map([[m.kind!, 1]]) });
    }
  }

  // 3. Corroboration and the span limit.
  const windows: BuildTimeWindow[] = [];
  for (const c of clusters) {
    if (c.last - c.first > MAX_MARKER_SPAN_MS) continue;
    const start = c.first - WINDOW_MARGIN_MS;
    const end = c.last + WINDOW_MARGIN_MS;
    const count = [...c.kinds.values()].reduce((a, b) => a + b, 0);
    // Only THIS host's own observed bounds corroborate it: another machine's rename, or an analyst's
    // manual attribution, says nothing about what this one was doing.
    const hasBound = (bounds.get(c.chain.host) ?? []).some((ms) => ms >= start && ms <= end);
    const provisioners = new Map([...c.kinds].filter(([kind]) => !SERVICING_KINDS.has(kind)));
    if (provisioners.size === 0) continue;
    const dense = count >= MIN_MARKERS && provisioners.size >= MIN_MARKER_KINDS;
    if (!hasBound && !dense) continue;
    windows.push({
      host: c.chain.host,
      names: [...c.chain.names],
      start: iso(start),
      end: iso(end),
      marker: dominant(provisioners),
      markerCount: count,
    });
  }

  // 4. Veto: a window holding a hard attacker signal is not applied at all.
  const vetoed = new Set<BuildTimeWindow>();
  for (const e of events) {
    const w = windowFor(windows, e);
    if (w && hardAttackerSignal(e)) vetoed.add(w);
  }
  return windows.filter((w) => !vetoed.has(w));
}

/** The window this row sits in, or undefined. Host and time must both match. */
export function windowFor(
  windows: readonly BuildTimeWindow[],
  e: ForensicEvent,
): BuildTimeWindow | undefined {
  const key = assetKey(e);
  if (!key) return undefined;
  const ms = Date.parse(e.timestamp);
  if (Number.isNaN(ms)) return undefined;
  return windows.find((w) => w.names.includes(key) && ms >= Date.parse(w.start) && ms <= Date.parse(w.end));
}

// ───────────────────────────── the cap ─────────────────────────────

const capped = (s: Severity): Severity =>
  SEVERITY_RANK[s] < SEVERITY_RANK[BUILD_TIME_SEVERITY_CAP] ? BUILD_TIME_SEVERITY_CAP : s;

function withNote(e: ForensicEvent, w: BuildTimeWindow): ForensicEvent {
  const note = `${w.marker}, ${w.start.slice(0, 16)}Z–${w.end.slice(11, 16)}Z`;
  const next: ForensicEvent = {
    ...e,
    severity: capped(e.severity),
    description: appendDerivedNote(e.description, BUILD_TIME_MARKER, note, DESCRIPTION_BASE_MAX),
    buildTime: {
      marker: w.marker,
      window: `${w.start}/${w.end}`,
      ...(capped(e.severity) !== e.severity ? { cappedFrom: e.severity } : {}),
    },
  };
  return next;
}

// The row with every build-time note removed and nothing else changed. For a note that arrived without
// its record (#1698) — a correlated row that unioned a capped member's note — so no grade is touched.
function stripNote(e: ForensicEvent): ForensicEvent {
  return { ...e, description: e.description.replace(BUILD_TIME_NOTE_RE, "").trim() };
}

function withoutNote(e: ForensicEvent): ForensicEvent {
  const { buildTime, ...rest } = e;
  return {
    ...rest,
    severity: buildTime?.cappedFrom ?? e.severity,
    description: e.description.replace(BUILD_TIME_NOTE_RE, "").trim(),
  };
}

/**
 * Cap every forensic row that sits inside a provisioning window, and un-cap every row whose window
 * is gone. Pure and idempotent — a second run over the same state returns the same object.
 *
 * Runs at the import seam AFTER the deterministic content tagger and BEFORE demote (CLAUDE.md §7):
 * the tagger still gets its one chance to promote high-value telemetry, and the cap floors at Low,
 * so a capped row stays in the forensic timeline the model reads. An Info row is never touched —
 * it was never in that record.
 */
export function capBuildTimeRows(state: InvestigationState): {
  state: InvestigationState;
  changed: number;
} {
  const windows = buildTimeWindows(state.forensicTimeline, state.hostRenames ?? []);
  let changed = 0;
  const forensicTimeline = state.forensicTimeline.map((e) => {
    const found = windowFor(windows, e);
    const w = found && !protectedFromCap(e) ? found : undefined;
    // One rule whatever path produced the row (#1698): inside a window, one note and nothing above
    // Low; outside every window, no note. A merge can bring a note without its record, or a record
    // with a grade it raised, and every branch below exists because one of those reached a case.
    if (w && !e.buildTime) {
      changed++;
      return withNote(HAS_BUILD_TIME_NOTE.test(e.description) ? stripNote(e) : e, w);
    }
    // The window moved (a later import extended or narrowed the burst): restore first, then re-mark,
    // so the note and the recorded pre-cap severity describe the window that exists now.
    if (w && e.buildTime && e.buildTime.window !== `${w.start}/${w.end}`) {
      changed++;
      return withNote(withoutNote(e), w);
    }
    // A merge raised a capped row inside its own window. Re-cap it and keep the WORSE of the two
    // original grades, so a later un-cap restores the grade the evidence actually carries.
    if (w && e.buildTime && capped(e.severity) !== e.severity) {
      changed++;
      const cappedFrom = worstSeverity(e.buildTime.cappedFrom ?? e.severity, e.severity);
      return { ...e, severity: capped(e.severity), buildTime: { ...e.buildTime, cappedFrom } };
    }
    if (!w && e.buildTime) {
      changed++;
      return withoutNote(e);
    }
    if (!w && HAS_BUILD_TIME_NOTE.test(e.description)) {
      changed++;
      return stripNote(e);
    }
    return e;
  });
  return changed ? { state: { ...state, forensicTimeline }, changed } : { state, changed: 0 };
}

/**
 * The consistency repair synthesis runs after its own correlation (#1698) — never window discovery.
 *
 * The import seam finds windows BEFORE demote, while the build's Info markers are still in the forensic
 * timeline. Synthesis sees only what demote kept, so recomputing windows there would find a window
 * "gone" and lift a valid cap (Codex review of #1698). This pass therefore never un-caps and never
 * opens a window. It only makes a row agree with itself: a note with no record is removed (grade
 * untouched), and a recorded row a merge raised above the cap is capped again with the worse original
 * grade kept. Protected rows (a hard attacker signal, an analyst's pull) are left as they are.
 */
export function repairBuildTimeRows(state: InvestigationState): {
  state: InvestigationState;
  changed: number;
} {
  let changed = 0;
  const forensicTimeline = state.forensicTimeline.map((e) => {
    if (!e.buildTime) {
      if (!HAS_BUILD_TIME_NOTE.test(e.description)) return e;
      changed++;
      return stripNote(e);
    }
    if (protectedFromCap(e) || capped(e.severity) === e.severity) return e;
    changed++;
    const cappedFrom = worstSeverity(e.buildTime.cappedFrom ?? e.severity, e.severity);
    return { ...e, severity: capped(e.severity), buildTime: { ...e.buildTime, cappedFrom } };
  });
  return changed ? { state: { ...state, forensicTimeline }, changed } : { state, changed: 0 };
}

// ───────────────────────────── what the readers need ─────────────────────────────

/** The `<build-time:…>` tag for the synthesis row render, or "" — the 240-char clip cannot reach it. */
export function renderBuildTimeTag(e: Pick<ForensicEvent, "buildTime">): string {
  const marker = e.buildTime?.marker;
  return marker ? `<build-time:${marker.replace(/[<>\u0000-\u001f]/gu, "")}>` : "";
}

export interface BuildTimeSupport {
  total: number;
  build: number; // cited rows that are the host's own provisioning
  allBuild: boolean;
  firstOutside?: string; // earliest cited row that is NOT build-time
}

/** How much of a finding's cited evidence is the host building itself. */
export function buildTimeSupport(supporting: readonly ForensicEvent[]): BuildTimeSupport {
  const build = supporting.filter((e) => !!e.buildTime).length;
  const outside = supporting
    .filter((e) => !e.buildTime)
    .map((e) => e.timestamp)
    .filter((t) => !Number.isNaN(Date.parse(t)))
    .sort();
  return {
    total: supporting.length,
    build,
    allBuild: supporting.length > 0 && build === supporting.length,
    ...(outside.length ? { firstOutside: outside[0] } : {}),
  };
}

/**
 * The synthesis context block (#1529). Built from the rows themselves, so it costs nothing on a case
 * with no provisioning window, and it carries what the narrative kept getting wrong: the attacker
 * path must not open on a build row and no next step may ask for logs predating the build.
 *
 * The "earliest real activity" line is deliberately hedged three ways — outside every window, graded
 * Medium or higher, and after the host's own provisioning boundary (#1503) — because the install
 * media's own file dates sit outside a window too, and they are not an intrusion either.
 */
export function buildTimeContextBlock(
  events: readonly ForensicEvent[],
  renames: readonly HostRenameRecord[] = [],
): string {
  const rows = events.filter((e) => !!e.buildTime);
  if (rows.length === 0) return "";
  const byWindow = new Map<string, { marker: string; count: number }>();
  for (const e of rows) {
    const key = e.buildTime!.window;
    const cur = byWindow.get(key);
    if (cur) cur.count++;
    else byWindow.set(key, { marker: e.buildTime!.marker, count: 1 });
  }
  const lines = [...byWindow.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([window, v]) => {
      const [start, end] = window.split("/");
      return `- ${start} → ${end}: ${v.marker} (${v.count} row${v.count === 1 ? "" : "s"}, capped at Low)`;
    });

  // Each host is measured against ITS OWN provisioning boundary (#1503). A single case-wide boundary
  // would let a machine built last month hide an attack that happened on another host before it, and
  // a row on a host the ledger never renamed is never filtered at all.
  const chains = hostBuildMarkers(renames);
  const real = events
    .filter((e) => {
      if (e.buildTime || SEVERITY_RANK[e.severity] > SEVERITY_RANK.Medium) return false;
      const bound = Date.parse(chainOf(chains, e)?.before ?? "");
      return Number.isNaN(bound) || Date.parse(e.timestamp) >= bound;
    })
    .map((e) => e.timestamp)
    .filter((t) => !Number.isNaN(Date.parse(t)))
    .sort();

  return (
    `BUILD-TIME BASELINE (deterministic — the host building ITSELF, not the intrusion; these rows are ` +
    `capped at Low and tagged <build-time:…>):\n${lines.join("\n")}\n` +
    `A log clear, an account creation, a driver-service install, a firewall change or an installer ` +
    `script inside these windows is the image being made. Do NOT open the attacker path on one, do ` +
    `not date the incident from one, and do not ask for logs from before them. ` +
    (real.length
      ? `The earliest graded activity outside them is ${real[0]} — start the story there.`
      : `Nothing outside them is graded Medium or higher: say the collection shows no post-provisioning ` +
        `activity rather than dating an intrusion to the build.`) +
    `\n\n`
  );
}
