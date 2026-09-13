// Ransomware precursor correlation (#908 item 3).
//
// The minutes before encryption look the same across families, and none of the individual steps is
// remarkable on its own. Defender gets turned off. The firewall is opened or an ACL rewritten.
// Ownership of a directory is taken. Event logs are cleared. Shadow copies are deleted and backups
// disabled. Every one of those is something an administrator does on an ordinary Tuesday.
//
// What is not ordinary is SEVERAL OF THEM, on one host, inside a few minutes. That combination is
// the finding, and it is invisible to any rule that looks at one command at a time — which is why
// the Companion could tag each step and still never say "this host is about to be encrypted".
//
// ─────────────────────────── WHY A SINGLE STEP CANNOT COUNT ───────────────────────────
//
// The issue is explicit: a single maintenance command must not establish a ransomware verdict, and
// approved administration has to be accounted for. So:
//
//   • DISTINCT BEHAVIOUR CLASSES are counted, never events. Ten `vssadmin delete` lines from one
//     script are one behaviour, not ten — otherwise a single loop manufactures a verdict.
//   • The same command reported by two tools is one behaviour. Overlapping telemetry is the normal
//     case in a case that imported both EDR and event logs, and counting it twice inflates
//     confidence in exactly the situation where the evidence is strongest and least ambiguous.
//   • The threshold is three classes, not two. Two is a plausible maintenance window — disabling a
//     scanner to install something, then clearing a noisy log.
//
// The finding names WHICH behaviours contributed and links the events that carried them, because
// "ransomware precursors detected" without the list is not something an analyst can check.
//
// ─────────────────────────── WHAT THIS PASS CANNOT SEE ───────────────────────────
//
// Approved administration is handled by SAYING SO, not by filtering. False-positive markers live in
// their own store and are applied when the timeline is PROJECTED, not held in state — so a pass
// running at merge time has no access to them and cannot exclude a behaviour the analyst has
// already explained. A dismissed event is still dropped from what the analyst sees, but it can
// contribute to the class count that formed the group.
//
// That is why the note ends by telling the reader to confirm against change records: the pass
// cannot do it, and pretending otherwise would be worse than saying so.

import type { ForensicEvent, Severity } from "./stateTypes.js";
import { normalizeCommand } from "./commandNormalize.js";
import { shortHost } from "./correlate.js";
import { appendDerivedNote } from "./derivedNote.js";

/** The behaviour classes that make up the pattern, keyed by the technique that identifies them. */
export const PRECURSOR_CLASSES: { id: string; label: string; techniques: string[] }[] = [
  {
    id: "security-tools",
    label: "security tooling disabled or tampered with",
    techniques: ["T1562.001", "T1562.006", "T1562"],
  },
  {
    id: "firewall-acl",
    label: "firewall changed",
    techniques: ["T1562.004"],
  },
  {
    id: "logs",
    label: "event logs cleared or logging disabled",
    techniques: ["T1070.001", "T1562.002"],
  },
  {
    id: "recovery",
    label: "backups or shadow copies removed",
    techniques: ["T1490"],
  },
  {
    // Ownership and permissions. Listed AFTER firewall previously and sharing its technique ids, so
    // classOf — which returns the first match — could never reach it. The ids are separated now.
    id: "ownership",
    label: "file ownership or permissions taken",
    techniques: ["T1222", "T1222.001", "T1222.002"],
  },
];

/** How many DISTINCT classes must appear before the pattern is reported. */
export const MIN_CLASSES = 3;

/** How close together, in milliseconds. */
export const DEFAULT_WINDOW_MS = 60 * 60 * 1000;

/** Most recent precursor events considered per host, bounding the quadratic window walk. */
export const MAX_EVENTS_PER_HOST = 2_000;

/** The marker this pass appends. Stripped by correlate.ts before a duplicate key is taken. */
export const PRECURSOR_MARKER = "[ransomware precursors:";

const RANK: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

function classOf(techniques: readonly string[]): string | null {
  for (const c of PRECURSOR_CLASSES) {
    if (c.techniques.some((t) => techniques.includes(t))) return c.id;
  }
  return null;
}

function labelOf(id: string): string {
  return PRECURSOR_CLASSES.find((c) => c.id === id)?.label ?? id;
}

/**
 * A behaviour, identified so the same one reported twice is counted once.
 *
 * The key is the class plus the command that carried it — not the event id. Two tools reporting one
 * `vssadmin delete shadows` are two events describing one action, and treating them as two
 * behaviours would inflate confidence precisely where the evidence is least ambiguous.
 */
function behaviourKey(e: ForensicEvent, cls: string): string {
  const raw = (e.commandLine ?? "").trim();
  if (raw) {
    // The repository's normalizer, so two tools that quote or escape the same command differently
    // still produce one key. Trim-and-lowercase alone missed those.
    return `${cls}|${normalizeCommand(raw).text.toLowerCase().replace(/\s+/g, " ")}`;
  }
  // No command line. The description is all there is, and a fixed-length PREFIX of it collided:
  // two different actions in one class whose text starts the same way became one behaviour, and one
  // event's evidence disappeared. The whole normalized description is used instead.
  return `${cls}|${(e.description ?? "").trim().toLowerCase().replace(/\s+/g, " ")}`;
}

export interface PrecursorGroup {
  host: string;
  classes: string[];
  eventIds: string[];
  first: string;
  last: string;
  severity: Severity;
  note: string;
}

/**
 * Find hosts where several distinct precursor behaviours cluster inside one window.
 *
 * Pure. Returns the groups; the timeline pass below applies them.
 */
export function findPrecursorGroups(
  events: readonly ForensicEvent[],
  opts: { windowMs?: number; minClasses?: number } = {},
): PrecursorGroup[] {
  const windowMs = opts.windowMs ?? DEFAULT_WINDOW_MS;
  const minClasses = opts.minClasses ?? MIN_CLASSES;

  // Per host, the precursor events in time order.
  const byHost = new Map<string, { t: number; e: ForensicEvent; cls: string }[]>();
  for (const e of events) {
    if (!e.asset) continue;
    const cls = classOf(e.mitreTechniques ?? []);
    if (!cls) continue;
    const t = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(t)) continue; // an undated event cannot be placed in a window
    // The repository's host normalizer: an exact-string key never matched HOST against
    // HOST.domain.local, which is how the same machine arrives from two importers.
    const host = shortHost(e.asset) || e.asset;
    const list = byHost.get(host) ?? [];
    list.push({ t, e, cls });
    byHost.set(host, list);
  }

  const out: PrecursorGroup[] = [];
  for (const [host, all] of byHost) {
    // Bounded. The window walk is quadratic in one host's precursor events, and an accumulated case
    // timeline has no cap of its own — the newest events are the ones an analyst is working from.
    const list = all.length > MAX_EVENTS_PER_HOST ? all.slice(-MAX_EVENTS_PER_HOST) : all;
    list.sort((a, b) => a.t - b.t);

    // The densest window, walked once. Distinct CLASSES are what count, and a behaviour seen twice
    // counts once — see behaviourKey.
    let best: { classes: Set<string>; ids: string[]; first: number; last: number } | null = null;
    for (let start = 0; start < list.length; start++) {
      const classes = new Set<string>();
      const seen = new Set<string>();
      const ids: string[] = [];
      let end = start;
      while (end < list.length && list[end].t - list[start].t <= windowMs) {
        const item = list[end];
        const key = behaviourKey(item.e, item.cls);
        if (!seen.has(key)) {
          seen.add(key);
          classes.add(item.cls);
          if (ids.length < 20) ids.push(item.e.id);
        }
        end++;
      }
      if (classes.size >= minClasses && (!best || classes.size > best.classes.size)) {
        best = { classes, ids, first: list[start].t, last: list[end - 1].t };
      }
    }
    if (!best) continue;

    const labels = [...best.classes].map(labelOf);
    out.push({
      host,
      classes: [...best.classes],
      eventIds: best.ids,
      first: new Date(best.first).toISOString(),
      last: new Date(best.last).toISOString(),
      // High, not Critical: this is the shape that precedes encryption, and it is also the shape of
      // an aggressive but legitimate maintenance window. It is a reason to act now, not a verdict
      // that encryption happened.
      severity: "High",
      note:
        `${best.classes.size} distinct precursor behaviours on ${host} within ` +
        `${Math.max(1, Math.round((best.last - best.first) / 60000))} minute(s): ${labels.join("; ")}. ` +
        `Contributing events: ${best.ids.join(", ")}. ` +
        "Each of these is something an administrator also does; several together, on one host, in " +
        "one window is the pattern that precedes encryption. This does not establish that " +
        "encryption occurred, and an approved maintenance window can produce the same shape — " +
        "confirm against change records before acting on it as an incident.",
    });
  }
  return out;
}

/**
 * Raise the contributing events, and say why.
 *
 * Only ever raises, and is idempotent: the marker is appended once and the severity uses a floor.
 */
export function markRansomwarePrecursors(
  events: readonly ForensicEvent[],
  opts: { windowMs?: number; minClasses?: number } = {},
): ForensicEvent[] {
  const groups = findPrecursorGroups(events, opts);
  if (groups.length === 0) return events as ForensicEvent[];

  const noteFor = new Map<string, string>();
  for (const g of groups) for (const id of g.eventIds) noteFor.set(id, g.note);

  return events.map((e) => {
    const note = noteFor.get(e.id);
    if (!note) return e;
    if ((e.description ?? "").includes(PRECURSOR_MARKER)) return e;
    // NO technique is added. Tagging these T1486 (Data Encrypted for Impact) said the opposite of
    // the note attached to the same event, and it reached the MITRE panel, the report and the
    // ATT&CK Navigator export as a High-confidence encryption claim with no encryption evidence
    // behind it. The events keep the techniques their own evidence supports.
    const severity: Severity = RANK["High"] > RANK[e.severity] ? "High" : e.severity;
    return {
      ...e,
      severity,
      description: appendDerivedNote(e.description, PRECURSOR_MARKER, note),
    };
  });
}
