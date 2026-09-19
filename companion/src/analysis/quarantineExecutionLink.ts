// A quarantine-marked file against the evidence it ran or was used (#1037 link 2, the execution /
// usage path) — the macOS counterpart of downloadExecution.ts's mark ↔ Prefetch/Sysmon join.
//
// The marked file is any row whose envelope carries a `quarantineAttribute` with an established
// path: a collected attribute record, or a launchd job's program (#1407). The evidence is a
// process-start row whose executable is the SAME path, or a Spotlight store item for that path
// with a last-used date — each dated AFTER the mark's own time beyond the tolerance. The path is
// compared byte-exact: APFS may be case-sensitive, and the attribute row deliberately carries no
// structured `path` for the same reason (quarantineJoin.ts). A basename is never a match; a hash
// that both rows carry and disagree on vetoes a path match (a reused path is not the same file).
// Two named hosts must agree; an unnamed side attaches only when the pair names one host.
//
// What a match establishes: that a record says the file at that path started, or was opened or
// used, after it was marked. Not that it was malicious, not that the download caused the run, not
// that a file with no such record never ran (macOS process-execution logs are not parsed here —
// unified-log exec messages are free text; the join runs over whatever process-start rows the
// case already holds). Raises only: the marked row to Medium so it reaches the forensic timeline
// beside the record that explains it, the evidence row to Medium so the next merge can still
// find it. Notes are recomputed on every merge.

import type { QuarantineAttributeBlock } from "./canonicalQuarantine.js";
import { appendDerivedNote, splitDerivedNotes } from "./derivedNote.js";
import {
  excerpt,
  hostOf,
  ms,
  neutral,
  ORDER_TOLERANCE_MS,
  type TimelineEventShape,
} from "./downloadCorroborationShared.js";
import type { Severity } from "./stateTypes.js";

export const RAN_MARKED_MARKER = "[ran a quarantine-marked file:";
export const USED_MARKED_MARKER = "[quarantine-marked file used:";
export const MARKED_FILE_MARKER = "[a quarantine-marked file:";
/** Evidence rows named per marked file; the rest are counted. */
export const EVIDENCE_NAMED_MAX = 8;
const MARKS_PER_EVIDENCE_MAX = 4;
const BUCKET_MAX = 64;
const NOTE_MAX = 700;
const RAISED: Severity = "Medium";
const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

export interface QuarantineExecutionEventShape extends TimelineEventShape {
  canonical?: TimelineEventShape["canonical"] & {
    quarantineAttribute?: QuarantineAttributeBlock;
    process?: { executable?: string };
    spotlightUsage?: { path?: string; lastUsedDate?: string };
  };
}

const OWN = [RAN_MARKED_MARKER, USED_MARKED_MARKER, MARKED_FILE_MARKER].map((m) => m.slice(1, -1));
const OWN_RE = new RegExp(
  `\\s*\\[(?:${OWN.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")}):[\\s\\S]{0,1200}?\\]`,
  "gu",
);

function withoutOwnNotes(description: string | undefined): string {
  const { base, notes } = splitDerivedNotes(description);
  if (!notes) return base;
  return [base, notes.replace(OWN_RE, "").trim()].filter(Boolean).join(" ");
}
const clip = (s: string): string => (s.length > NOTE_MAX ? `${s.slice(0, NOTE_MAX - 1)}…` : s);
const raise = (current: Severity | undefined): Severity =>
  RANK[current ?? "Info"] < RANK[RAISED] ? RAISED : (current ?? "Info");

interface Marked<T> {
  event: T;
  path: string;
  host: string;
  hash?: string;
  /** The mark's own time (the attribute's Unix-hex time), or null when unreadable. */
  anchor: number | null;
}
interface Evidence<T> {
  event: T;
  kind: "ran" | "used";
  path: string;
  host: string;
  hash?: string;
  at: number | null;
}

const markedOf = <T extends QuarantineExecutionEventShape>(e: T): Marked<T> | null => {
  const a = e.canonical?.quarantineAttribute;
  if (!a || a.folded || !a.path || a.pathState) return null;
  const host = a.host && "name" in a.host ? a.host.name.trim().toLowerCase() : hostOf(e);
  const time = a.mark && "time" in a.mark ? a.mark.time : e.timestamp;
  return {
    event: e,
    path: a.path,
    host,
    ...(e.sha256 ? { hash: e.sha256.toLowerCase() } : {}),
    anchor: ms(time),
  };
};

const evidenceOf = <T extends QuarantineExecutionEventShape>(e: T): Evidence<T> | null => {
  const c = e.canonical;
  if (!c) return null;
  if (c.event?.category === "process" && c.event.type === "start") {
    const path = c.process?.executable || e.path || "";
    if (!path) return null;
    return {
      event: e,
      kind: "ran",
      path,
      host: hostOf(e),
      ...(e.sha256 ? { hash: e.sha256.toLowerCase() } : {}),
      at: ms(e.timestamp),
    };
  }
  if (c.spotlightUsage?.path && c.spotlightUsage.lastUsedDate) {
    return {
      event: e,
      kind: "used",
      path: c.spotlightUsage.path,
      host: hostOf(e),
      at: ms(c.spotlightUsage.lastUsedDate),
    };
  }
  return null;
};

/** Two named hosts must agree; an unnamed side attaches only when the pair names one host. */
function hostNote(a: string, b: string): string | null {
  if (a && b) return a === b ? "" : null;
  const named = a || b;
  return named
    ? `host not named on one record — attributed to ${neutral(named).slice(0, 80)}`
    : "host not named on either record";
}

const gapWords = (gapMs: number): string => {
  const s = Math.round(gapMs / 1000);
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86_400) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86_400)} d`;
};

export function linkQuarantineExecution<T extends QuarantineExecutionEventShape>(events: readonly T[]): T[] {
  const stripped = events.map((e) => {
    const description = withoutOwnNotes(e.description);
    return description === (e.description ?? "") ? e : { ...e, description };
  });
  const marked = stripped.map(markedOf).filter((m): m is Marked<T> => m !== null);
  if (!marked.length) return stripped;
  const byPath = new Map<string, Evidence<T>[]>();
  for (const e of stripped) {
    const ev = evidenceOf(e);
    if (!ev) continue;
    const list = byPath.get(ev.path) ?? byPath.set(ev.path, []).get(ev.path)!;
    if (list.length < BUCKET_MAX) list.push(ev);
  }
  const markNotes = new Map<T, { ran: string[]; used: string[]; more: number }>();
  const evidenceNotes = new Map<T, { marks: string[]; more: number }>();
  for (const m of marked) {
    const candidates = byPath.get(m.path) ?? [];
    for (const ev of candidates) {
      const hn = hostNote(m.host, ev.host);
      if (hn === null) continue;
      if (m.hash && ev.hash && m.hash !== ev.hash) continue;
      if (m.anchor === null || ev.at === null || ev.at - m.anchor <= ORDER_TOLERANCE_MS) continue;
      const note =
        markNotes.get(m.event) ?? markNotes.set(m.event, { ran: [], used: [], more: 0 }).get(m.event)!;
      const when = `${gapWords(ev.at - m.anchor)} after the mark`;
      const words =
        ev.kind === "ran"
          ? `${excerpt(ev.event.description ?? "")} — ${when}${hn ? ` (${hn})` : ""}`
          : `Spotlight last-used ${neutral(ev.event.canonical?.spotlightUsage?.lastUsedDate ?? "").slice(0, 40)} — ${when} — opened or used, not necessarily executed${hn ? ` (${hn})` : ""}`;
      if (note.ran.length + note.used.length < EVIDENCE_NAMED_MAX)
        (ev.kind === "ran" ? note.ran : note.used).push(words);
      else note.more += 1;
      const en =
        evidenceNotes.get(ev.event) ?? evidenceNotes.set(ev.event, { marks: [], more: 0 }).get(ev.event)!;
      if (en.marks.length < MARKS_PER_EVIDENCE_MAX)
        en.marks.push(
          `${neutral(m.path).slice(0, 200)}${m.host ? ` on ${neutral(m.host).slice(0, 80)}` : ""}`,
        );
      else en.more += 1;
    }
  }
  return stripped.map((e) => {
    let description = e.description ?? "";
    let severity = e.severity;
    const mn = markNotes.get(e);
    if (mn) {
      // The count leads, so a long list clipped at NOTE_MAX still says how many records there are.
      const total = mn.ran.length + mn.used.length + mn.more;
      const head = (n: number): string =>
        mn.more ? `${n} of ${total} records (+${mn.more} more not named): ` : "";
      if (mn.ran.length)
        description = appendDerivedNote(
          description,
          RAN_MARKED_MARKER,
          clip(head(mn.ran.length) + mn.ran.join("; ")),
        );
      if (mn.used.length)
        description = appendDerivedNote(
          description,
          USED_MARKED_MARKER,
          clip(head(mn.used.length) + mn.used.join("; ")),
        );
      severity = raise(severity);
    }
    const en = evidenceNotes.get(e);
    if (en) {
      const words = [...en.marks, ...(en.more ? [`+${en.more} more`] : [])].join("; ");
      description = appendDerivedNote(description, MARKED_FILE_MARKER, clip(words));
      severity = raise(severity);
    }
    if (description === (e.description ?? "") && severity === e.severity) return e;
    return { ...e, description, ...(severity !== undefined ? { severity } : {}) };
  });
}
