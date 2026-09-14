// A Defender action, then a later start of the same file on the same host (#930 item 1 part B —
// #964). Part A (#968) made the Defender Operational records honest rows with a typed envelope;
// this pass is the join the item asks for: "flag a subsequent execution attempt or observed
// execution of the same payload". It runs at merge time, beside the download-execution pass and
// for the same reason — the Defender record and the process start arrive from different imports.
//
// WHAT IT ESTABLISHES. That a process-start record (Sysmon 1, Security 4688, an EDR start row)
// names the same host and the same path as one of a Defender record's flagged resources, and is
// dated after that record — and, only when the Defender record carries its OWN sha256, that the
// start's image is the same bytes. It binds the start to ONE Defender record: the one whose
// interval it falls in (from that record's time to the next Defender record of the same episode),
// and the note carries THAT record's disposition — never the episode's latest, never a later one.
//
// WHAT IT NEVER CLAIMS. A path match is a path match: "a process later started from the same
// path", not "the same file", not "retry", not "re-dropped" — a reused path is not the same
// bytes. No hash is borrowed from an earlier row at the path: a file hashed before the detection
// may have been overwritten before Defender looked, so a borrowed digest can neither prove the
// same bytes nor veto a path match. No technique is added: a process start is not user-mediated
// launch (T1204.002) and supports execution, not completion. No second AV alert is not evidence
// that the file ran or that remediation held. The scanner runs as SYSTEM, so its identity is never
// the launcher — the start row's own account is. A drive letter is not removable media.
// `allowed` is not a compromise verdict; `remediated` is not proof the file never ran. A start
// before the Defender record is not "after"; one inside the tolerance has no established order.
//
// Typed input only: the pass reads `canonical.defender`, `canonical.event`, the start row's own
// `sha256`, `asset`, `path` and `timestamp` — never the description. Only ever raises; its notes
// are recomputed from the current evidence on every merge.

import type { Severity } from "./stateTypes.js";
import type { DefenderBlock } from "./canonicalDefender.js";
import { appendDerivedNote, splitDerivedNotes } from "./derivedNote.js";
import { canonicalHostName } from "./hostAlias.js";
import { filePath } from "./downloadExecution.js";
import { createHash } from "node:crypto";

/** The marker this pass appends. Registered in derivedNote.ts; stripped by correlate.ts before a duplicate key is taken. */
export const DEFENDER_SEQUEL_MARKER = "[after Defender:";
/** A start inside this window of the Defender record has no established order. */
export const DEFENDER_SEQUEL_TOLERANCE_MS = 2000;
/** Starts named on one Defender record's note; the rest are counted. */
export const STARTS_NAMED_MAX = 8;
/** Defender records indexed per host; the rest are counted, never read. */
const RECORDS_PER_HOST_MAX = 512;
/** Start rows indexed per host+path / host+hash bucket; the rest counted. */
const BUCKET_MAX = 64;
const NOTE_MAX = 900;
const DEFAULT_GAP_HOURS = 24;
const GAP_HOURS_MIN = 1;
const GAP_HOURS_MAX = 720;

/** `DFIR_DEFENDER_EPISODE_GAP_HOURS`: two Defender records of one identity further apart than this are two episodes. */
export function defenderEpisodeGapHours(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.DFIR_DEFENDER_EPISODE_GAP_HOURS);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_GAP_HOURS;
  return Math.min(GAP_HOURS_MAX, Math.max(GAP_HOURS_MIN, n));
}

export interface DefenderTimelineShape {
  id?: string;
  description?: string;
  asset?: string;
  severity?: Severity;
  mitreTechniques?: string[];
  path?: string;
  sha256?: string;
  timestamp?: string;
  canonical?: {
    event?: { category?: string; type?: string };
    file?: { sha256?: string };
    time?: { normalized?: string };
    defender?: DefenderBlock;
  };
}

const RANK: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

// ───────────────────────────── reading rows ─────────────────────────────

export interface DefenderRecord<T> {
  event: T;
  block: DefenderBlock;
  host: string;
  at: number;
  /** Normalised resource paths (filePath relative form) the record flagged. */
  resources: string[];
  /** The record's OWN digest, when the export carried one. Never borrowed. */
  sha256?: string;
}

export interface DefenderEpisode<T> {
  /** A digest of the identity and the first record's time — record content, never a timeline event id. */
  id: string;
  identity: string;
  records: DefenderRecord<T>[];
}

export interface StartMatch<T> {
  event: T;
  by: "path" | "hash";
  at: number;
  path: string;
}

export interface EpisodeMatch<T> {
  episode: DefenderEpisode<T>;
  record: DefenderRecord<T>;
  disposition: DefenderBlock["disposition"];
  /** In time order, every matched start in this record's interval (bounded by the buckets). */
  starts: StartMatch<T>[];
  /** Resources the record listed beyond the bounded list — never read. */
  resourcesNotRead: number;
}

const ms = (iso: string | undefined): number | null => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};

const relativeOf = (raw: string): string | null => filePath(raw)?.relative ?? null;

/** One Defender row as the matcher reads it, or null when the row carries no block, host or time. */
export function readDefenderRecord<T extends DefenderTimelineShape>(e: T): DefenderRecord<T> | null {
  const block = e.canonical?.defender;
  if (!block || !e.asset) return null;
  const at = ms(e.canonical?.time?.normalized) ?? ms(e.timestamp);
  if (at === null) return null;
  const resources = block.resources.map(relativeOf).filter((p): p is string => !!p);
  const sha = (e.canonical?.file?.sha256 ?? e.sha256)?.toLowerCase();
  return {
    event: e,
    block,
    host: canonicalHostName(e.asset),
    at,
    resources,
    ...(sha ? { sha256: sha } : {}),
  };
}

const isProcessStart = (e: DefenderTimelineShape): boolean =>
  e.canonical?.event?.category === "process" && e.canonical.event.type === "start";

// ───────────────────────────── episodes ─────────────────────────────

const short = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 12);

/** The episode identity: host + Detection ID, else host + threat + normalised primary path. */
export function defenderIdentity<T>(r: DefenderRecord<T>): string {
  const key = r.block.detectionId
    ? `id|${r.block.detectionId.toLowerCase()}`
    : `threat|${r.block.threat.toLowerCase()}|${r.resources[0] ?? ""}`;
  return `${r.host}|${key}`;
}

/**
 * Group the timeline's Defender records into episodes: one identity, closed by a gap of
 * `gapHours` between consecutive records. Pure; records sorted by time within an episode.
 */
export function defenderEpisodes<T extends DefenderTimelineShape>(
  events: readonly T[],
  gapHours: number,
): DefenderEpisode<T>[] {
  const perHost = new Map<string, number>();
  const byIdentity = new Map<string, DefenderRecord<T>[]>();
  for (const e of events) {
    const r = readDefenderRecord(e);
    if (!r) continue;
    const n = perHost.get(r.host) ?? 0;
    perHost.set(r.host, n + 1);
    if (n >= RECORDS_PER_HOST_MAX) continue;
    const key = defenderIdentity(r);
    (byIdentity.get(key) ?? byIdentity.set(key, []).get(key)!).push(r);
  }
  const gap = gapHours * 3_600_000;
  const out: DefenderEpisode<T>[] = [];
  for (const [identity, records] of byIdentity) {
    records.sort((a, b) => a.at - b.at);
    let current: DefenderRecord<T>[] = [];
    const flush = () => {
      if (!current.length) return;
      out.push({ id: short(`${identity}|${current[0].at}`), identity, records: current });
      current = [];
    };
    for (const r of records) {
      if (current.length && r.at - current[current.length - 1].at > gap) flush();
      current.push(r);
    }
    flush();
  }
  return out.sort((a, b) => a.records[0].at - b.records[0].at || a.id.localeCompare(b.id));
}

// ───────────────────────────── hosts ─────────────────────────────

const label = (host: string): string => host.split(".")[0];

/**
 * Whether two assets name one machine: equal canonical names, or equal first labels when that
 * label names exactly one host across the timeline. Two hosts sharing a label under different
 * domains never pair (hostAlias.ts: a short-name/FQDN pair nothing has linked is not one host).
 */
function sameHost(a: string, b: string, hostsByLabel: ReadonlyMap<string, Set<string>>): boolean {
  if (a === b) return true;
  const la = label(a);
  if (la !== label(b)) return false;
  // Every distinct full name under this label, the bare label itself not counted.
  const full = [...(hostsByLabel.get(la) ?? [])].filter((h) => h !== la);
  return full.length <= 1;
}

// ───────────────────────────── the matcher ─────────────────────────────

interface Bucket<T> {
  starts: { event: T; at: number; path: string; sha256?: string }[];
  beyond: number;
}

function addToBucket<T>(map: Map<string, Bucket<T>>, key: string, s: Bucket<T>["starts"][number]): void {
  const b = map.get(key) ?? map.set(key, { starts: [], beyond: 0 }).get(key)!;
  if (b.starts.length < BUCKET_MAX) b.starts.push(s);
  else b.beyond += 1;
}

/**
 * Every Defender record with at least one later start of the same path (or, with the record's
 * own digest, the same bytes) on the same host inside its interval. The typed result both the
 * annotator here and the finding pass (defenderEpisodeFindings.ts) read.
 */
export function defenderEpisodeMatches<T extends DefenderTimelineShape>(
  events: readonly T[],
  gapHours: number = defenderEpisodeGapHours(),
): EpisodeMatch<T>[] {
  const episodes = defenderEpisodes(events, gapHours);
  if (!episodes.length) return [];
  const hostsByLabel = new Map<string, Set<string>>();
  for (const e of events) {
    if (!e.asset) continue;
    const h = canonicalHostName(e.asset);
    (hostsByLabel.get(label(h)) ?? hostsByLabel.set(label(h), new Set()).get(label(h))!).add(h);
  }
  // Starts bucketed by label+path and label+hash; the host rule is judged per candidate.
  const byPath = new Map<string, Bucket<T>>();
  const byHash = new Map<string, Bucket<T>>();
  for (const e of events) {
    if (!isProcessStart(e) || !e.path || !e.asset) continue;
    const at = ms(e.timestamp);
    const rel = relativeOf(e.path);
    if (at === null || !rel) continue;
    const host = canonicalHostName(e.asset);
    const sha = e.sha256?.toLowerCase();
    const s = { event: e, at, path: e.path, ...(sha ? { sha256: sha } : {}) };
    addToBucket(byPath, `${label(host)}|${rel}`, s);
    if (sha) addToBucket(byHash, `${label(host)}|${sha}`, s);
  }
  const gap = gapHours * 3_600_000;
  const out: EpisodeMatch<T>[] = [];
  for (const episode of episodes) {
    for (const [i, record] of episode.records.entries()) {
      const next = episode.records[i + 1];
      // Inside the tolerance (inclusive) no order is established; the interval closes at the next
      // record of the episode, else at the gap bound.
      const from = record.at + DEFENDER_SEQUEL_TOLERANCE_MS;
      const to = next ? next.at : record.at + gap;
      const seen = new Set<T>();
      const starts: StartMatch<T>[] = [];
      const consider = (bucket: Bucket<T> | undefined, by: StartMatch<T>["by"]) => {
        for (const s of bucket?.starts ?? []) {
          if (seen.has(s.event) || s.at <= from || s.at > to) continue;
          if (!sameHost(record.host, canonicalHostName(s.event.asset ?? ""), hostsByLabel)) continue;
          seen.add(s.event);
          starts.push({ event: s.event, by, at: s.at, path: s.path });
        }
      };
      // The record's own digest first, so a start that is both reads as "the same file".
      if (record.sha256) consider(byHash.get(`${label(record.host)}|${record.sha256}`), "hash");
      for (const rel of record.resources) consider(byPath.get(`${label(record.host)}|${rel}`), "path");
      if (!starts.length) continue;
      starts.sort((a, b) => a.at - b.at || String(a.event.id).localeCompare(String(b.event.id)));
      out.push({
        episode,
        record,
        disposition: record.block.disposition,
        starts,
        resourcesNotRead: Math.max(0, record.block.resourcesTotal - record.block.resources.length),
      });
    }
  }
  return out;
}

// ───────────────────────────── words ─────────────────────────────

/** Brackets to parentheses, control characters and hash runs neutralised (recordIdentity.ts). */
const neutral = (t: string): string =>
  t
    .replace(/\[/g, "(")
    .replace(/\]/g, ")")
    .replace(/[ --]/g, " ")
    .replace(/\s+/g, " ")
    .replace(/[a-f0-9]{32,}/gi, (m) => `${m.slice(0, 8)}…${m.slice(-4)}`)
    .trim();
const clipNote = (s: string): string => (s.length > NOTE_MAX ? `${s.slice(0, NOTE_MAX - 1)}…` : s);

/** `<disposition> of <threat>` — a detection-only record reads "detected (no action recorded)". */
export function dispositionWords(block: DefenderBlock): string {
  const threat = neutral(block.threat).slice(0, 120);
  return block.eventType === "detection"
    ? `detected (no action recorded) ${threat}`
    : `${block.disposition} of ${threat}`;
}

/** `1h 5m later` from the Defender record to the start. */
export function laterWords(fromMs: number, toMs: number): string {
  const minutes = Math.max(0, Math.round((toMs - fromMs) / 60_000));
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m later`;
}

function startNote<T>(m: EpisodeMatch<T>, s: StartMatch<T>): string {
  const path = neutral(s.path).slice(0, 300);
  const what =
    s.by === "hash"
      ? `the same file (sha256) later started from ${path}`
      : `a process later started from the same path ${path}`;
  return `${dispositionWords(m.record.block)}; ${what} (${laterWords(m.record.at, s.at)})`;
}

function recordNote<T>(m: EpisodeMatch<T>): string {
  const byHash = m.starts.filter((s) => s.by === "hash").length;
  const n = m.starts.length;
  const what =
    byHash === n
      ? `from the same file`
      : byHash
        ? `from the same path (${byHash} the same file)`
        : `from the same path`;
  const first = new Date(m.starts[0].at).toISOString();
  const tail = m.resourcesNotRead
    ? `; ${m.resourcesNotRead} of ${m.record.block.resourcesTotal} listed resources not read`
    : "";
  return `${dispositionWords(m.record.block)}; ${n} later start${n === 1 ? "" : "s"} ${what}, first at ${first}${tail}`;
}

// ───────────────────────────── the pass ─────────────────────────────

const OWN_NOTE = /\s*\[after Defender:[\s\S]{0,1200}?\]/gu;

/** The description with this pass's own notes removed — recomputed on every merge. */
function withoutOwnNotes(description: string | undefined): string {
  const { base, notes } = splitDerivedNotes(description);
  if (!notes) return base;
  return [base, notes.replace(OWN_NOTE, "").trim()].filter(Boolean).join(" ");
}

function raise(current: Severity | undefined, to: Severity): Severity {
  return RANK[to] > RANK[current ?? "Info"] ? to : (current ?? "Info");
}

/**
 * Annotate every start that followed a Defender record on the same file, and the record with what
 * followed. A path match raises the start to Medium, a hash match to High; the Defender record's
 * own severity never changes. Pure; idempotent across merges.
 */
export function corroborateDefenderEpisodes<T extends DefenderTimelineShape>(
  events: readonly T[],
  gapHours: number = defenderEpisodeGapHours(),
): T[] {
  const matches = defenderEpisodeMatches(events, gapHours);
  const startNotes = new Map<T, { note: string; to: Severity }>();
  const recordNotes = new Map<T, string>();
  for (const m of matches) {
    recordNotes.set(m.record.event, recordNote(m));
    for (const s of m.starts.slice(0, STARTS_NAMED_MAX))
      startNotes.set(s.event, { note: startNote(m, s), to: s.by === "hash" ? "High" : "Medium" });
  }
  return events.map((e) => {
    const base = withoutOwnNotes(e.description);
    let description = base;
    let severity = e.severity ?? "Info";
    const s = startNotes.get(e);
    if (s) {
      description = appendDerivedNote(description, DEFENDER_SEQUEL_MARKER, clipNote(s.note));
      severity = raise(severity, s.to);
    }
    const r = recordNotes.get(e);
    if (r) description = appendDerivedNote(description, DEFENDER_SEQUEL_MARKER, clipNote(r));
    if (description === (e.description ?? "") && severity === (e.severity ?? "Info")) return e;
    return { ...e, description, severity };
  });
}
