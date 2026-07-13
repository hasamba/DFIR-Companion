// Per-case prevalence / baseline index (investigation-guidance #15). Marking one event a false positive
// teaches the system nothing about how COMMON that pattern is; synthesis then re-grades the same
// nightly-robocopy High every import because it has no baseline. This module computes, per case, how
// often each normalized activity PATTERN occurs across the timeline — so a pattern seen 500× on 14 hosts
// reads as routine and a 1-off reads as an anomaly worth a seat. Pure + deterministic, derived on read
// from fields the importers already populate (NO persisted index, NO AI).
//
// The pattern KEY deliberately ignores the host and volatile tokens (numbers, paths, hashes-as-args,
// GUIDs) so the SAME command shape on different hosts collapses to one pattern whose host-spread we can
// then count. Content hashes (sha256/md5) are the strongest key when present.

import type { ForensicEvent } from "./stateTypes.js";

export interface PatternStats {
  key: string;
  count: number;        // total occurrences of this pattern in the corpus
  hosts: Set<string>;   // distinct assets it appeared on
  first: string;        // earliest dated occurrence (ISO); "" if all undated
  last: string;         // latest dated occurrence (ISO); "" if all undated
}
export type PrevalenceIndex = Map<string, PatternStats>;

export const RARE_MAX_DEFAULT = 2;    // ≤ this many occurrences → rare (anomaly-ish)
export const COMMON_MIN_DEFAULT = 20; // ≥ this many occurrences → common (baseline noise)

// Collapse a command line / description to a stable SHAPE: lowercase, and replace volatile tokens
// (hashes, GUIDs, Windows + UNC + Unix paths, quoted strings, bare numbers) with placeholders, so
// "robocopy C:\\data\\1 \\\\srv1\\bak /mir" and "robocopy C:\\data\\2 \\\\srv2\\bak /mir" fingerprint the
// same. Order matters: paths/hashes before the bare-number pass. Bounded output length.
export function commandShape(text: string): string {
  let s = String(text ?? "").toLowerCase();
  s = s.replace(/\b[a-f0-9]{32,64}\b/g, "<hash>");                          // md5/sha1/sha256 as args
  s = s.replace(/\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?/g, "<guid>");
  s = s.replace(/\\\\[^\s"']+/g, "<unc>");                                  // \\server\share…
  s = s.replace(/[a-z]:\\[^\s"']*/g, "<path>");                             // C:\dir\file
  s = s.replace(/(?:\/[^\s"'/]+){2,}\/?/g, "<path>");                       // /usr/bin/… (≥2 segments)
  s = s.replace(/"[^"]*"/g, "<str>").replace(/'[^']*'/g, "<str>");          // quoted strings
  s = s.replace(/\b\d[\d.,:]*\b/g, "<n>");                                   // bare numbers / versions / times
  s = s.replace(/\s+/g, " ").trim();
  return s.slice(0, 200);
}

// The canonical pattern key for an event. A content hash is the strongest (same binary anywhere), else
// process + command shape, else the bare description shape. Returns "" when the event has no stable
// pattern (empty description, no hash/process) — such events are skipped from the index.
export function patternKey(e: ForensicEvent): string {
  const hash = (e.sha256 ?? e.md5 ?? "").trim().toLowerCase();
  if (hash) return `hash:${hash}`;
  const proc = (e.processName ?? "").trim().toLowerCase();
  const shape = commandShape(e.description ?? "");
  if (proc) return `proc:${proc}|${shape}`;
  if (shape) return `desc:${shape}`;
  return "";
}

// Build the per-case prevalence index over a corpus (pass the forensic timeline, optionally unioned with
// the super-timeline for a fuller baseline). Undated events still count toward totals/host-spread.
export function buildPrevalenceIndex(events: readonly ForensicEvent[]): PrevalenceIndex {
  const index: PrevalenceIndex = new Map();
  for (const e of events) {
    const key = patternKey(e);
    if (!key) continue;
    let stats = index.get(key);
    if (!stats) { stats = { key, count: 0, hosts: new Set(), first: "", last: "" }; index.set(key, stats); }
    stats.count += 1;
    const asset = (e.asset ?? "").trim();
    if (asset) stats.hosts.add(asset.toLowerCase());
    const t = Date.parse(e.timestamp);
    if (!Number.isNaN(t)) {
      if (!stats.first || t < Date.parse(stats.first)) stats.first = new Date(t).toISOString();
      if (!stats.last || t > Date.parse(stats.last)) stats.last = new Date(t).toISOString();
    }
  }
  return index;
}

export interface EventPrevalence {
  count: number;
  hostCount: number;
  spanDays: number;   // whole days between first and last dated occurrence (0 when single/undated)
}

// Look up an event's prevalence. Returns null when the event has no stable pattern key.
export function eventPrevalence(e: ForensicEvent, index: PrevalenceIndex): EventPrevalence | null {
  const key = patternKey(e);
  if (!key) return null;
  const stats = index.get(key);
  if (!stats) return null;
  const spanMs = stats.first && stats.last ? Date.parse(stats.last) - Date.parse(stats.first) : 0;
  return { count: stats.count, hostCount: stats.hosts.size, spanDays: Math.max(0, Math.floor(spanMs / 86_400_000)) };
}

export function isRare(p: EventPrevalence, rareMax = RARE_MAX_DEFAULT): boolean {
  return p.count <= rareMax;
}
export function isCommon(p: EventPrevalence, commonMin = COMMON_MIN_DEFAULT): boolean {
  return p.count >= commonMin;
}

// A compact human tag for a prompt line / dashboard chip. "" for the uninformative middle band (only the
// extremes — clearly common baseline vs clearly rare — earn a tag so the prompt stays lean).
export function prevalenceTag(
  p: EventPrevalence,
  opts: { rareMax?: number; commonMin?: number } = {},
): string {
  const rareMax = opts.rareMax ?? RARE_MAX_DEFAULT;
  const commonMin = opts.commonMin ?? COMMON_MIN_DEFAULT;
  const span = p.spanDays > 0 ? ` over ${p.spanDays}d` : "";
  const hosts = p.hostCount > 0 ? ` on ${p.hostCount} host${p.hostCount === 1 ? "" : "s"}` : "";
  if (p.count >= commonMin) return `common: seen ${p.count}×${hosts}${span}`;
  if (p.count <= rareMax) return `rare: seen ${p.count}×${hosts}`;
  return "";
}

// Rarity score for the synthesis selection bias (#4): higher = rarer = more worth a seat. 1/count so a
// singleton scores 1.0 and a 500× pattern ~0.002. An event with no pattern key scores 0 (neutral).
export function rarityScore(e: ForensicEvent, index: PrevalenceIndex): number {
  const p = eventPrevalence(e, index);
  return p && p.count > 0 ? 1 / p.count : 0;
}
