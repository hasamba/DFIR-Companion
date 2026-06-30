// Deterministic cross-source correlation: the same real-world artifact is often
// reported by more than one tool (e.g. a Velociraptor alert AND a THOR alert about the
// same downloaded file). Without correlation each tool produces its own timeline event
// and (via synthesis/backfill) its own finding — duplicating the same fact. This pass
// groups events that describe the SAME artifact and merges them into one canonical
// event that carries every tool as a source (corroboration raises confidence).
//
// Matching (per the chosen policy): two events correlate if they share a file HASH
// (sha256/md5 — exact), OR the same normalized file PATH with event timestamps within a
// small window (default ±2s; tools often differ by sub-second). Hashes are read from the
// structured fields first, then extracted from the description text as a fallback so a
// hash-bearing AI-extracted event still matches a structured THOR event.

import type { ForensicEvent, Severity } from "./stateTypes.js";

export interface CorrelateOptions {
  windowSeconds?: number; // path+time match tolerance (default 2)
  pidWindowSeconds?: number; // host+pid (process-creation) match tolerance (default 120)
}

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

const SHA256_RE = /\b[a-f0-9]{64}\b/i;
const MD5_RE = /\b[a-f0-9]{32}\b/i;
// Windows ("C:\…") or UNC ("\\host\…") or Unix ("/usr/…") paths. The Unix branch carries a
// negative lookbehind so it does NOT match a URL path (e.g. the "https://go.microsoft.com/fwlink"
// in a Windows Defender message): a "/seg/seg" preceded by a word char, "/", or ":" is part of a
// URL/host, not a filesystem path — matching it falsely correlated unrelated detections that merely
// shared a vendor URL in their text. (#102)
const PATH_RE = /(?:[A-Za-z]:\\|\\\\)[^\s"'|<>]+|(?<![\w/:])\/(?:[\w.\-]+\/)+[\w.\-]+/;

function eventHashes(e: ForensicEvent): string[] {
  const out = new Set<string>();
  if (e.sha256) out.add(e.sha256.toLowerCase());
  if (e.md5) out.add(e.md5.toLowerCase());
  // Fallback: pull a hash out of the description (e.g. an AI-extracted Velociraptor row).
  const s256 = SHA256_RE.exec(e.description); if (s256) out.add(s256[0].toLowerCase());
  // Only treat a bare 32-hex as MD5 if no sha256 present in the text (avoid matching part of a sha).
  if (!s256) { const m = MD5_RE.exec(e.description); if (m) out.add(m[0].toLowerCase()); }
  return [...out];
}

// A normalized file path for correlation, plus whether it came from a STRUCTURED field (`e.path`)
// or was scraped from the description. Free-text paths are weak — a process executable (e.g.
// powershell.exe) or a vendor URL recurs across unrelated detections — so they correlate ONLY
// against a structured path, never another free-text one (see the structured gate in step 2). (#102)
function eventPath(e: ForensicEvent): { path: string; structured: boolean } | undefined {
  if (e.path && e.path.trim()) return { path: e.path.trim().toLowerCase(), structured: true };
  const m = PATH_RE.exec(e.description)?.[0];
  return m ? { path: m.trim().toLowerCase(), structured: false } : undefined;
}

function epoch(ts: string): number | undefined {
  if (!ts) return undefined;
  const t = Date.parse(ts);
  return Number.isNaN(t) ? undefined : t;
}

// Union-find over event indices.
class DSU {
  private parent: number[];
  constructor(n: number) { this.parent = Array.from({ length: n }, (_, i) => i); }
  find(x: number): number { while (this.parent[x] !== x) { this.parent[x] = this.parent[this.parent[x]]; x = this.parent[x]; } return x; }
  union(a: number, b: number): void { const ra = this.find(a), rb = this.find(b); if (ra !== rb) this.parent[Math.max(ra, rb)] = Math.min(ra, rb); }
}

function worse(a: Severity, b: Severity): Severity {
  return SEV_RANK[a] <= SEV_RANK[b] ? a : b;
}

// Path+time correlation (step 2) exists for CROSS-tool corroboration — the same file reported by two
// tools. It must NOT collapse many distinct rows from ONE tool that merely share a container path
// (e.g. every PSReadline command shares the history-file OSPath; every registry hit shares a hive).
// So a path merge requires the two events to add corroboration: one carries a source the other lacks.
// Unknown-source events keep the old behavior (back-compat). Hash/exact-dup merges are unaffected.
function corroborates(a: ForensicEvent, b: ForensicEvent): boolean {
  const sa = (a.sources ?? []).filter((s) => s && s !== "unknown source");
  const sb = (b.sources ?? []).filter((s) => s && s !== "unknown source");
  if (!sa.length || !sb.length) return true;
  return sa.some((s) => !sb.includes(s)) || sb.some((s) => !sa.includes(s));
}

// A legacy "[corroborated by N sources: …]" suffix an earlier build appended to the
// description. Stripped so it (a) never pollutes the text and (b) doesn't change the
// dedup key — appending to the description used to break exact-duplicate re-matching.
const CORRO_NOTE = /\s*\[corroborated by \d+ sources?:[^\]]*\]\s*$/i;
export function cleanDescription(d: string): string {
  return d.replace(CORRO_NOTE, "").trim();
}

// Real source names only — drop empty and the legacy "unknown source" placeholder so a
// source-less event (e.g. from a build before sources existed) never counts as a tool.
function realSources(events: ForensicEvent[]): string[] {
  return [...new Set(events.flatMap((e) => e.sources ?? []).filter((s) => s && s !== "unknown source"))];
}

// Merge a group of events (≥1) into one canonical event. The lowest-index event's id is
// kept (stable); severity is the most severe; evidence/links/sources are unioned. The
// description is NOT mutated — corroboration is conveyed only via the `sources` field.
function mergeGroup(events: ForensicEvent[]): ForensicEvent {
  const primary = [...events].sort((a, b) =>
    (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || (b.description.length - a.description.length))[0];
  const uniq = <T,>(xs: T[]): T[] => [...new Set(xs)];
  const sources = realSources(events);
  const times = events.map((e) => e.timestamp).filter(Boolean).sort();
  const ends = events.map((e) => e.endTimestamp || e.timestamp).filter(Boolean).sort();

  const merged: ForensicEvent = {
    ...primary,
    description: cleanDescription(primary.description),
    severity: events.reduce<Severity>((acc, e) => worse(acc, e.severity), "Info"),
    timestamp: times[0] ?? primary.timestamp,
    mitreTechniques: uniq(events.flatMap((e) => e.mitreTechniques)),
    relatedFindingIds: uniq(events.flatMap((e) => e.relatedFindingIds)),
    sourceScreenshots: uniq(events.flatMap((e) => e.sourceScreenshots)),
    sources: sources.length ? sources : undefined,
    sha256: events.find((e) => e.sha256)?.sha256,
    md5: events.find((e) => e.md5)?.md5,
    path: primary.path ?? events.find((e) => e.path)?.path,
    asset: primary.asset ?? events.find((e) => e.asset)?.asset,
    processName: primary.processName ?? events.find((e) => e.processName)?.processName,
    parentName: primary.parentName ?? events.find((e) => e.parentName)?.parentName,
    pid: primary.pid ?? events.find((e) => e.pid !== undefined)?.pid,
    chainCheck: primary.chainCheck ?? events.find((e) => e.chainCheck)?.chainCheck,
    action: primary.action ?? events.find((e) => e.action)?.action,
    srcIp: primary.srcIp ?? events.find((e) => e.srcIp)?.srcIp,
    dstIp: primary.dstIp ?? events.find((e) => e.dstIp)?.dstIp,
    port: primary.port ?? events.find((e) => e.port !== undefined)?.port,
    deobfuscated: primary.deobfuscated ?? events.find((e) => e.deobfuscated)?.deobfuscated,
  };
  const lastEnd = ends[ends.length - 1];
  if (lastEnd && lastEnd !== merged.timestamp) merged.endTimestamp = lastEnd;
  return merged;
}

// Group events that describe the same artifact and merge each group into one event.
// Idempotent: re-running on already-merged events is a no-op (a merged event's keys
// only match itself). Preserves input order and ids for events that don't correlate,
// so callers/tests that don't rely on correlation see unchanged output.
export function correlateEvents(events: readonly ForensicEvent[], opts: CorrelateOptions = {}): ForensicEvent[] {
  const windowMs = (opts.windowSeconds ?? 2) * 1000;
  const n = events.length;
  // Always strip any legacy corroboration note from descriptions, even for a single
  // event, so old polluted state self-heals on the next merge/synthesis.
  if (n < 2) return events.map((e) => (CORRO_NOTE.test(e.description) ? { ...e, description: cleanDescription(e.description) } : e));
  const dsu = new DSU(n);

  // 0) EXACT duplicates → union. Same event time + same description is the same
  // observation — this collapses re-imports of the SAME file (and any event type that
  // lacks a hash/path), so importing a report twice never doubles the timeline.
  const byExact = new Map<string, number>();
  events.forEach((e, i) => {
    const k = `${e.timestamp} ${cleanDescription(e.description)}`;
    const prev = byExact.get(k);
    if (prev !== undefined) dsu.union(prev, i);
    else byExact.set(k, i);
  });

  // 1) Same hash → union. Events with different `action` values (e.g. a write and an
  //    execute of the same binary) are keyed separately so they remain distinct events —
  //    they are two causal steps, not duplicates — and file_lineage edges can be derived.
  //    Events without an action (the common case) all share the "" bucket and correlate
  //    as before, so this is fully backward-compatible.
  const byHash = new Map<string, number>(); // "hash:action" → first index with that pair
  events.forEach((e, i) => {
    // Process-CREATION events (those carrying a `pid`) are correlated by host+pid in step 3, NOT by
    // image hash: a process's hash identifies the BINARY, not the activity, and an interpreter's image
    // hash (powershell.exe / cmd.exe / rundll32.exe) is identical across EVERY invocation — so
    // hash-merging here collapsed all of a host's distinct PowerShell commands (e.g. a benign cmdlet,
    // `Compress-Archive` collection and `Invoke-RestMethod` exfil) into one row, destroying the kill
    // chain. Skipping pid-bearing events keeps distinct creations distinct; re-import dedup is still
    // covered by step 0 (exact time+description) and genuine cross-tool pairs by step 3.
    if (e.pid !== undefined) return;
    for (const h of eventHashes(e)) {
      const key = `${h}:${e.action ?? ""}`;
      const prev = byHash.get(key);
      if (prev !== undefined) dsu.union(prev, i);
      else byHash.set(key, i);
    }
  });

  // 2) Same normalized path with timestamps within the window → union — but only when at least one
  //    side carries the path as a STRUCTURED field. Two free-text path mentions are too weak (a
  //    shared process exe or vendor URL would falsely merge distinct same-tool detections, #102);
  //    a structured path matching a text path still corroborates (AI-extracted event ↔ import).
  const byPath = new Map<string, { i: number; structured: boolean }[]>();
  events.forEach((e, i) => {
    const p = eventPath(e);
    if (p) (byPath.get(p.path) ?? byPath.set(p.path, []).get(p.path)!).push({ i, structured: p.structured });
  });
  for (const entries of byPath.values()) {
    if (entries.length < 2) continue;
    const dated = entries.map((x) => ({ i: x.i, structured: x.structured, t: epoch(events[x.i].timestamp) }))
      .sort((a, b) => (a.t ?? Infinity) - (b.t ?? Infinity));
    for (let k = 1; k < dated.length; k++) {
      const a = dated[k - 1], b = dated[k];
      if (!a.structured && !b.structured) continue; // both free-text → too weak to merge
      if (!corroborates(events[a.i], events[b.i])) continue; // same tool sharing a container path → keep distinct
      // Undated events on the same path correlate too (no time to disprove); dated ones
      // must be within the window.
      if (a.t === undefined || b.t === undefined || Math.abs(b.t - a.t) <= windowMs) dsu.union(a.i, b.i);
    }
  }

  // 3) Same host + created-process PID within a window → union. Cross-tool corroboration for a process
  //    CREATION: the EDR (ECAR) and the Windows log (Security 4688 / Sysmon 1) both record the same
  //    creation with the same pid on the same host, but with different wording + no shared hash/path, so
  //    steps 0–2 miss it. pids recycle over time, so a window bounds the match; corroboration is required
  //    (one side carries a source the other lacks) so two creations from ONE tool that happen to reuse a
  //    pid never merge — only genuine cross-tool pairs do. Only process-creation events carry `pid`.
  const pidWindowMs = (opts.pidWindowSeconds ?? 120) * 1000;
  // Match on the SHORT hostname: an EDR reports `FILE-BO-01` while the Windows log records the FQDN
  // `FILE-BO-01.northstar-branch.local` for the same host — keying on the full string would never match.
  const shortHost = (asset: string): string => asset.split(".")[0].trim().toLowerCase();
  const byPid = new Map<string, number[]>();
  events.forEach((e, i) => {
    if (e.pid === undefined || !e.asset) return;
    const key = `${shortHost(e.asset)}|${e.pid}`;
    (byPid.get(key) ?? byPid.set(key, []).get(key)!).push(i);
  });
  for (const idxs of byPid.values()) {
    if (idxs.length < 2) continue;
    const dated = idxs.map((i) => ({ i, t: epoch(events[i].timestamp) }))
      .sort((a, b) => (a.t ?? Infinity) - (b.t ?? Infinity));
    for (let k = 1; k < dated.length; k++) {
      const a = dated[k - 1], b = dated[k];
      if (!corroborates(events[a.i], events[b.i])) continue;
      if (a.t === undefined || b.t === undefined || Math.abs(b.t - a.t) <= pidWindowMs) dsu.union(a.i, b.i);
    }
  }

  // Collect groups, preserving first-appearance order.
  const groups = new Map<number, number[]>();
  for (let i = 0; i < n; i++) {
    const r = dsu.find(i);
    (groups.get(r) ?? groups.set(r, []).get(r)!).push(i);
  }
  const out: ForensicEvent[] = [];
  const emitted = new Set<number>();
  for (let i = 0; i < n; i++) {
    const r = dsu.find(i);
    if (emitted.has(r)) continue;
    emitted.add(r);
    const members = groups.get(r)!;
    if (members.length > 1) {
      out.push(mergeGroup(members.map((m) => events[m])));
    } else {
      // Singleton: still strip any legacy corroboration note so old state self-heals.
      const e = events[members[0]];
      out.push(CORRO_NOTE.test(e.description) ? { ...e, description: cleanDescription(e.description) } : e);
    }
  }
  return out;
}
