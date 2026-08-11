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
import { trustForSources, type SourceTrustMap } from "./sourceTrust.js";
import { computeChainSignature } from "./chainSignature.js";

export interface CorrelateOptions {
  windowSeconds?: number; // path+time match tolerance (default 2)
  pidWindowSeconds?: number; // host+pid (process-creation) match tolerance (default 120)
  cmdlineWindowSeconds?: number; // host+command-line (process-creation) match tolerance (default 60, #68)
  // Per-source trust weights (#66): when a group merges events from several tools, the canonical
  // description is taken from the highest-TRUST contributor (tie-broken by the old length rule), so a
  // noisy raw-artifact row never wins the shown text over a CrowdStrike/THOR detection of the same fact.
  sourceTrust?: SourceTrustMap;
  // The time each event is COMPARED at, for the windowed steps below. Defaults to its recorded
  // timestamp. Clock-skew alignment (#228) passes skew-corrected times here so a host running seven
  // minutes fast still correlates against the rest of the fleet — without touching the events
  // themselves, so what gets merged and persisted still carries the recorded time.
  epochOf?: (e: ForensicEvent) => number | undefined;
  // Let the hash and path steps group an artifact ACROSS hosts (default false — see hostScopedGroups).
  // Only clock-skew detection (#228) wants this: its anchors are, by definition, one artifact stamped
  // by two different machines' clocks. Merging must never use it, or the lateral movement between
  // those machines is collapsed into a single event (#345).
  crossHostArtifacts?: boolean;
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
  const s256 = SHA256_RE.exec(e.description);
  if (s256) out.add(s256[0].toLowerCase());
  // Only treat a bare 32-hex as MD5 if no sha256 present in the text (avoid matching part of a sha).
  if (!s256) {
    const m = MD5_RE.exec(e.description);
    if (m) out.add(m[0].toLowerCase());
  }
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
  constructor(n: number) {
    this.parent = Array.from({ length: n }, (_, i) => i);
  }
  find(x: number): number {
    let i = x;
    while (this.parent[i] !== i) {
      this.parent[i] = this.parent[this.parent[i]];
      i = this.parent[i];
    }
    return i;
  }
  union(a: number, b: number): void {
    const ra = this.find(a),
      rb = this.find(b);
    if (ra !== rb) this.parent[Math.max(ra, rb)] = Math.min(ra, rb);
  }
}

function worse(a: Severity, b: Severity): Severity {
  return SEV_RANK[a] <= SEV_RANK[b] ? a : b;
}

// Match on the SHORT hostname: an EDR reports `FILE-BO-01` while the Windows log records the FQDN
// `FILE-BO-01.northstar-branch.local` for the same host — keying on the full string would never match.
// "" when the event has no recorded host.
function shortHost(asset: string | undefined): string {
  return (asset ?? "").split(".")[0].trim().toLowerCase();
}

// Split one artifact bucket (same hash, or same path) into the sets that may actually merge.
//
// A hash or a path identifies an ARTIFACT, not an event: the same binary dropped on two machines is
// two facts, and the gap between them IS the lateral movement. Merging across hosts collapsed that
// into one row — taking the timestamp from one host and the name from the other, and leaving the
// evidence graph a single asset where its lateral_move rule needs two (#345). Steps 3 and 4 already
// scope to a host (host+pid; host inside chainSignature); these two now do the same.
//
// Events with no recorded host are the exception. Attributing one to a host would be a guess, but
// refusing to merge them at all would re-duplicate the AI-extracted rows that today gain their asset
// from a structured sibling. So they group with each other, and join a real host only when the
// artifact was seen on EXACTLY ONE — where there is nothing to be ambiguous about.
function hostScopedGroups(indices: number[], evs: ForensicEvent[], crossHost: boolean): number[][] {
  if (crossHost) return [indices];
  const byHost = new Map<string, number[]>();
  for (const i of indices) {
    const key = shortHost(evs[i].asset);
    (byHost.get(key) ?? byHost.set(key, []).get(key)!).push(i);
  }
  const unknown = byHost.get("") ?? [];
  byHost.delete("");
  const groups = [...byHost.values()];
  if (groups.length === 1) {
    groups[0].push(...unknown);
    return groups;
  } // unambiguous → attach
  if (unknown.length) groups.push(unknown);
  return groups;
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
function mergeGroup(events: ForensicEvent[], trustMap?: SourceTrustMap): ForensicEvent {
  // Primary (its description is the canonical shown text): most SEVERE first — a Critical detection's
  // wording must win over an Info row of the same fact — then highest TRUST (#66: prefer the reliable
  // tool's phrasing over a noisy artifact row), then the longest description as the final tie-break.
  const primary = [...events].sort(
    (a, b) =>
      SEV_RANK[a.severity] - SEV_RANK[b.severity] ||
      trustForSources(b.sources, trustMap) - trustForSources(a.sources, trustMap) ||
      b.description.length - a.description.length,
  )[0];
  const uniq = <T>(xs: T[]): T[] => [...new Set(xs)];
  const sources = realSources(events);
  const times = events
    .map((e) => e.timestamp)
    .filter(Boolean)
    .sort();
  const ends = events
    .map((e) => e.endTimestamp || e.timestamp)
    .filter(Boolean)
    .sort();

  const merged: ForensicEvent = {
    ...primary,
    description: cleanDescription(primary.description),
    severity: events.reduce<Severity>((acc, e) => worse(acc, e.severity), "Info"),
    timestamp: times[0] ?? primary.timestamp,
    mitreTechniques: uniq(events.flatMap((e) => e.mitreTechniques)),
    relatedFindingIds: uniq(events.flatMap((e) => e.relatedFindingIds)),
    sourceScreenshots: uniq(events.flatMap((e) => e.sourceScreenshots)),
    sources: sources.length ? sources : undefined,
    // artifactName, unlike the fields below, is an ATTRIBUTION of the shown description (which artifact
    // produced this text) — not a neutral shared fact about the underlying process/host/connection — so
    // it must come from the SAME event as `description` (primary), never borrowed from a different
    // contributor. A same-tool duplicate merge that splits artifactName across near-identical rows
    // legitimately loses it here (falls back to that source's own sources[0] in the UI); the alternative
    // — a genuinely cross-tool correlation (e.g. a Chainsaw/Sigma detection + a Velociraptor Pstree
    // record sharing host+pid) — otherwise showed the WRONG artifact next to the detection's own text.
    artifactName: primary.artifactName,
    message: primary.message ?? events.find((e) => e.message)?.message,
    veloUrl: primary.veloUrl ?? events.find((e) => e.veloUrl)?.veloUrl,
    sha256: events.find((e) => e.sha256)?.sha256,
    md5: events.find((e) => e.md5)?.md5,
    path: primary.path ?? events.find((e) => e.path)?.path,
    asset: primary.asset ?? events.find((e) => e.asset)?.asset,
    processName: primary.processName ?? events.find((e) => e.processName)?.processName,
    parentName: primary.parentName ?? events.find((e) => e.parentName)?.parentName,
    pid: primary.pid ?? events.find((e) => e.pid !== undefined)?.pid,
    commandLine: primary.commandLine ?? events.find((e) => e.commandLine)?.commandLine,
    chainSignature: primary.chainSignature ?? events.find((e) => e.chainSignature)?.chainSignature,
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
// Stamp a chainSignature onto a process-creation event (#68) when it lacks one, so the field is
// populated even for importers that don't set it and old state self-heals. Idempotent: an event that
// already carries a signature (or isn't a process creation) is returned unchanged.
function withSignature(e: ForensicEvent): ForensicEvent {
  if (e.pid === undefined || e.chainSignature) return e;
  const sig = computeChainSignature(e);
  return sig ? { ...e, chainSignature: sig } : e;
}

// The grouping half of correlateEvents: decide WHICH events describe the same real-world artifact,
// without merging them. Returns the signature-stamped working copy plus each group's member indices
// in first-appearance order (singletons included). Split out so clock-skew detection (#228) can read
// the groups BEFORE mergeGroup collapses them — a group whose members were recorded by different
// tools is exactly the "same event, two clocks" anchor the skew detector needs, and after the merge
// only one timestamp survives. correlateEvents is the sole other caller; the two must stay in step.
function groupEvents(
  events: readonly ForensicEvent[],
  opts: CorrelateOptions,
): { evs: ForensicEvent[]; groups: number[][] } {
  const windowMs = (opts.windowSeconds ?? 2) * 1000;
  const timeOf = opts.epochOf ?? ((e: ForensicEvent) => epoch(e.timestamp));
  const crossHostArtifacts = opts.crossHostArtifacts === true;
  const n = events.length;
  // Work over a copy with chainSignature populated so step 4 can key on it and every emitted
  // process-creation event carries the field (satisfying the importer-agnostic path).
  const evs = events.map(withSignature);
  const dsu = new DSU(n);

  // 0) EXACT duplicates → union. Same event time + same description ON THE SAME HOST is the same
  // observation — this collapses re-imports of the SAME file (and any event type that
  // lacks a hash/path), so importing a report twice never doubles the timeline.
  //
  // The host is part of the key (#345): a fleet-wide sweep reports identical text at the identical
  // second for every machine it hits, and those are as many findings as there are machines, not one.
  // A re-import always carries the same asset, so dedup is unaffected. Unlike the artifact steps
  // below this is never relaxed by crossHostArtifacts — two hosts' rows are not one observation, no
  // matter who is asking.
  const byExact = new Map<string, number>();
  evs.forEach((e, i) => {
    const k = `${e.timestamp} ${cleanDescription(e.description)} ${shortHost(e.asset)}`;
    const prev = byExact.get(k);
    if (prev !== undefined) dsu.union(prev, i);
    else byExact.set(k, i);
  });

  // 1) Same hash → union. Events with different `action` values (e.g. a write and an
  //    execute of the same binary) are keyed separately so they remain distinct events —
  //    they are two causal steps, not duplicates — and file_lineage edges can be derived.
  //    Events without an action (the common case) all share the "" bucket and correlate
  //    as before, so this is fully backward-compatible.
  const byHash = new Map<string, number[]>(); // "hash:action" → every index with that pair
  evs.forEach((e, i) => {
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
      (byHash.get(key) ?? byHash.set(key, []).get(key)!).push(i);
    }
  });
  for (const idxs of byHash.values()) {
    if (idxs.length < 2) continue;
    for (const group of hostScopedGroups(idxs, evs, crossHostArtifacts)) {
      for (let k = 1; k < group.length; k++) dsu.union(group[0], group[k]);
    }
  }

  // 2) Same normalized path with timestamps within the window → union — but only when at least one
  //    side carries the path as a STRUCTURED field. Two free-text path mentions are too weak (a
  //    shared process exe or vendor URL would falsely merge distinct same-tool detections, #102);
  //    a structured path matching a text path still corroborates (AI-extracted event ↔ import).
  const byPath = new Map<string, { i: number; structured: boolean }[]>();
  evs.forEach((e, i) => {
    const p = eventPath(e);
    if (p) (byPath.get(p.path) ?? byPath.set(p.path, []).get(p.path)!).push({ i, structured: p.structured });
  });
  for (const entries of byPath.values()) {
    if (entries.length < 2) continue;
    const structuredBy = new Map(entries.map((x) => [x.i, x.structured]));
    // Same path on two machines is two files, not one (#345) — so pair within a host, exactly like
    // the hash step above.
    for (const group of hostScopedGroups(
      entries.map((x) => x.i),
      evs,
      crossHostArtifacts,
    )) {
      if (group.length < 2) continue;
      const dated = group
        .map((i) => ({ i, structured: structuredBy.get(i) === true, t: timeOf(evs[i]) }))
        .sort((a, b) => (a.t ?? Infinity) - (b.t ?? Infinity));
      for (let k = 1; k < dated.length; k++) {
        const a = dated[k - 1],
          b = dated[k];
        if (!a.structured && !b.structured) continue; // both free-text → too weak to merge
        if (!corroborates(evs[a.i], evs[b.i])) continue; // same tool sharing a container path → keep distinct
        // Undated events on the same path correlate too (no time to disprove); dated ones
        // must be within the window.
        if (a.t === undefined || b.t === undefined || Math.abs(b.t - a.t) <= windowMs) dsu.union(a.i, b.i);
      }
    }
  }

  // 3) Same host + created-process PID within a window → union. Cross-tool corroboration for a process
  //    CREATION: the EDR (ECAR) and the Windows log (Security 4688 / Sysmon 1) both record the same
  //    creation with the same pid on the same host, but with different wording + no shared hash/path, so
  //    steps 0–2 miss it. pids recycle over time, so a window bounds the match; corroboration is required
  //    (one side carries a source the other lacks) so two creations from ONE tool that happen to reuse a
  //    pid never merge — only genuine cross-tool pairs do. Only process-creation events carry `pid`.
  const pidWindowMs = (opts.pidWindowSeconds ?? 120) * 1000;
  const byPid = new Map<string, number[]>();
  evs.forEach((e, i) => {
    if (e.pid === undefined || !e.asset) return;
    const key = `${shortHost(e.asset)}|${e.pid}`;
    (byPid.get(key) ?? byPid.set(key, []).get(key)!).push(i);
  });
  for (const idxs of byPid.values()) {
    if (idxs.length < 2) continue;
    const dated = idxs
      .map((i) => ({ i, t: timeOf(evs[i]) }))
      .sort((a, b) => (a.t ?? Infinity) - (b.t ?? Infinity));
    for (let k = 1; k < dated.length; k++) {
      const a = dated[k - 1],
        b = dated[k];
      if (!corroborates(evs[a.i], evs[b.i])) continue;
      if (a.t === undefined || b.t === undefined || Math.abs(b.t - a.t) <= pidWindowMs) dsu.union(a.i, b.i);
    }
  }

  // 4) Same host + normalized COMMAND LINE within a window → union. Cross-tool corroboration for a
  //    process CREATION that steps 0–3 miss: Sysmon and the EDR both record the same command but with
  //    different wording, no shared file hash, and DIFFERENT pids (each tool assigns its own view of the
  //    creation), so the host+pid step can't link them. The command line + parent + host does. Keyed on
  //    the time-independent `chainSignature`; corroboration is required (one side carries a source the
  //    other lacks) so two DISTINCT commands from ONE tool never merge — only genuine cross-tool pairs
  //    do — and a genuine re-run of the same command later is kept apart by the window. (#68)
  const cmdWindowMs = (opts.cmdlineWindowSeconds ?? 60) * 1000;
  const bySig = new Map<string, number[]>();
  evs.forEach((e, i) => {
    if (e.pid === undefined || !e.chainSignature) return;
    (bySig.get(e.chainSignature) ?? bySig.set(e.chainSignature, []).get(e.chainSignature)!).push(i);
  });
  for (const idxs of bySig.values()) {
    if (idxs.length < 2) continue;
    const dated = idxs
      .map((i) => ({ i, t: timeOf(evs[i]) }))
      .sort((a, b) => (a.t ?? Infinity) - (b.t ?? Infinity));
    for (let k = 1; k < dated.length; k++) {
      const a = dated[k - 1],
        b = dated[k];
      if (!corroborates(evs[a.i], evs[b.i])) continue;
      if (a.t === undefined || b.t === undefined || Math.abs(b.t - a.t) <= cmdWindowMs) dsu.union(a.i, b.i);
    }
  }

  // Collect groups, preserving first-appearance order.
  const byRoot = new Map<number, number[]>();
  for (let i = 0; i < n; i++) {
    const r = dsu.find(i);
    (byRoot.get(r) ?? byRoot.set(r, []).get(r)!).push(i);
  }
  const groups: number[][] = [];
  const emitted = new Set<number>();
  for (let i = 0; i < n; i++) {
    const r = dsu.find(i);
    if (emitted.has(r)) continue;
    emitted.add(r);
    groups.push(byRoot.get(r)!);
  }
  return { evs, groups };
}

// Groups of events that describe the SAME real-world artifact, un-merged, in first-appearance order.
// Singleton groups are included so a caller can tell "seen once" from "not seen". The events carry a
// populated chainSignature (as correlateEvents emits them) but are otherwise untouched. Used by
// clock-skew detection (#228) — see groupEvents above for why the pre-merge view matters.
export function correlationGroups(
  events: readonly ForensicEvent[],
  opts: CorrelateOptions = {},
): ForensicEvent[][] {
  if (events.length === 0) return [];
  if (events.length < 2) return [[withSignature(events[0])]];
  const { evs, groups } = groupEvents(events, opts);
  return groups.map((members) => members.map((m) => evs[m]));
}

export function correlateEvents(
  events: readonly ForensicEvent[],
  opts: CorrelateOptions = {},
): ForensicEvent[] {
  // Always strip any legacy corroboration note from descriptions, even for a single
  // event, so old polluted state self-heals on the next merge/synthesis.
  if (events.length < 2)
    return events.map((e) =>
      withSignature(
        CORRO_NOTE.test(e.description) ? { ...e, description: cleanDescription(e.description) } : e,
      ),
    );
  const { evs, groups } = groupEvents(events, opts);
  const out: ForensicEvent[] = [];
  for (const members of groups) {
    if (members.length > 1) {
      out.push(
        mergeGroup(
          members.map((m) => evs[m]),
          opts.sourceTrust,
        ),
      );
    } else {
      // Singleton: still strip any legacy corroboration note so old state self-heals.
      const e = evs[members[0]];
      out.push(CORRO_NOTE.test(e.description) ? { ...e, description: cleanDescription(e.description) } : e);
    }
  }
  return out;
}
