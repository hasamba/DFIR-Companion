import type { ForensicEvent } from "./stateTypes.js";
import { correlationGroups, shortHost, type CorrelateOptions } from "./correlate.js";

// Clock-skew detection & cross-host timeline alignment (#228).
//
// Hosts in a fleet rarely share a synchronised clock: NTP drift, a misconfigured timezone, or a
// tampered log source places an event minutes or hours off its true time, which breaks every
// cross-host correlation window and the lateral-movement edges derived from them.
//
// ANCHORS. The detector needs records that describe ONE real-world event but were stamped by
// DIFFERENT clocks — e.g. a logon written both by the endpoint and by the DC. Those are exactly
// what correlate.ts already finds, so anchors are read from `correlationGroups` rather than
// re-derived here. This matters practically: correlateEvents MERGES each group down to a single
// event keeping the earliest timestamp, so once a timeline has been correlated the evidence of skew
// is gone. Detection therefore runs on the PRE-merge timeline (see pipeline.synthesize).
//
// SKEW vs PROPAGATION. The same artifact appearing on two hosts is ambiguous: a 30s gap can be a
// 30s clock offset, or a file that genuinely took 30s to travel from A to B. Nothing in a single
// anchor separates them. What separates them is CONSISTENCY across anchors: a wrong clock is
// systematically wrong by the same amount, while propagation delays vary. So an offset is only
// reported as measured once it is backed by `minAnchors` samples whose dispersion (median absolute
// deviation) stays under `maxDispersionMs`. A host whose samples scatter is reported as
// low-confidence and never aligned — the timeline is left alone rather than "corrected" into a
// fiction.
//
// Pure, deterministic, NO AI call.

// A host is FLAGGED to the analyst above this offset (#228: "highlight hosts with skew > threshold,
// default 60s"). This is an alerting threshold, NOT a matching window: anchors are accepted at any
// spread up to DEFAULT_MAX_ANCHOR_SPREAD_MS, otherwise the detector could never see the multi-hour
// timezone offsets that are the worst case it exists to catch.
export const DEFAULT_SKEW_ALERT_MS = 60_000;
// Samples required before an offset is reported as measured rather than coincidental.
export const DEFAULT_MIN_ANCHORS = 3;
// Ceiling on the samples' median absolute deviation — the skew-vs-propagation discriminator above.
export const DEFAULT_MAX_DISPERSION_MS = 5_000;
// Sanity cap on one anchor group's spread. It exists to keep an absurd pairing out of the samples,
// NOT to bound how wrong a clock may be: a VM restored from an old snapshot, or one whose RTC never
// got set, is wrong by MONTHS, and the 48-hour cap this used to carry made that case undetectable by
// construction (#740 — case INC-2026-020 ran ~268 days out and produced no signal at all). Nothing is
// lost by widening it, because the spread was never the discriminator: a group only becomes a
// measured offset once `minAnchors` independent groups agree to within `maxDispersionMs`, and an
// artifact genuinely re-used weeks apart cannot reproduce the same offset to the second three times
// over. A year is the practical ceiling for "these two records describe one real-world event".
export const DEFAULT_MAX_ANCHOR_SPREAD_MS = 400 * 24 * 3_600_000;
// Ceiling on an offset alignment will apply BY ITSELF. Widening the anchor cap above is what lets a
// months-wrong clock be SEEN; it must not also make it silently applied. Consistency alone cannot
// separate a year-scale clock error from a legitimate one: a batch of files deployed to a fleet and
// re-observed by a second tool months later yields one anchor group per file, and those propagation
// intervals can agree well inside `maxDispersionMs` — which would qualify a fictional multi-month
// offset and, with alignment on, shift a whole host's timeline by months. So a large offset is
// measured, reported and flagged, but never auto-applied: the analyst confirms it with an explicit
// per-host override, which effectiveOffsets already honours above any detection. 48 hours is the
// value the anchor cap itself used to carry — beyond two days a clock error stops being routine
// drift or a timezone mistake and becomes a claim worth a human signing off on.
export const DEFAULT_MAX_AUTO_ALIGN_MS = 48 * 3_600_000;
// Standalone timestamp-gap warning (#740), independent of anchors and of any correction. A host
// whose own events split into two clusters this far apart has almost certainly logged part of its
// evidence under a wrong clock — worth saying out loud even when no anchor exists to measure it.
export const DEFAULT_MIN_TIME_GAP_MS = 30 * 24 * 3_600_000;
// Dated events a host needs before its distribution is worth splitting.
export const DEFAULT_GAP_MIN_EVENTS = 12;
// The far cluster must be a MINORITY this small. A host whose evidence genuinely spans years (an MFT
// or registry collection always does) splits near the middle, and that is normal, not skew.
export const DEFAULT_MAX_GAP_MINORITY_FRACTION = 0.25;

export interface ClockSkewOptions extends CorrelateOptions {
  alertThresholdMs?: number;
  minAnchors?: number;
  maxDispersionMs?: number;
  maxAnchorSpreadMs?: number;
  maxAutoAlignMs?: number;
}

export interface TimeGapOptions {
  minGapMs?: number; // cluster separation worth warning about. Default 30 days.
  minEvents?: number; // dated events a host needs before it is examined. Default 12.
  maxMinorityFraction?: number; // how small the far cluster must be. Default 0.25.
}

export type SkewConfidence = "high" | "medium" | "low";

export interface ClockSkewResult {
  host: string; // display name (the first spelling seen, e.g. the FQDN)
  hostKey: string; // normalized short hostname the offset is keyed on
  offsetMs: number; // host clock − consensus. Positive ⇒ this host runs FAST.
  anchorCount: number; // samples behind the offset
  dispersionMs: number; // median absolute deviation of those samples
  confidence: SkewConfidence;
  qualified: boolean; // enough consistent samples to trust the measurement
  // Whether alignment may apply this offset on its own: qualified AND within `maxAutoAlignMs`. A
  // qualified-but-large offset is real enough to show and to warn about, and too consequential to
  // act on unasked — the analyst turns it on with a per-host override. See DEFAULT_MAX_AUTO_ALIGN_MS.
  alignable: boolean;
  skewed: boolean; // qualified AND beyond the alert threshold
  sources: string[]; // tools that contributed anchors, for auditability
}

/**
 * One host whose own dated events split into two clusters far apart in time (#740).
 *
 * This is a WARNING, never a correction. Unlike a measured offset it needs no cross-host anchor, so
 * it still fires on the case that has one evidence source and no correlation groups at all — which
 * is exactly the case where a wrong VM clock otherwise passes through the whole pipeline in silence.
 */
export interface HostTimeGap {
  host: string; // display name (the first spelling seen)
  hostKey: string; // normalized short hostname
  gapMs: number; // distance between the two clusters
  minorityCount: number; // events in the smaller (suspect) cluster
  totalCount: number; // this host's dated events
  minorityStart: string; // ISO bounds of the smaller cluster
  minorityEnd: string;
  majorityStart: string; // ISO bounds of the bulk
  majorityEnd: string;
  minoritySide: "before" | "after"; // where the suspect cluster sits relative to the bulk
  sources: string[]; // tools that reported the suspect cluster, for auditability
}

export interface ClockSkewReport {
  results: ClockSkewResult[];
  // Hosts whose timestamps split across a large gap. Present only when the caller measured them —
  // detectClockSkew reads correlation GROUPS and cannot see a host's full distribution, so the
  // gaps are computed from the timeline by detectHostTimeGaps and merged in by the caller.
  timeGaps?: HostTimeGap[];
  // The clock every offset is expressed against — the best-anchored host, whose own offset is 0 by
  // construction. "" when nothing was measured.
  referenceHost: string;
  anchorGroups: number; // correlation groups that qualified as anchors
  groupsExamined: number;
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? Math.round((sorted[mid - 1] + sorted[mid]) / 2) : sorted[mid];
}

// Median absolute deviation — a spread measure a single wild sample cannot inflate the way a
// standard deviation can. 0 for a perfectly consistent host.
function mad(values: number[], center: number): number {
  if (values.length === 0) return 0;
  return median(values.map((v) => Math.abs(v - center)));
}

// Match correlate.ts's host keying: an EDR reports `FILE-BO-01` while the Windows log records
// `FILE-BO-01.corp.local` for the same machine, and both must land on one offset. It DELEGATES
// rather than restating the rule — the two drifted apart on IP-literal assets, where truncating at
// the first dot folded every address on a /8 onto the key "10" and reported one machine's clock
// under another machine's name.
export function hostKey(asset: string): string {
  return shortHost(asset);
}

function epoch(ts: string | undefined): number | undefined {
  if (!ts) return undefined;
  const t = Date.parse(ts);
  return Number.isNaN(t) ? undefined : t;
}

interface Sample {
  offsetMs: number;
  sources: string[];
}

/**
 * Per-host clock offsets measured from pre-merge correlation groups.
 *
 * Each qualifying group contributes ONE sample per host (the median of that host's records in the
 * group), so a host that logged an artifact five times cannot outvote a host that logged it once —
 * and the group's consensus reference is the median across hosts, not across records.
 */
export function detectClockSkew(
  groups: readonly ForensicEvent[][],
  opts: ClockSkewOptions = {},
): ClockSkewReport {
  const minAnchors = opts.minAnchors ?? DEFAULT_MIN_ANCHORS;
  const maxDispersionMs = opts.maxDispersionMs ?? DEFAULT_MAX_DISPERSION_MS;
  const maxSpreadMs = opts.maxAnchorSpreadMs ?? DEFAULT_MAX_ANCHOR_SPREAD_MS;
  const alertMs = opts.alertThresholdMs ?? DEFAULT_SKEW_ALERT_MS;
  const maxAutoAlignMs = opts.maxAutoAlignMs ?? DEFAULT_MAX_AUTO_ALIGN_MS;

  const samplesByHost = new Map<string, Sample[]>();
  const displayName = new Map<string, string>();
  let anchorGroups = 0;

  for (const group of groups) {
    if (group.length < 2) continue;

    // One representative time per host, plus the tools that recorded it.
    const timesByHost = new Map<string, number[]>();
    const sourcesByHost = new Map<string, Set<string>>();
    for (const e of group) {
      if (!e.asset) continue;
      const t = epoch(e.timestamp);
      if (t === undefined) continue;
      const key = hostKey(e.asset);
      if (!key) continue;
      if (!displayName.has(key)) displayName.set(key, e.asset);
      (timesByHost.get(key) ?? timesByHost.set(key, []).get(key)!).push(t);
      const srcs = sourcesByHost.get(key) ?? sourcesByHost.set(key, new Set()).get(key)!;
      for (const s of e.sources ?? []) if (s && s !== "unknown source") srcs.add(s);
    }
    if (timesByHost.size < 2) continue; // single host in the group ⇒ nothing to compare against

    // The group must carry more than one tool's word for it. A single tool reporting the same
    // artifact on two hosts is the propagation case with no second clock in evidence; two tools
    // give genuinely independent stamps of the same fact.
    const allSources = new Set<string>();
    for (const srcs of sourcesByHost.values()) for (const s of srcs) allSources.add(s);
    if (allSources.size < 2) continue;

    const reps = new Map<string, number>();
    for (const [key, times] of timesByHost) reps.set(key, median(times));
    const repTimes = [...reps.values()];
    if (Math.max(...repTimes) - Math.min(...repTimes) > maxSpreadMs) continue;

    const reference = median(repTimes);
    anchorGroups++;
    for (const [key, rep] of reps) {
      const arr = samplesByHost.get(key) ?? samplesByHost.set(key, []).get(key)!;
      arr.push({ offsetMs: rep - reference, sources: [...(sourcesByHost.get(key) ?? [])] });
    }
  }

  const results: ClockSkewResult[] = [];
  for (const [key, samples] of samplesByHost) {
    const offsets = samples.map((s) => s.offsetMs);
    const offsetMs = median(offsets);
    const dispersionMs = mad(offsets, offsetMs);
    const anchorCount = samples.length;
    const qualified = anchorCount >= minAnchors && dispersionMs <= maxDispersionMs;
    const confidence: SkewConfidence =
      anchorCount >= 5 && dispersionMs <= 1_000 ? "high" : qualified ? "medium" : "low";
    results.push({
      host: displayName.get(key) ?? key,
      hostKey: key,
      offsetMs,
      anchorCount,
      dispersionMs,
      confidence,
      qualified,
      alignable: false, // decided after re-centering below, like `skewed`
      skewed: false, // decided after re-centering below
      sources: [...new Set(samples.flatMap((s) => s.sources))].sort(),
    });
  }

  // Only RELATIVE offsets are measurable — no evidence in a case says which clock is right. Rather
  // than leave every host floating around a consensus midpoint (which moves everybody, including
  // whichever clock is actually correct), express offsets against a reference clock, as #228 asks:
  // "median offset (host_time − reference_time) per host". The reference is the best-anchored host
  // — usually the central log source that observed the rest of the fleet — so alignment shifts the
  // fewest events and the analyst can read the timeline as "on DC01's clock".
  const reference = [...results]
    .filter((r) => r.qualified)
    .sort(
      (a, b) =>
        b.anchorCount - a.anchorCount ||
        b.sources.length - a.sources.length ||
        a.hostKey.localeCompare(b.hostKey),
    )[0];
  if (reference) {
    const base = reference.offsetMs;
    for (const r of results) r.offsetMs -= base;
  }
  for (const r of results) {
    r.skewed = r.qualified && Math.abs(r.offsetMs) > alertMs;
    r.alignable = r.qualified && Math.abs(r.offsetMs) <= maxAutoAlignMs;
  }

  results.sort((a, b) => a.hostKey.localeCompare(b.hostKey));
  return { results, referenceHost: reference?.host ?? "", anchorGroups, groupsExamined: groups.length };
}

/**
 * Convenience wrapper that derives the correlation groups itself. Correct for a RAW (un-correlated)
 * timeline; on an already-correlated one it finds few anchors, because the merge that produced it
 * kept one timestamp per group. Callers holding the pre-merge events should prefer
 * `detectClockSkew(correlationGroups(events, { ...opts, crossHostArtifacts: true }), opts)` — the flag is
 * required: without it correlate scopes each artifact to one host (#345) and no anchor ever spans two.
 */
export function detectClockSkewFromTimeline(
  events: readonly ForensicEvent[],
  opts: ClockSkewOptions = {},
): ClockSkewReport {
  return detectClockSkew(correlationGroups(events, { ...opts, crossHostArtifacts: true }), opts);
}

/**
 * Hosts whose own dated events split into two clusters far apart in time (#740).
 *
 * WHY THIS EXISTS SEPARATELY FROM detectClockSkew. An offset can only be MEASURED where two clocks
 * stamped one real-world event, and a case can easily have no such pair — one evidence source, or a
 * host nothing else observed. Case INC-2026-020 was exactly that: a lab VM ~268 days out, zero anchor
 * groups, and therefore not one word of warning anywhere in the pipeline. This detector needs no
 * second clock. It reads one host's own distribution and asks whether part of it sits implausibly far
 * from the rest.
 *
 * It NEVER corrects anything, and it is deliberately quiet. A forensic timeline legitimately spans
 * years (an MFT or a registry hive always does), so a warning needs BOTH a wide gap AND a far side
 * small enough to be an anomaly rather than half the evidence. Pure and deterministic.
 */
export function detectHostTimeGaps(
  events: readonly ForensicEvent[],
  opts: TimeGapOptions = {},
): HostTimeGap[] {
  const minGapMs = opts.minGapMs ?? DEFAULT_MIN_TIME_GAP_MS;
  const minEvents = opts.minEvents ?? DEFAULT_GAP_MIN_EVENTS;
  const maxMinorityFraction = opts.maxMinorityFraction ?? DEFAULT_MAX_GAP_MINORITY_FRACTION;

  interface Row {
    t: number;
    sources: string[];
  }
  const byHost = new Map<string, Row[]>();
  const displayName = new Map<string, string>();
  for (const e of events) {
    if (!e.asset) continue;
    const t = epoch(e.timestamp);
    if (t === undefined) continue;
    const key = hostKey(e.asset);
    if (!key) continue;
    if (!displayName.has(key)) displayName.set(key, e.asset);
    (byHost.get(key) ?? byHost.set(key, []).get(key)!).push({
      t,
      sources: (e.sources ?? []).filter((sc) => sc && sc !== "unknown source"),
    });
  }

  const out: HostTimeGap[] = [];
  for (const [key, rowsRaw] of byHost) {
    if (rowsRaw.length < minEvents) continue;
    const rows = [...rowsRaw].sort((a, b) => a.t - b.t);

    // Split at the host's WIDEST adjacent gap. One cut is enough: a clock that is wrong is wrong for
    // a contiguous stretch of the collection, so the suspect events land on one side of one seam.
    let cut = -1;
    let gapMs = 0;
    for (let i = 1; i < rows.length; i++) {
      const g = rows[i].t - rows[i - 1].t;
      if (g > gapMs) {
        gapMs = g;
        cut = i;
      }
    }
    if (cut < 0 || gapMs < minGapMs) continue;

    const before = rows.slice(0, cut);
    const after = rows.slice(cut);
    const minoritySide: "before" | "after" = before.length <= after.length ? "before" : "after";
    const minority = minoritySide === "before" ? before : after;
    const majority = minoritySide === "before" ? after : before;
    if (minority.length / rows.length > maxMinorityFraction) continue; // an evenly split host is normal

    const iso = (ms: number): string => new Date(ms).toISOString();
    out.push({
      host: displayName.get(key) ?? key,
      hostKey: key,
      gapMs,
      minorityCount: minority.length,
      totalCount: rows.length,
      minorityStart: iso(minority[0].t),
      minorityEnd: iso(minority[minority.length - 1].t),
      majorityStart: iso(majority[0].t),
      majorityEnd: iso(majority[majority.length - 1].t),
      minoritySide,
      sources: [...new Set(minority.flatMap((r) => r.sources))].sort(),
    });
  }
  // Widest gap first — the most likely wrong clock is the one the analyst should read first.
  out.sort((a, b) => b.gapMs - a.gapMs || a.hostKey.localeCompare(b.hostKey));
  return out;
}

/**
 * The offsets alignment should actually apply: analyst overrides first (a deliberate statement about
 * a host's clock), then detected offsets that cleared the confidence bar AND are small enough to
 * apply unattended. Keyed by normalized short hostname.
 */
export function effectiveOffsets(
  results: readonly ClockSkewResult[],
  overrides: Readonly<Record<string, number>> = {},
): Map<string, number> {
  const out = new Map<string, number>();
  // `alignable`, not `qualified`: a measurement can be sound and still too large to apply without a
  // human saying so (DEFAULT_MAX_AUTO_ALIGN_MS). The override loop below is how they say so.
  for (const r of results) if (r.alignable && r.offsetMs !== 0) out.set(r.hostKey, r.offsetMs);
  for (const [host, offset] of Object.entries(overrides)) {
    const key = hostKey(host);
    if (!key || !Number.isFinite(offset)) continue;
    if (offset === 0)
      out.delete(key); // an explicit 0 override means "this clock is correct"
    else out.set(key, offset);
  }
  return out;
}

/**
 * Project events onto a common time axis. This is a VIEW, never a rewrite: each shifted event keeps
 * its recorded time in `originalTimestamp` and the applied correction in `skewOffsetMs`, so the UI
 * and the report can show both and the stored case file is never touched. Output is re-sorted,
 * because shifting one host's events changes their order relative to every other host's.
 */
export function alignTimestamps(
  events: readonly ForensicEvent[],
  offsets: ReadonlyMap<string, number>,
): ForensicEvent[] {
  if (offsets.size === 0) return [...events];
  const shifted = events.map((e) => {
    const offset = e.asset ? offsets.get(hostKey(e.asset)) : undefined;
    if (!offset) return e;
    const ts = epoch(e.timestamp);
    if (ts === undefined) return e;
    const out: ForensicEvent = {
      ...e,
      timestamp: new Date(ts - offset).toISOString(),
      originalTimestamp: e.timestamp,
      skewOffsetMs: offset,
    };
    const end = epoch(e.endTimestamp);
    if (end !== undefined) out.endTimestamp = new Date(end - offset).toISOString();
    return out;
  });
  // Undated events sort to the end rather than to the epoch.
  return shifted.sort((a, b) => (epoch(a.timestamp) ?? Infinity) - (epoch(b.timestamp) ?? Infinity));
}

/**
 * The time an event should be COMPARED at once its host's clock is corrected. Feeds
 * `CorrelateOptions.epochOf` so cross-host correlation windows account for skew (#228 item 4)
 * without rewriting the events that get merged and persisted.
 */
export function alignedEpoch(e: ForensicEvent, offsets: ReadonlyMap<string, number>): number | undefined {
  const t = epoch(e.timestamp);
  if (t === undefined) return undefined;
  const offset = e.asset ? offsets.get(hostKey(e.asset)) : undefined;
  return offset ? t - offset : t;
}

/** The persisted state a projection needs — structurally satisfied by ClockSkewRecord. */
export interface AlignmentState {
  alignEnabled: boolean;
  results: readonly ClockSkewResult[];
  overrides: Readonly<Record<string, number>>;
}

/**
 * Apply the case's stored alignment decision to a timeline. The single entry point every READ path
 * uses (the state route, the report writer, and through it the evidence graph and lateral paths), so
 * "align timelines" means one thing everywhere. A no-op when the toggle is off or no host qualifies.
 */
export function projectAlignment(
  state: AlignmentState | undefined,
  events: readonly ForensicEvent[],
): ForensicEvent[] {
  if (!state?.alignEnabled) return [...events];
  return alignTimestamps(events, effectiveOffsets(state.results, state.overrides));
}

/**
 * Drop the projection fields, restoring each event's recorded time. Used before anything derived
 * from aligned events is PERSISTED, so alignment can never bake itself into the case file.
 */
export function stripAlignment(events: readonly ForensicEvent[]): ForensicEvent[] {
  return events.map((e) => {
    if (e.originalTimestamp === undefined && e.skewOffsetMs === undefined) return e;
    const { originalTimestamp, skewOffsetMs, ...rest } = e;
    const restored: ForensicEvent = { ...rest };
    if (originalTimestamp) restored.timestamp = originalTimestamp;
    if (skewOffsetMs !== undefined && e.endTimestamp) {
      const end = epoch(e.endTimestamp);
      if (end !== undefined) restored.endTimestamp = new Date(end + skewOffsetMs).toISOString();
    }
    return restored;
  });
}
