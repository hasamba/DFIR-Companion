// Proactive false-positive pattern propagation (investigation-guidance #15b). Marking one event false
// positive teaches the system nothing lasting — the same nightly-robocopy pattern re-arrives High after
// every import. This closes that loop: an event marked FP stamps a `patternFingerprint` (the prevalence
// pattern key of the anchor), and after each import we check the NEW events against those fingerprints.
// When enough new events match a known FP pattern, the import banner suggests a one-click bulk-mark —
// SUGGESTED, never auto-applied (the analyst always confirms; an attacker hiding inside a benign-looking
// pattern must never be silently suppressed).
//
// Precision over recall on purpose: the match is EXACT on the normalized pattern key (same command shape
// / same hash), not the fuzzy findSimilarEvents scorer — auto-suggesting a bulk FP mark on a loose "same
// MITRE" match would be dangerous. The fuzzy scorer stays for the interactive mark-FP dialog.

import type { ForensicEvent } from "./stateTypes.js";
import type { FalsePositiveMarker } from "./falsePositive.js";
import { patternKey } from "./prevalence.js";

export interface FpPropagationSuggestion {
  markerId: string;            // the FP marker this pattern came from
  ref: string;                 // the marker's ref (the original anchor event id), for display
  note: string;                // the marker's note/reason, for display
  patternFingerprint: string;  // the matched normalized pattern key
  count: number;               // how many NEW events match it
  matchedEventIds: string[];   // the matching new-event ids (capped) — fed to the bulk-mark batch call
  sampleLabel: string;         // a sample new-event description, for the banner
}

export interface FpPropagationOptions {
  minMatches?: number;     // suggest only when at least this many new events match (default 3)
  maxSuggestions?: number; // cap the number of distinct patterns surfaced (default 5)
  maxIdsPerPattern?: number; // cap the id list per pattern (default 500 — the batch endpoint's practical bound)
}

const MIN_MATCHES_DEFAULT = 3;
const MAX_SUGGESTIONS_DEFAULT = 5;
const MAX_IDS_DEFAULT = 500;

// Match freshly-imported events against the pattern fingerprints of existing false-positive markers.
// Returns one suggestion per FP pattern that ≥ minMatches new events reproduce, most-matched first. Pure
// + deterministic — no clock, no I/O.
export function matchFpPropagation(
  newEvents: readonly ForensicEvent[],
  markers: readonly FalsePositiveMarker[],
  opts: FpPropagationOptions = {},
): FpPropagationSuggestion[] {
  const minMatches = Math.max(1, Math.floor(opts.minMatches ?? MIN_MATCHES_DEFAULT));
  const maxSuggestions = Math.max(1, Math.floor(opts.maxSuggestions ?? MAX_SUGGESTIONS_DEFAULT));
  const maxIds = Math.max(1, Math.floor(opts.maxIdsPerPattern ?? MAX_IDS_DEFAULT));

  // fingerprint → the (first) event marker that carries it. Only event markers with a fingerprint
  // participate — a finding/IOC marker has no per-event pattern to propagate.
  const byFingerprint = new Map<string, FalsePositiveMarker>();
  for (const m of markers) {
    if (m.kind !== "event" || !m.patternFingerprint) continue;
    if (!byFingerprint.has(m.patternFingerprint)) byFingerprint.set(m.patternFingerprint, m);
  }
  if (!byFingerprint.size) return [];

  const hits = new Map<string, { marker: FalsePositiveMarker; ids: string[]; sample: string }>();
  for (const e of newEvents) {
    const key = patternKey(e);
    if (!key) continue;
    const marker = byFingerprint.get(key);
    if (!marker) continue;
    let hit = hits.get(key);
    if (!hit) { hit = { marker, ids: [], sample: e.description || e.id }; hits.set(key, hit); }
    if (hit.ids.length < maxIds) hit.ids.push(e.id);
  }

  const suggestions: FpPropagationSuggestion[] = [];
  for (const [key, hit] of hits) {
    if (hit.ids.length < minMatches) continue;
    suggestions.push({
      markerId: hit.marker.id,
      ref: hit.marker.ref,
      note: (hit.marker.note ?? "").trim() || hit.marker.reason,
      patternFingerprint: key,
      count: hit.ids.length,
      matchedEventIds: hit.ids,
      sampleLabel: hit.sample.slice(0, 160),
    });
  }
  suggestions.sort((a, b) => b.count - a.count || a.patternFingerprint.localeCompare(b.patternFingerprint));
  return suggestions.slice(0, maxSuggestions);
}
