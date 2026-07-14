// Per-source noise/trust scores (issue #66). Not every tool is equally reliable: a CrowdStrike/Defender
// detection is authoritative, a Hayabusa/Chainsaw/THOR Sigma hit is strong, a Velociraptor raw-artifact
// row is useful-but-noisy, and a generic log line or a screenshot is weakest. Today synthesis, correlation,
// and confidence treat every `sources[]` entry the same. This module assigns each source a trust weight in
// [0,1] and exposes it so:
//   - correlate.ts mergeGroup prefers the HIGHEST-trust event's description as the canonical one,
//   - findingGrounding.ts caps confidence for a finding supported ONLY by low-trust sources (only LOWERS —
//     it never boosts a high-trust one, preserving that pass's "confidence can only fall" invariant),
//   - the analyst can override a source's trust per case (a hunt that's noisy on THIS engagement).
//
// PURE + unit-tested: a default tier map + a fuzzy resolver (source strings are messy — "Velociraptor",
// "velociraptor_processes.csv", "corroborated by Velociraptor, THOR" must all resolve). The per-case
// override store is sourceTrustStore.ts; the wiring is in pipeline.ts.

export type SourceTrustMap = Record<string, number>;

// Trust for a source that matches no known tier. Mid-low: unknown provenance shouldn't be treated as
// authoritative, but also shouldn't be punished as hard as a known-noisy generic log.
export const SOURCE_TRUST_UNKNOWN = 0.7;

// Default trust by tool CATEGORY, keyed by a lowercase keyword matched (substring) against the raw source.
// Values are deliberately coarse tiers, not false precision. Analysts override per case via the store.
export const DEFAULT_SOURCE_TRUST: SourceTrustMap = {
  // EDR / endpoint detection — authoritative
  crowdstrike: 1.0,
  defender: 1.0,
  "carbon black": 0.95,
  "cortex xdr": 0.95,
  sentinelone: 0.95,
  // Sigma / triage engines — strong
  hayabusa: 0.95,
  chainsaw: 0.95,
  thor: 0.95,
  // Endpoint forensics / DFIR collectors — useful but noisier
  velociraptor: 0.85,
  sysmon: 0.85,
  kape: 0.85,
  volatility: 0.85,
  // SIEM / aggregators
  splunk: 0.8,
  sentinel: 0.8,      // Microsoft Sentinel (resolved AFTER sentinelone — see trustForSource ordering)
  elastic: 0.8,
  qradar: 0.8,
  wazuh: 0.8,
  graylog: 0.8,
  siem: 0.8,
  // Network sensors
  zeek: 0.8,
  suricata: 0.8,
  arkime: 0.8,
  wireshark: 0.8,
  // Intel / weaker provenance
  virustotal: 0.75,
  misp: 0.75,
  screenshot: 0.75,
  // Generic imports — weakest
  log: 0.6,
  csv: 0.6,
};

export function normalizeSourceKey(source: string): string {
  return String(source ?? "").trim().toLowerCase();
}

// Trust for ONE raw source string. Exact key first; otherwise the MAX trust among every tier keyword that
// appears as a substring. Max (not first/longest) is what makes messy strings resolve correctly: a
// "corroborated by Velociraptor, THOR" entry inherits THOR's higher trust, and a generic substring
// ("csv"/"log") can never drag down a co-occurring specific tool ("velociraptor_processes.csv" → 0.85).
// Unknown / empty / the legacy "unknown source" placeholder → SOURCE_TRUST_UNKNOWN.
export function trustForSource(source: string, map: SourceTrustMap = DEFAULT_SOURCE_TRUST): number {
  const s = normalizeSourceKey(source);
  if (!s || s === "unknown source") return SOURCE_TRUST_UNKNOWN;
  if (map[s] !== undefined) return map[s];
  let best: number | undefined;
  for (const [k, v] of Object.entries(map)) {
    if (s.includes(k) && (best === undefined || v > best)) best = v;
  }
  return best ?? SOURCE_TRUST_UNKNOWN;
}

// The trust of an EVENT = the MAX over its sources: an event corroborated by even one high-trust tool
// inherits that tool's authority. A source-less event falls back to SOURCE_TRUST_UNKNOWN.
export function trustForSources(sources: readonly string[] | undefined, map: SourceTrustMap = DEFAULT_SOURCE_TRUST): number {
  const real = (sources ?? []).filter((s) => s && s !== "unknown source");
  if (!real.length) return SOURCE_TRUST_UNKNOWN;
  return Math.max(...real.map((s) => trustForSource(s, map)));
}

// Merge per-case overrides onto the default map. Overrides are already normalized/clamped by the store;
// here we just layer them so an override for one key leaves the rest of the defaults intact.
export function effectiveTrustMap(overrides?: SourceTrustMap): SourceTrustMap {
  return { ...DEFAULT_SOURCE_TRUST, ...(overrides ?? {}) };
}

// Clamp/validate one override value into [0,1]; returns null for a non-finite or out-of-range value so the
// store can drop it rather than persist garbage that would skew every downstream weight.
export function sanitizeTrustValue(v: unknown): number | null {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n) || n < 0 || n > 1) return null;
  return n;
}

// Sanitize a whole override map: keep only real keys with in-range values (lowercased keys).
export function sanitizeTrustOverrides(raw: unknown): SourceTrustMap {
  const out: SourceTrustMap = {};
  if (!raw || typeof raw !== "object") return out;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    const key = normalizeSourceKey(k);
    const val = sanitizeTrustValue(v);
    if (key && val !== null) out[key] = val;
  }
  return out;
}
