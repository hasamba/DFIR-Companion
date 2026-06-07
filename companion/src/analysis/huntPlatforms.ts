// Which hunt-query platforms the dashboard's 🔍 generator offers. The generator emits a card per
// platform (Velociraptor VQL, Defender/Sentinel KQL, Elastic ES|QL, Splunk SPL, Sigma, YARA,
// Suricata). On a given team only some of those tools exist, so the analyst can trim the modal via
// the DFIR_HUNT_PLATFORMS allowlist env var (e.g. `velociraptor` to show only Velociraptor).
//
// This is a server-side config: startServer resolves the env var and exposes the enabled list on
// /health; the dashboard reads it and renders only those cards. The platform KEYS below are the
// contract between the two — the dashboard tags each card with the same key. Keep them in sync.

// Canonical platform keys, in the display order the modal uses (stable for the UI).
export const HUNT_PLATFORMS = [
  "velociraptor",
  "defender",
  "elastic",
  "splunk",
  "sigma",
  "yara",
  "suricata",
] as const;

export type HuntPlatform = (typeof HUNT_PLATFORMS)[number];

// Forgiving aliases so the env var accepts the names analysts actually type (product/query-language
// synonyms), not just the canonical key. Case-insensitive (input is lowercased before lookup).
const ALIASES: Readonly<Record<string, HuntPlatform>> = {
  velociraptor: "velociraptor", velo: "velociraptor", vql: "velociraptor",
  defender: "defender", kql: "defender", sentinel: "defender", microsoft: "defender", mde: "defender", "msde": "defender",
  elastic: "elastic", esql: "elastic", kibana: "elastic", elasticsearch: "elastic", "elk": "elastic",
  splunk: "splunk", spl: "splunk",
  sigma: "sigma",
  yara: "yara",
  suricata: "suricata", snort: "suricata", ids: "suricata",
};

/**
 * Resolve the DFIR_HUNT_PLATFORMS allowlist into the set of enabled hunt-query platforms.
 *
 * - Unset / empty → ALL platforms (backward compatible — the generator behaves as before).
 * - Otherwise → the subset named, in canonical display order. Tokens are split on comma / space /
 *   semicolon, lowercased, and mapped through {@link ALIASES}; unknown tokens are ignored.
 * - If a non-empty value yields zero recognized platforms (all typos), fall back to ALL so a
 *   mistake never leaves the analyst with an empty hunt modal and no explanation.
 *
 * Pure — depends only on its argument.
 */
export function resolveHuntPlatforms(raw: string | undefined | null): HuntPlatform[] {
  if (raw == null || !raw.trim()) return [...HUNT_PLATFORMS];
  const wanted = new Set<HuntPlatform>();
  for (const token of raw.split(/[\s,;]+/)) {
    const key = token.trim().toLowerCase();
    if (!key) continue;
    const mapped = ALIASES[key];
    if (mapped) wanted.add(mapped);
  }
  if (wanted.size === 0) return [...HUNT_PLATFORMS]; // all tokens unrecognized → don't break the UI
  return HUNT_PLATFORMS.filter((p) => wanted.has(p));
}
