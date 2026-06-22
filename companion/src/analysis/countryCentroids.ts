// Loader + resolver for the bundled country-centroid dataset (companion/data/country-centroids.json).
//
// Isolated from callers so the module stays I/O-free and trivially testable. The dataset is a
// static, committed file regenerated offline by `npm run data:update-geo`; there is NO runtime
// network call (OPSEC-safe).
//
// Read once and cached: the geo-map builder calls this per IOC on demand. Degrades gracefully —
// a missing/corrupt file yields an empty map (the feature shows no centroid markers rather than
// crashing a report or the dashboard).
//
// Usage:
//   countryCentroid("DE")       → { lat: 51.165691, lon: 10.451526, name: "Germany" }
//   countryCentroid("de")       → same (case-insensitive)
//   countryCentroid("Germany")  → same (full-name lookup)
//   countryCentroid("ZZ")       → undefined
//   countryCentroid("")         → undefined

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface Centroid {
  lat: number;
  lon: number;
  name: string;
}

// Raw shape stored in the JSON file.
interface CentroidEntry {
  name: string;
  lat: number;
  lon: number;
}

// Candidate file locations, most-likely first: dev/tsc resolve relative to this module; the SEA
// EXE ships data/ next to the binary (build-sea stages it) — mirrors adversaryGroupsData.ts.
function candidatePaths(): string[] {
  const paths: string[] = [];
  try {
    paths.push(fileURLToPath(new URL("../../data/country-centroids.json", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers) — fall through to the execPath candidate.
  }
  try {
    paths.push(join(dirname(process.execPath), "data", "country-centroids.json"));
  } catch {
    // ignore
  }
  return paths;
}

interface CentroidCache {
  /** alpha-2 code (uppercase) → centroid */
  byCode: Map<string, Centroid>;
  /** lowercased full name → alpha-2 code */
  byName: Map<string, string>;
}

let cached: CentroidCache | null = null;
let warned = false;

function loadCache(): CentroidCache {
  if (cached) return cached;

  for (const path of candidatePaths()) {
    try {
      const raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
      const byCode = new Map<string, Centroid>();
      const byName = new Map<string, string>();

      for (const [code, entry] of Object.entries(raw)) {
        const e = entry as Partial<CentroidEntry>;
        const lat = typeof e.lat === "number" && Number.isFinite(e.lat) ? e.lat : null;
        const lon = typeof e.lon === "number" && Number.isFinite(e.lon) ? e.lon : null;
        const name = typeof e.name === "string" && e.name.trim() ? e.name.trim() : code;
        if (lat === null || lon === null) continue;

        const normCode = code.trim().toUpperCase();
        const centroid: Centroid = { lat, lon, name };
        byCode.set(normCode, centroid);
        byName.set(name.toLowerCase(), normCode);
      }

      cached = { byCode, byName };
      return cached;
    } catch {
      // try the next candidate
    }
  }

  if (!warned) {
    warned = true;
    console.warn(
      "[country-centroids] country-centroids.json not found or invalid — " +
        "centroid fallback disabled. Run `npm run data:update-geo` to (re)generate it.",
    );
  }
  cached = { byCode: new Map(), byName: new Map() };
  return cached;
}

/**
 * Resolve a country to its geographic centroid.
 *
 * Accepts either:
 * - A 2-letter ISO 3166-1 alpha-2 code (case-insensitive): "DE", "de", "IL"
 * - A full English country name (case-insensitive): "Germany", "germany", "Israel"
 *
 * Returns `undefined` for empty/unknown input.
 */
export function countryCentroid(country: string): Centroid | undefined {
  const input = country?.trim();
  if (!input) return undefined;

  const { byCode, byName } = loadCache();

  // Try alpha-2 code first (fast path — most callers pass a code).
  if (input.length === 2) {
    const hit = byCode.get(input.toUpperCase());
    if (hit) return hit;
  }

  // Try full name lookup (case-insensitive).
  const code = byName.get(input.toLowerCase());
  if (code) return byCode.get(code);

  // Final fallback: try as an alpha-2 code even if length !== 2 (defensive).
  return byCode.get(input.toUpperCase());
}

// Test-only: drop the cache so a test can verify fresh-load behaviour.
export function _resetCentroidCache(): void {
  cached = null;
  warned = false;
}
