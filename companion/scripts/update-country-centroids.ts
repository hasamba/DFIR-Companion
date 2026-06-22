// Re-fetch + write the country-centroid lookup table into companion/data/country-centroids.json.
//
// Powers the offline "Geographic IP Map" feature (issue #133): when a GeoIP enrichment carries
// only a country code (not precise lat/lon), the map falls back to the country centroid so the
// indicator still appears on the map (flagged approximate). This script is the ONLY network touch;
// the resulting JSON is committed and loaded at runtime without any network call (OPSEC-safe).
//
// Source: Google DSPL canonical countries CSV (public domain)
//   https://raw.githubusercontent.com/google/dspl/master/samples/google/canonical/countries.csv
//   Columns: country (alpha-2), latitude, longitude, name
//
// Run:  npm run data:update-geo   (re-fetches and overwrites companion/data/country-centroids.json)
//
// It is run with tsx and is NOT in tsconfig `include`, so `tsc` won't type-check it — verify by
// running. Keep it dependency-free (Node 20+ global fetch only).
// Override the source URL via DFIR_COUNTRY_CENTROIDS_URL.

import { writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const CSV_URL =
  process.env.DFIR_COUNTRY_CENTROIDS_URL ||
  "https://raw.githubusercontent.com/google/dspl/master/samples/google/canonical/countries.csv";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_PATH = join(HERE, "..", "data", "country-centroids.json");

interface CentroidEntry {
  name: string;
  lat: number;
  lon: number;
}

// Parse a minimal RFC 4180 CSV, returning rows as string[] arrays.
// Handles header row at index 0. Supports "quoted fields" (outer quotes stripped, no
// embedded-comma or escaped-quote handling needed for this specific dataset).
function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let i = 0;
  while (i <= line.length) {
    if (line[i] === '"') {
      // Quoted field: advance past opening quote, read until closing quote.
      const close = line.indexOf('"', i + 1);
      if (close === -1) {
        fields.push(line.slice(i + 1).trim());
        break;
      }
      fields.push(line.slice(i + 1, close).trim());
      i = close + 2; // skip closing quote + comma
    } else {
      const comma = line.indexOf(",", i);
      if (comma === -1) {
        fields.push(line.slice(i).trim());
        break;
      }
      fields.push(line.slice(i, comma).trim());
      i = comma + 1;
    }
  }
  return fields;
}

function parseCsv(text: string): { headers: string[]; rows: string[][] } {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length === 0) return { headers: [], rows: [] };
  const headers = parseCsvLine(lines[0]);
  const rows = lines.slice(1).map(parseCsvLine);
  return { headers, rows };
}

async function main(): Promise<void> {
  console.log(`[geo] fetching ${CSV_URL}`);
  const res = await fetch(CSV_URL);
  if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
  const text = await res.text();

  const { headers, rows } = parseCsv(text);

  // Detect column indices by name (tolerant of capitalisation differences).
  const h = (name: string): number =>
    headers.findIndex((x) => x.toLowerCase() === name.toLowerCase());

  const idxCode = h("country");
  const idxLat = h("latitude");
  const idxLon = h("longitude");
  const idxName = h("name");

  if (idxCode === -1 || idxLat === -1 || idxLon === -1 || idxName === -1) {
    throw new Error(
      `unexpected CSV headers: ${JSON.stringify(headers)} — ` +
        `expected country, latitude, longitude, name`,
    );
  }

  console.log(`[geo] ${rows.length} rows, headers: ${JSON.stringify(headers)}`);

  const centroids: Record<string, CentroidEntry> = {};
  let skipped = 0;

  for (const row of rows) {
    const code = (row[idxCode] ?? "").trim().toUpperCase();
    const latStr = (row[idxLat] ?? "").trim();
    const lonStr = (row[idxLon] ?? "").trim();
    const name = (row[idxName] ?? "").trim();

    if (!code || code.length !== 2) {
      skipped++;
      continue;
    }
    if (!latStr || !lonStr) {
      skipped++;
      continue;
    }

    const lat = Number(latStr);
    const lon = Number(lonStr);

    if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
      skipped++;
      continue;
    }

    centroids[code] = { name: name || code, lat, lon };
  }

  // Sort keys alphabetically for deterministic output.
  const sorted = Object.fromEntries(
    Object.keys(centroids)
      .sort()
      .map((k) => [k, centroids[k]]),
  );

  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(OUT_PATH, JSON.stringify(sorted, null, 2) + "\n", "utf8");

  const count = Object.keys(sorted).length;
  console.log(
    `[geo] wrote ${OUT_PATH}\n[geo] ${count} country centroids (skipped ${skipped} rows)`,
  );

  // Spot-check a few key entries.
  const spot = ["DE", "IL", "US", "GB", "JP"];
  for (const code of spot) {
    const e = sorted[code];
    if (e) {
      console.log(`[geo]   ${code}: ${e.name} (${e.lat}, ${e.lon})`);
    } else {
      console.warn(`[geo]   WARNING: ${code} not found in output`);
    }
  }
}

main().catch((err) => {
  console.error("[geo] FAILED:", err instanceof Error ? err.message : err);
  process.exit(1);
});
