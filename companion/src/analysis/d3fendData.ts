// Loader for the bundled MITRE D3FEND mapping (companion/data/d3fend-map.json).
//
// Isolated from the pure resolution (d3fendMap.ts) so that module stays I/O-free and trivially
// testable. The dataset is a static, committed file regenerated offline by `npm run
// data:update-d3fend`; there is NO runtime network call (OPSEC-safe, deterministic).
//
// Read once and cached: the report renderer and the /d3fend-countermeasures route both call this,
// and the file never changes at runtime. Degrades gracefully — a missing/corrupt file yields an
// empty mapping (the feature shows "dataset not available" rather than crashing a report).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_MAX_PER_TECHNIQUE,
  type D3fendCountermeasure,
  type D3fendDatasetView,
  type D3fendOptions,
} from "./d3fendMap.js";

const EMPTY: D3fendDatasetView = {
  d3fendVersion: "unknown",
  generated: "",
  source: "",
  note: "",
  countermeasureCount: 0,
  map: {},
};

// Candidate locations, most-likely first: dev/tsc resolve relative to this module; the SEA EXE ships
// data/ next to the binary (build-sea stages it).
function candidatePaths(): string[] {
  const paths: string[] = [];
  try {
    paths.push(fileURLToPath(new URL("../../data/d3fend-map.json", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers) — fall through to the execPath candidate.
  }
  try {
    paths.push(join(dirname(process.execPath), "data", "d3fend-map.json"));
  } catch {
    // ignore
  }
  return paths;
}

function isCountermeasure(value: unknown): value is D3fendCountermeasure {
  const c = value as Partial<D3fendCountermeasure>;
  return !!c && typeof c.id === "string" && typeof c.name === "string" && typeof c.tactic === "string";
}

// Validate + normalize a parsed JSON blob into a dataset, dropping malformed countermeasure records.
function coerce(raw: unknown): D3fendDatasetView {
  const obj = raw as Partial<D3fendDatasetView> & { map?: unknown };
  const rawMap = obj?.map && typeof obj.map === "object" && !Array.isArray(obj.map) ? (obj.map as Record<string, unknown>) : {};
  const map: Record<string, D3fendCountermeasure[]> = {};
  for (const [tech, cms] of Object.entries(rawMap)) {
    if (!Array.isArray(cms)) continue;
    const clean = cms.filter(isCountermeasure).map((c) => ({
      id: c.id,
      name: c.name,
      tactic: c.tactic,
      category: typeof c.category === "string" ? c.category : "",
    }));
    if (clean.length) map[tech] = clean;
  }
  const rawDefs =
    obj?.definitions && typeof obj.definitions === "object" && !Array.isArray(obj.definitions)
      ? (obj.definitions as Record<string, unknown>)
      : {};
  const definitions: Record<string, string> = {};
  for (const [id, def] of Object.entries(rawDefs)) {
    if (typeof def === "string" && def.trim()) definitions[id] = def;
  }
  return {
    d3fendVersion: typeof obj?.d3fendVersion === "string" ? obj.d3fendVersion : "unknown",
    generated: typeof obj?.generated === "string" ? obj.generated : "",
    source: typeof obj?.source === "string" ? obj.source : "",
    note: typeof obj?.note === "string" ? obj.note : "",
    countermeasureCount: typeof obj?.countermeasureCount === "number" ? obj.countermeasureCount : 0,
    map,
    definitions,
  };
}

let cached: D3fendDatasetView | null = null;
let warned = false;

// The bundled D3FEND mapping, loaded once and cached. Never throws — returns an empty mapping (and
// warns once) if the file is missing or unparseable, so callers degrade gracefully.
export function loadD3fendDataset(): D3fendDatasetView {
  if (cached) return cached;
  for (const path of candidatePaths()) {
    try {
      cached = coerce(JSON.parse(readFileSync(path, "utf8")));
      return cached;
    } catch {
      // try the next candidate
    }
  }
  if (!warned) {
    warned = true;
    console.warn(
      "[d3fend] d3fend-map.json not found or invalid — defensive countermeasures disabled. " +
        "Run `npm run data:update-d3fend` to (re)generate it.",
    );
  }
  cached = EMPTY;
  return cached;
}

// Resolution options from the environment, so the route and the report agree:
//   DFIR_D3FEND_MAX_PER_TECHNIQUE  (default 12)  — cap on countermeasures listed per technique
export function d3fendEnvOptions(): Required<D3fendOptions> {
  return {
    maxPerTechnique: Number(process.env.DFIR_D3FEND_MAX_PER_TECHNIQUE) || DEFAULT_MAX_PER_TECHNIQUE,
  };
}

// Test-only: drop the cache so a test can point the loader at a fresh state.
export function _resetD3fendCache(): void {
  cached = null;
  warned = false;
}
