// Loader for the bundled incident-type library (companion/data/incident-types/*.json, one file per
// type) — issue #236.
//
// Isolated from the pure apply logic (incidentTypes.ts) so that module stays I/O-free and trivially
// testable. The dataset is static, committed, analyst-editable data; there is NO runtime network
// call. Read once and cached. Degrades gracefully: a missing directory or a corrupt file yields the
// types that DID parse rather than crashing case creation — a bad hand-edit must never take the
// New Case dialog down with it.
//
// Mirrors knownPlaybooksData.ts, including the SEA candidate-path handling (build-sea stages
// companion/data/ next to the binary).

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BUILT_IN_INCIDENT_TYPE_IDS,
  parseIncidentType,
  type IncidentType,
} from "./incidentTypes.js";

const DATA_SUBDIR = join("data", "incident-types");

// Candidate locations, most-likely first: dev/tsc resolve relative to this module; the SEA EXE
// ships data/ next to the binary.
function candidateDirs(): string[] {
  const dirs: string[] = [];
  try {
    dirs.push(fileURLToPath(new URL("../../data/incident-types/", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers) — fall through to the execPath candidate.
  }
  try {
    dirs.push(join(dirname(process.execPath), DATA_SUBDIR));
  } catch {
    // ignore
  }
  return dirs;
}

// Order by the canonical id list so the pickers lead with the most common incident types; any type
// found on disk but absent from that list (an analyst dropped an extra file into the bundled dir)
// keeps a stable alphabetical position at the end rather than disappearing.
function inCanonicalOrder(types: IncidentType[]): IncidentType[] {
  const rank = new Map<string, number>(BUILT_IN_INCIDENT_TYPE_IDS.map((id, i) => [id, i]));
  const known = BUILT_IN_INCIDENT_TYPE_IDS.length;
  return [...types].sort((a, b) => {
    const ra = rank.get(a.id) ?? known;
    const rb = rank.get(b.id) ?? known;
    return ra !== rb ? ra - rb : a.id.localeCompare(b.id);
  });
}

function readDir(dir: string): IncidentType[] {
  const out: IncidentType[] = [];
  for (const entry of readdirSync(dir)) {
    if (!entry.endsWith(".json")) continue;
    try {
      const parsed = parseIncidentType(JSON.parse(readFileSync(join(dir, entry), "utf8")));
      // Force builtIn on anything read from the bundled dir — the flag is what tells the UI a type
      // can't be deleted, and it must reflect where the file lives, not what the file claims.
      if (parsed) out.push({ ...parsed, builtIn: true });
    } catch {
      // skip an unreadable/unparseable file — the rest of the library still loads
    }
  }
  return out;
}

let cached: IncidentType[] | null = null;
let warned = false;

// The bundled incident-type library, loaded once and cached. Never throws — returns an empty list
// (and warns once) if no candidate directory is readable, so callers degrade to "no built-in types"
// rather than failing the request.
export function loadBuiltInIncidentTypes(): readonly IncidentType[] {
  if (cached) return cached;
  for (const dir of candidateDirs()) {
    try {
      const types = readDir(dir);
      if (types.length > 0) {
        cached = inCanonicalOrder(types);
        return cached;
      }
    } catch {
      // try the next candidate
    }
  }
  if (!warned) {
    warned = true;
    console.warn(
      "[incident-types] data/incident-types/ not found or empty — built-in incident types unavailable.",
    );
  }
  cached = [];
  return cached;
}

// Resolve a built-in incident type by id. Returns undefined for an unknown id (custom types are
// resolved by IncidentTypeStore, which falls back to its own on-disk list).
export function getBuiltInIncidentType(id: string): IncidentType | undefined {
  return loadBuiltInIncidentTypes().find((t) => t.id === id);
}

// Test-only: drop the cache so a test can point the loader at a fresh state.
export function _resetIncidentTypesCache(): void {
  cached = null;
  warned = false;
}
