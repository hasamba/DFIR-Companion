// Loader for the bundled MITRE ATT&CK Groups dataset (companion/data/attack-groups.json).
//
// Isolated from the pure scoring (adversaryHints.ts) so that module stays I/O-free and trivially
// testable. The dataset is a static, committed file regenerated offline by `npm run
// data:update-attack`; there is NO runtime network call (OPSEC-safe — adversary attribution is
// computed entirely locally).
//
// Read once and cached: the report renderer and the /adversary-hints route both call this, and the
// file never changes at runtime. Degrades gracefully — a missing/corrupt file yields an empty
// dataset (the feature shows "no hints" rather than crashing a report or the dashboard).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_MIN_OVERLAP,
  DEFAULT_TOP_N,
  type AdversaryGroup,
  type AdversaryHintOptions,
} from "./adversaryHints.js";

export interface AdversaryGroupsDataset {
  source: string;
  attackVersion: string; // ATT&CK release the data came from, e.g. "19.1"
  generated: string; // ISO date the slim file was generated
  groupCount: number;
  groups: AdversaryGroup[];
}

const EMPTY: AdversaryGroupsDataset = {
  source: "",
  attackVersion: "unknown",
  generated: "",
  groupCount: 0,
  groups: [],
};

// Candidate locations, most-likely first: dev/tsc resolve relative to this module; the SEA EXE
// ships data/ next to the binary (build-sea stages it).
function candidatePaths(): string[] {
  const paths: string[] = [];
  try {
    paths.push(fileURLToPath(new URL("../../data/attack-groups.json", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers) — fall through to the execPath candidate.
  }
  try {
    paths.push(join(dirname(process.execPath), "data", "attack-groups.json"));
  } catch {
    // ignore
  }
  return paths;
}

function isGroup(value: unknown): value is AdversaryGroup {
  const g = value as Partial<AdversaryGroup>;
  return (
    !!g &&
    typeof g.id === "string" &&
    typeof g.name === "string" &&
    Array.isArray(g.techniques) &&
    Array.isArray(g.aliases)
  );
}

// Validate + normalize a parsed JSON blob into a dataset, dropping malformed group records.
function coerce(raw: unknown): AdversaryGroupsDataset {
  const obj = raw as Partial<AdversaryGroupsDataset>;
  const groups = Array.isArray(obj?.groups) ? obj.groups.filter(isGroup) : [];
  return {
    source: typeof obj?.source === "string" ? obj.source : "",
    attackVersion: typeof obj?.attackVersion === "string" ? obj.attackVersion : "unknown",
    generated: typeof obj?.generated === "string" ? obj.generated : "",
    groupCount: groups.length,
    groups,
  };
}

let cached: AdversaryGroupsDataset | null = null;
let warned = false;

// The bundled adversary-groups dataset, loaded once and cached. Never throws — returns an empty
// dataset (and warns once) if the file is missing or unparseable, so callers degrade gracefully.
export function loadAdversaryGroupsDataset(): AdversaryGroupsDataset {
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
      "[adversary-hints] attack-groups.json not found or invalid — adversary hints disabled. " +
        "Run `npm run data:update-attack` to (re)generate it.",
    );
  }
  cached = EMPTY;
  return cached;
}

// Hint thresholds resolved from the environment, so the route and the report agree:
//   DFIR_ADVERSARY_MIN_OVERLAP (default 3)  — minimum overlapping techniques to surface a group
//   DFIR_ADVERSARY_TOP_N       (default 5)  — cap on how many groups to return
export function adversaryHintEnvOptions(): Required<AdversaryHintOptions> {
  return {
    minOverlap: Number(process.env.DFIR_ADVERSARY_MIN_OVERLAP) || DEFAULT_MIN_OVERLAP,
    topN: Number(process.env.DFIR_ADVERSARY_TOP_N) || DEFAULT_TOP_N,
  };
}

// Test-only: drop the cache so a test can point the loader at a fresh state.
export function _resetAdversaryGroupsCache(): void {
  cached = null;
  warned = false;
}
