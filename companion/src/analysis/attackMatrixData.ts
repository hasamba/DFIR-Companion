// Loader for the bundled MITRE ATT&CK Enterprise matrix (companion/data/attack-matrix.json, #1764).
//
// Isolated from the pure layout (attackMatrix.ts) so that module stays I/O-free and trivially
// testable. The dataset is a static, committed file regenerated offline by `npm run
// data:update-attack-matrix`; there is NO runtime network call. Read once and cached; degrades
// gracefully — a missing/corrupt file yields an empty catalogue, and the matrix then puts every
// case technique in its Unmapped column instead of dropping it.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface AttackMatrixTactic {
  id: string; // "TA0002"
  shortname: string; // "execution"
  name: string; // "Execution"
}
export interface AttackMatrixTechnique {
  id: string; // "T1059" | "T1059.001"
  name: string; // own name only
  tactics: string[]; // tactic shortnames, in column order
  platforms: string[]; // ATT&CK platform names, verbatim
  parent?: string; // sub-techniques only
}
export interface AttackMatrixData {
  source: string;
  attackVersion: string;
  generated: string;
  tactics: AttackMatrixTactic[];
  techniques: AttackMatrixTechnique[];
}

export const EMPTY_ATTACK_MATRIX: AttackMatrixData = {
  source: "",
  attackVersion: "unknown",
  generated: "",
  tactics: [],
  techniques: [],
};

function candidatePaths(): string[] {
  const paths: string[] = [];
  try {
    paths.push(fileURLToPath(new URL("../../data/attack-matrix.json", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers)
  }
  try {
    paths.push(join(dirname(process.execPath), "data", "attack-matrix.json"));
  } catch {
    // ignore
  }
  return paths;
}

const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

// Validate at the boundary: a hand-edited or truncated file keeps only the well-formed entries.
export function coerceAttackMatrix(raw: unknown): AttackMatrixData {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const tactics: AttackMatrixTactic[] = [];
  for (const t of Array.isArray(obj.tactics) ? obj.tactics : []) {
    const r = t as Record<string, unknown>;
    if (typeof r?.id === "string" && typeof r.shortname === "string" && typeof r.name === "string") {
      tactics.push({ id: r.id, shortname: r.shortname, name: r.name });
    }
  }
  const techniques: AttackMatrixTechnique[] = [];
  for (const t of Array.isArray(obj.techniques) ? obj.techniques : []) {
    const r = t as Record<string, unknown>;
    if (typeof r?.id !== "string" || typeof r.name !== "string") continue;
    techniques.push({
      id: r.id,
      name: r.name,
      tactics: strings(r.tactics),
      platforms: strings(r.platforms),
      ...(typeof r.parent === "string" ? { parent: r.parent } : {}),
    });
  }
  return {
    source: typeof obj.source === "string" ? obj.source : "",
    attackVersion: typeof obj.attackVersion === "string" ? obj.attackVersion : "unknown",
    generated: typeof obj.generated === "string" ? obj.generated : "",
    tactics,
    techniques,
  };
}

let cached: AttackMatrixData | null = null;
let warned = false;

// The bundled ATT&CK matrix, loaded once and cached. Never throws — empty on a missing/invalid
// file (and warns once) so callers degrade gracefully.
export function loadAttackMatrix(): AttackMatrixData {
  if (cached) return cached;
  for (const path of candidatePaths()) {
    try {
      cached = coerceAttackMatrix(JSON.parse(readFileSync(path, "utf8")));
      return cached;
    } catch {
      // try the next candidate
    }
  }
  if (!warned) {
    warned = true;
    console.warn(
      "[attack-matrix] attack-matrix.json not found or invalid — the ATT&CK matrix shows case techniques only. " +
        "Run `npm run data:update-attack-matrix` to (re)generate it.",
    );
  }
  cached = EMPTY_ATTACK_MATRIX;
  return cached;
}

// Test-only: drop the cache, or pin it to a given catalogue (e.g. EMPTY_ATTACK_MATRIX to simulate a
// missing file).
export function resetAttackMatrixCacheForTests(pin: AttackMatrixData | null = null): void {
  cached = pin;
  warned = false;
}
