// Loader for the bundled MITRE ATT&CK Mitigations mapping (companion/data/attack-mitigations.json).
//
// Isolated from the pure resolution (attackMitigations.ts) so that module stays I/O-free and
// trivially testable. The dataset is a static, committed file regenerated offline by `npm run
// data:update-attack-mitigations`; there is NO runtime network call. Read once and cached; degrades
// gracefully — a missing/corrupt file yields an empty mapping (the feature shows "not available").

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AttackMitigation, MitigationMapLink, MitigationsDatasetView } from "./attackMitigations.js";

const EMPTY: MitigationsDatasetView = {
  attackVersion: "unknown",
  generated: "",
  source: "",
  note: "",
  mitigationCount: 0,
  mitigations: {},
  map: {},
};

function candidatePaths(): string[] {
  const paths: string[] = [];
  try {
    paths.push(fileURLToPath(new URL("../../data/attack-mitigations.json", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers)
  }
  try {
    paths.push(join(dirname(process.execPath), "data", "attack-mitigations.json"));
  } catch {
    // ignore
  }
  return paths;
}

function isMitigation(v: unknown): v is AttackMitigation {
  const m = v as Partial<AttackMitigation>;
  return !!m && typeof m.id === "string" && typeof m.name === "string";
}

function coerce(raw: unknown): MitigationsDatasetView {
  const obj = raw as Partial<MitigationsDatasetView> & { mitigations?: unknown; map?: unknown };
  const mitigations: Record<string, AttackMitigation> = {};
  if (obj?.mitigations && typeof obj.mitigations === "object" && !Array.isArray(obj.mitigations)) {
    for (const [id, m] of Object.entries(obj.mitigations as Record<string, unknown>)) {
      if (!isMitigation(m)) continue;
      mitigations[id] = {
        id: m.id,
        name: m.name,
        description: typeof m.description === "string" ? m.description : "",
        url: typeof m.url === "string" ? m.url : "",
      };
    }
  }
  const map: Record<string, MitigationMapLink[]> = {};
  if (obj?.map && typeof obj.map === "object" && !Array.isArray(obj.map)) {
    for (const [tech, links] of Object.entries(obj.map as Record<string, unknown>)) {
      if (!Array.isArray(links)) continue;
      const clean = links
        .filter((l): l is { id: string; detail?: unknown } => !!l && typeof (l as { id?: unknown }).id === "string")
        .map((l) => ({ id: l.id, detail: typeof l.detail === "string" ? l.detail : "" }));
      if (clean.length) map[tech] = clean;
    }
  }
  return {
    attackVersion: typeof obj?.attackVersion === "string" ? obj.attackVersion : "unknown",
    generated: typeof obj?.generated === "string" ? obj.generated : "",
    source: typeof obj?.source === "string" ? obj.source : "",
    note: typeof obj?.note === "string" ? obj.note : "",
    mitigationCount: Object.keys(mitigations).length,
    mitigations,
    map,
  };
}

let cached: MitigationsDatasetView | null = null;
let warned = false;

// The bundled ATT&CK Mitigations mapping, loaded once and cached. Never throws — empty on
// missing/invalid file (and warns once) so callers degrade gracefully.
export function loadMitigationsDataset(): MitigationsDatasetView {
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
      "[mitigations] attack-mitigations.json not found or invalid — ATT&CK mitigations disabled. " +
        "Run `npm run data:update-attack-mitigations` to (re)generate it.",
    );
  }
  cached = EMPTY;
  return cached;
}

// Test-only: drop the cache so a test can point the loader at a fresh state.
export function _resetMitigationsCache(): void {
  cached = null;
  warned = false;
}
