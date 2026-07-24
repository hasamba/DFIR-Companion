// Loader for the bundled known-playbooks dataset (companion/data/known-playbooks.json).
//
// Isolated from the pure matching (playbookMatch.ts) so that module stays I/O-free and trivially
// testable. The dataset is a static, committed file; there is NO runtime network call. Read once
// and cached — the route calls this, and the file never changes at runtime. Degrades gracefully:
// a missing/corrupt file yields an empty dataset (the endpoint returns "no matches" rather than
// crashing).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { KnownPlaybooksDataset, Playbook, PlaybookStep } from "./playbookMatch.js";

const EMPTY: KnownPlaybooksDataset = { source: "", generated: "", playbooks: [] };

// Candidate locations, most-likely first: dev/tsc resolve relative to this module; the SEA EXE
// ships data/ next to the binary (build-sea stages it). Mirrors adversaryGroupsData.ts.
function candidatePaths(): string[] {
  const paths: string[] = [];
  try {
    paths.push(fileURLToPath(new URL("../../data/known-playbooks.json", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers) — fall through to the execPath candidate.
  }
  try {
    paths.push(join(dirname(process.execPath), "data", "known-playbooks.json"));
  } catch {
    // ignore
  }
  return paths;
}

function isStep(value: unknown): value is PlaybookStep {
  const s = value as Partial<PlaybookStep>;
  return !!s && typeof s.technique === "string" && typeof s.name === "string";
}

function isPlaybook(value: unknown): value is Playbook {
  const p = value as Partial<Playbook>;
  return !!p && typeof p.name === "string" && Array.isArray(p.steps) && p.steps.every(isStep);
}

// Validate + normalize a parsed JSON blob into a dataset, dropping malformed playbook records.
function coerce(raw: unknown): KnownPlaybooksDataset {
  const obj = raw as Partial<KnownPlaybooksDataset>;
  const playbooks = Array.isArray(obj?.playbooks) ? obj.playbooks.filter(isPlaybook) : [];
  return {
    source: typeof obj?.source === "string" ? obj.source : "",
    generated: typeof obj?.generated === "string" ? obj.generated : "",
    playbooks,
  };
}

let cached: KnownPlaybooksDataset | null = null;
let warned = false;

// The bundled known-playbooks dataset, loaded once and cached. Never throws — returns an empty
// dataset (and warns once) if the file is missing or unparseable, so callers degrade gracefully.
export function loadKnownPlaybooks(): KnownPlaybooksDataset {
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
      "[playbook-match] known-playbooks.json not found or invalid — playbook matching disabled.",
    );
  }
  cached = EMPTY;
  return cached;
}

// Test-only: drop the cache so a test can point the loader at a fresh state.
export function _resetKnownPlaybooksCache(): void {
  cached = null;
  warned = false;
}
