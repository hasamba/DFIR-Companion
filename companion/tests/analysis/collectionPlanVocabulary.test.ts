import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { COLLECTION_STEPS } from "../../src/analysis/collectionPlan.js";
import { detectTool } from "../../src/analysis/toolDetect.js";

// #236 shipped 27 hunt-bundle ids and 8 report-template ids that referred to nothing. This test is
// the guard against doing it again: every source label a collection step claims to be satisfied by
// must be a label some importer actually stamps on an event, or a name detectTool() resolves.
// A renamed or invented label fails the build instead of silently leaving a step that never ticks.

const SRC = fileURLToPath(new URL("../../src/", import.meta.url));

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) return walk(full);
    return full.endsWith(".ts") ? [full] : [];
  });
}

// Labels written as literals in the importers: `sources: ["X"]` or `const X_SOURCE = "Y"`.
function importerLiterals(): Set<string> {
  const found = new Set<string>();
  for (const file of walk(SRC)) {
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(/sources:\s*\["([^"]+)"\]/g)) found.add(m[1]);
    for (const m of text.matchAll(/_SOURCE\s*=\s*"([^"]+)"/g)) found.add(m[1]);
    for (const m of text.matchAll(/\?\?\s*"([A-Z][^"]+)"/g)) found.add(m[1]);
  }
  return found;
}

describe("collection-plan vocabulary is grounded in real importers", () => {
  const literals = importerLiterals();

  it("finds the importer source literals to check against", () => {
    // Guards the guard: if the scrape breaks, every label would "pass" vacuously.
    expect(literals.size).toBeGreaterThan(20);
    expect(literals).toContain("MemProcFS");
    expect(literals).toContain("Entra ID");
  });

  it("every satisfying label is a real importer literal or a detectTool name", () => {
    const unknown: string[] = [];
    for (const step of COLLECTION_STEPS) {
      for (const label of step.satisfiedBy) {
        // detectTool round-trips its own vendor names: its patterns match the name itself.
        if (literals.has(label) || detectTool(label) === label) continue;
        unknown.push(`${step.id} → "${label}"`);
      }
    }
    expect(unknown, `labels no importer produces:\n${unknown.join("\n")}`).toEqual([]);
  });

  it("every step is either satisfiable or explicitly external", () => {
    for (const step of COLLECTION_STEPS) {
      const satisfiable = step.satisfiedBy.length > 0;
      const external = step.id === "physical-access";
      expect(satisfiable || external, `step "${step.id}" can never be satisfied`).toBe(true);
    }
  });
});
