import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";

// Guards the shipped default ruleset: a YAML typo, an unknown field, or a bad regex here would ship
// a broken default. This compiles data/tags.yaml exactly as the app does.
describe("bundled data/tags.yaml", () => {
  it("compiles cleanly and defines multiple rules", () => {
    const path = fileURLToPath(new URL("../../data/tags.yaml", import.meta.url));
    const text = readFileSync(path, "utf8");
    const rs = compileText(text);
    expect(rs.rules.length).toBeGreaterThan(5);
    // every rule carries at least one action
    for (const r of rs.rules) {
      const hasAction = r.tags.length > 0 || r.mitre.length > 0 || r.severity !== undefined || r.view !== undefined;
      expect(hasAction, `rule ${r.id} has no action`).toBe(true);
    }
  });
});
