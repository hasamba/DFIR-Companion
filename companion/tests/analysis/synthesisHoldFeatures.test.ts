// SYNTHESIS_HOLD_FEATURES names AI-call labels by string. If a call site renames its label, a held
// synthesis would stop counting as one, and clearing its Presidio gate would leave the pill reading
// "up to date" over a run that never happened. This pins each label to the file that sends it.
import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { SYNTHESIS_HOLD_FEATURES } from "../../src/analysis/aiState.js";
import { IMPORT_PRESCAN_FEATURE } from "../../src/analysis/ai/providerCall.js";

const SRC = join(__dirname, "../../src/analysis/ai");

// label → the source file whose AI call sends it, as a quoted string literal.
const SENT_BY: Record<string, string> = {
  synthesis: "synthesisCall.ts",
  "deep-pass-observe": "deepPassObserve.ts",
  "finding-tasks": "findingTaskPass.ts",
  extract: "extraction.ts",
  csv: "extraction.ts",
  log: "extraction.ts",
};

describe("SYNTHESIS_HOLD_FEATURES", () => {
  it("still matches the label each synthesis-family call sends", async () => {
    for (const [label, file] of Object.entries(SENT_BY)) {
      expect(SYNTHESIS_HOLD_FEATURES.has(label), label).toBe(true);
      const source = await readFile(join(SRC, file), "utf8");
      expect(source.includes(`"${label}"`), `${file} no longer sends "${label}"`).toBe(true);
    }
  });

  it("includes the import pre-scan's feature and the default label", () => {
    expect(SYNTHESIS_HOLD_FEATURES.has(IMPORT_PRESCAN_FEATURE)).toBe(true);
    expect(SYNTHESIS_HOLD_FEATURES.has("ai")).toBe(true);
  });

  it("does not count the hunt suggestions as a synthesis", () => {
    expect(SYNTHESIS_HOLD_FEATURES.has("suggest-language-hunts")).toBe(false);
    expect(SYNTHESIS_HOLD_FEATURES.has("suggest-playbook-language-hunts")).toBe(false);
  });
});
