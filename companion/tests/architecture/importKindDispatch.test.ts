import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { IMPORT_KINDS } from "../../src/analysis/importerSpec.js";

// "unknown" is the sentinel detectImportKind returns when it recognises nothing. It is rejected
// before dispatch, so it is the one kind that must NOT have a case.
const DISPATCHABLE = IMPORT_KINDS.filter((k) => k !== "unknown");

/**
 * Every registered import kind must have somewhere to go.
 *
 * Registering a kind and a content detector is enough to make an importer LOOK finished: the unit
 * tests pass, detection returns the new kind, and the whole suite is green. But the unified route
 * saves the evidence and returns 202 BEFORE dispatch runs in the background, so a kind with no
 * dispatch case fails after the analyst has already been told the upload was accepted. Nothing
 * surfaces. That is exactly how the WER importer shipped dead in its first commit.
 *
 * This reads the dispatch source rather than executing it, because standing up a real pipeline here
 * would test the harness instead of the wiring.
 */
describe("import kinds ↔ dispatch", () => {
  const dispatchSrc = readFileSync(
    join(process.cwd(), "src/composition/importIngest.ts"),
    "utf8",
  );

  it("has a dispatch case for every registered import kind", () => {
    const missing = DISPATCHABLE.filter((k) => !new RegExp(`case "${k}":`).test(dispatchSrc));
    expect(missing).toEqual([]);
  });

  it("routes each dispatch case at something, not at the unhandled fallback", () => {
    // A case that falls through to the default would be worse than a missing one: it reports the
    // generic "unhandled import kind" error naming a kind that IS registered.
    for (const kind of DISPATCHABLE) {
      const m = new RegExp(`case "${kind}":\\s*\\n\\s*return ([^;]+);`).exec(dispatchSrc);
      expect(m, `no dispatch body for kind "${kind}"`).not.toBeNull();
      expect(m![1]).not.toContain("unhandled import kind");
    }
  });
});
