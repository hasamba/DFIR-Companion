import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// `staging_temp_executable` says where a file sits, not that it masquerades. It used to add
// `defense-evasion` and T1036 to every executable in a temp folder, installers included.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

const TEMP_EXE = "C:\\Users\\USER01~1\\AppData\\Local\\Temp\\BingBarSetup-Partner.exe";

describe("staging_temp_executable", () => {
  it("tags an executable in a temp folder as temp-staging only", () => {
    const event = {
      id: "e1",
      path: TEMP_EXE,
      relatedFindingIds: [],
      sourceScreenshots: [],
      mitreTechniques: [],
    } as unknown as ForensicEvent;
    const proposal = runTagger([event], RULES).perEvent[0];
    expect(proposal?.ruleIds).toContain("staging_temp_executable");
    expect(proposal?.tags).toContain("temp-staging");
    expect(proposal?.tags).not.toContain("defense-evasion");
    expect(proposal?.mitre ?? []).not.toContain("T1036");
  });
});
