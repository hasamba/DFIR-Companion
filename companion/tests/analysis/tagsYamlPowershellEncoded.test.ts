import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// `win_powershell_encoded` used to match any `-e` plus 16 base64-like characters. `\s+` crossed a
// newline, so `UpgradeSubscription.exe -e⏎CurrentDirectory: ...` (a non-PowerShell process)
// was tagged as encoded PowerShell. The rule now needs PowerShell and stays on one line.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

function ruleIds(message: string): string[] {
  const event = {
    id: "e1",
    message,
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: [],
  } as unknown as ForensicEvent;
  return runTagger([event], RULES).perEvent[0]?.ruleIds ?? [];
}

describe("win_powershell_encoded", () => {
  it("does not match a non-PowerShell process whose -e flag ends a line", () => {
    const message =
      "Process Create:\nImage: C:\\Windows\\System32\\UpgradeSubscription.exe\n" +
      "CommandLine: C:\\Windows\\system32\\UpgradeSubscription.exe -e\n" +
      "CurrentDirectory: C:\\Windows\\system32\\\nUser: NT AUTHORITY\\SYSTEM";
    expect(ruleIds(message)).not.toContain("win_powershell_encoded");
  });

  it("still matches an encoded PowerShell command line", () => {
    const message = "CommandLine: powershell.exe -NoP -W Hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=";
    expect(ruleIds(message)).toContain("win_powershell_encoded");
  });

  it("still matches -EncodedCommand under pwsh", () => {
    const message = "CommandLine: pwsh -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=";
    expect(ruleIds(message)).toContain("win_powershell_encoded");
  });
});
