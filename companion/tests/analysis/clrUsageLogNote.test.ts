import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { splitDerivedNotes } from "../../src/analysis/derivedNote.js";
import {
  CLR_USAGE_LOG_MARKER,
  CLR_USAGE_LOG_RULE_ID,
  clrUsageLogHost,
} from "../../src/analysis/clrUsageLogNote.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// A CLR usage log named after a LOLBin is the only disk trace of Cobalt Strike execute-assembly: the
// CLR writes `<host>.exe.log` the first time a process loads .NET, and rundll32 never does on its
// own (#1559). The rule grades it; the derived note tells the AI what the file means, because a
// tagger rule's description never reaches the prompt.

const RULESET = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-09-22T14:38:27.492Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const USAGE = "C:\\Users\\Recruiter\\AppData\\Local\\Microsoft\\CLR_v4.0\\UsageLogs\\";

// The shape of forensicTimeline event 2e14 in a real case: a Chainsaw/Sigma Sysmon EID 11 row the
// scenario's lure-ZIP finding swallowed. Hostname replaced.
const REAL_2E14 = ev({
  id: "2e14",
  severity: "High",
  description:
    "[Windows.EventLogs.Chainsaw] Chainsaw/Sigma: Windows Shell/Scripting Application File Write to Suspicious Folder - Sysmon File created (EID 11) - Image=C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe - TargetFilename=C:\\Users\\Public\\EggCellentResumeSim\\hosts\\WORKSTATION01\\Users\\Recruiter\\AppData\\Local\\Microsoft\\CLR_v4.0\\UsageLogs\\rundll32.exe.log @ ws01.example.com",
  path: "C:\\Users\\Public\\EggCellentResumeSim\\hosts\\WORKSTATION01\\Users\\Recruiter\\AppData\\Local\\Microsoft\\CLR_v4.0\\UsageLogs\\rundll32.exe.log",
  asset: "ws01.example.com",
  sources: ["Chainsaw"],
  artifactName: "Windows.EventLogs.Chainsaw",
});

function hitFor(e: ForensicEvent) {
  return runTagger([e], RULESET).perEvent.find((r) => r.eventId === e.id);
}

describe("tags.yaml — CLR usage log named after a LOLBin (#1559)", () => {
  it.each([
    `${USAGE}rundll32.exe.log`,
    `${USAGE}REGSVR32.EXE.LOG`,
    "C:\\Users\\a\\AppData\\Local\\Microsoft\\CLR_v2.0_32\\UsageLogs\\mshta.exe.log",
    "C:\\Users\\a\\AppData\\Local\\Microsoft\\CLR_v2.0\\UsageLogs\\dllhost.exe.log",
    `${USAGE}wmic.exe.log`,
    `${USAGE}msxsl.exe.log`,
    `${USAGE}werfault.exe.log`,
    `${USAGE}svchost.exe.log`,
    `${USAGE}notepad.exe.log`,
  ])("grades %s High with execute-assembly, T1620 and T1218.011", (path) => {
    const hit = hitFor(ev({ id: "p", path }));
    expect(hit?.ruleIds).toContain(CLR_USAGE_LOG_RULE_ID);
    expect(hit?.severity).toBe("High");
    expect(hit?.tags).toContain("execute-assembly");
    expect(hit?.mitre).toEqual(expect.arrayContaining(["T1620", "T1218.011"]));
  });

  it.each([
    `${USAGE}dotnet.exe.log`,
    `${USAGE}powershell.exe.log`,
    `${USAGE}Teams.exe.log`,
    `${USAGE}rundll32.exe.log.bak`,
    "C:\\Users\\a\\AppData\\Local\\Microsoft\\CLR_v4.0\\rundll32.exe.log",
    "C:\\Users\\a\\AppData\\Local\\Temp\\rundll32.exe.log",
    `${USAGE}myrundll32.exe.log`,
  ])("does not fire on %s", (path) => {
    expect(hitFor(ev({ id: "n", path }))?.ruleIds ?? []).not.toContain(CLR_USAGE_LOG_RULE_ID);
  });

  it("fires on the real 2e14 row", () => {
    expect(hitFor(REAL_2E14)?.ruleIds).toContain(CLR_USAGE_LOG_RULE_ID);
  });
});

describe("clrUsageLogHost", () => {
  it("names the host process from the log file name, as written on disk", () => {
    expect(clrUsageLogHost(`${USAGE}rundll32.exe.log`)).toBe("rundll32.exe");
    expect(clrUsageLogHost(`${USAGE}RegSvr32.exe.log`)).toBe("RegSvr32.exe");
  });

  it("returns null for a path the rule does not cover", () => {
    expect(clrUsageLogHost(`${USAGE}powershell.exe.log`)).toBeNull();
    expect(clrUsageLogHost(`${USAGE}dotnet.exe.log`)).toBeNull();
    expect(clrUsageLogHost(undefined)).toBeNull();
  });
});

describe("applyToForensicEvent — the CLR usage-log note reaches the description (#1559)", () => {
  it("appends a registered note naming the host process on the real 2e14 row", () => {
    const next = applyToForensicEvent(REAL_2E14, hitFor(REAL_2E14)!);
    expect(next.description).toContain(
      `${CLR_USAGE_LOG_MARKER} .NET assembly ran inside rundll32.exe — typical of Cobalt Strike execute-assembly]`,
    );
    // Registered: the split keeps it as a note, so no later clip can cut it off.
    expect(splitDerivedNotes(next.description).notes).toContain(CLR_USAGE_LOG_MARKER);
    expect(next.mitreTechniques).toEqual(expect.arrayContaining(["T1620", "T1218.011"]));
    expect(REAL_2E14.description).not.toContain(CLR_USAGE_LOG_MARKER); // input untouched
  });

  it("names the actual host, not always rundll32", () => {
    const e = ev({ id: "m", path: `${USAGE}mshta.exe.log` });
    expect(applyToForensicEvent(e, hitFor(e)!).description).toContain("ran inside mshta.exe");
  });

  it("is idempotent — a second tagger run adds no second note", () => {
    const once = applyToForensicEvent(REAL_2E14, hitFor(REAL_2E14)!);
    const twice = applyToForensicEvent(once, hitFor(once)!);
    expect(twice).toBe(once);
    expect(twice.description.split(CLR_USAGE_LOG_MARKER)).toHaveLength(2);
  });

  it("adds no note when the rule did not match, even on a usage-log path", () => {
    const e = ev({ id: "x", path: `${USAGE}rundll32.exe.log` });
    const next = applyToForensicEvent(e, {
      eventId: "x",
      tags: [],
      mitre: [],
      severity: "Low",
      ruleIds: ["some_other_rule"],
    });
    expect(next.description).not.toContain(CLR_USAGE_LOG_MARKER);
  });

  it("still adds the note on a collector-origin row, whose grade it keeps", () => {
    const e = ev({ id: "c", path: `${USAGE}rundll32.exe.log`, origin: "collector" });
    const next = applyToForensicEvent(e, hitFor(e)!);
    expect(next.severity).toBe("Info");
    expect(next.description).toContain(CLR_USAGE_LOG_MARKER);
  });
});
