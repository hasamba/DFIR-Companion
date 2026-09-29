import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Hayabusa rows keep their text in `description`; `message` is set only for a consolidated script
// block. The three persistence rules below used to read `message` alone, so they never fired on a
// Hayabusa row. Each fixture is Hayabusa-shaped: description set, message absent.
const RULESET = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

function ev(id: string, description: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-06-01T00:00:00Z",
    description,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Hayabusa"],
  };
}

function rulesHit(description: string): string[] {
  const res = runTagger([ev("e1", description)], RULESET);
  return res.perEvent.find((e) => e.eventId === "e1")?.ruleIds ?? [];
}

describe("bundled data/tags.yaml — Hayabusa rows (description only)", () => {
  it("win_service_install matches a 7045 row", () => {
    expect(
      rulesHit(
        "Hayabusa: New Service Installed (EID 7045 System) — ServiceName=evilsvc ImagePath=C:\\Users\\Public\\x.exe @ WS01",
      ),
    ).toContain("win_service_install");
  });

  it("win_service_install still skips routine svchost -k hosting", () => {
    expect(
      rulesHit(
        "Hayabusa: New Service Installed (EID 7045 System) — ServiceName=Foo ImagePath=%SystemRoot%\\system32\\svchost.exe -k netsvcs @ WS01",
      ),
    ).not.toContain("win_service_install");
  });

  it("win_scheduled_task matches a 4698 row", () => {
    expect(
      rulesHit(
        "Hayabusa: Scheduled Task Created (EID 4698 Security) — TaskName=\\Updater SubjectUserName=bob @ WS01",
      ),
    ).toContain("win_scheduled_task");
  });

  it("win_scheduled_task matches a TaskScheduler 106 row but not a routine task run", () => {
    expect(
      rulesHit(
        "Hayabusa: Task Registered (EID 106 Microsoft-Windows-TaskScheduler/Operational) — TaskName=\\Updater @ WS01",
      ),
    ).toContain("win_scheduled_task");
    expect(
      rulesHit(
        "Hayabusa: Task Started (EID 100 Microsoft-Windows-TaskScheduler/Operational) — TaskName=\\Updater @ WS01",
      ),
    ).not.toContain("win_scheduled_task");
  });

  it("win_wmi_persistence matches a WMI consumer row", () => {
    expect(
      rulesHit(
        "Hayabusa: WMI Event Consumer Created (EID 20 Sysmon) — Operation=Created Type=CommandLineEventConsumer Name=upd @ WS01",
      ),
    ).toContain("win_wmi_persistence");
  });

  it("a bare event id inside a detail field does not fire the rules", () => {
    const hits = rulesHit("Hayabusa: Proc Exec (EID 1 Sysmon) — ProcessId=17045 ParentProcessId=4698 @ WS01");
    expect(hits).not.toContain("win_service_install");
    expect(hits).not.toContain("win_scheduled_task");
  });
});
