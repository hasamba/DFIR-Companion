// The demotion markers in veloDetectionNoise must only fire on signals an attacker cannot choose,
// and a demotion must never delete an indicator. Both halves are #720.
import { describe, it, expect } from "vitest";
import { isDetectionToolLocation, isCollectorOwnedLocation } from "../../src/analysis/veloDetectionNoise.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

describe("isDetectionToolLocation — corpus markers are full path components", () => {
  it.each([
    ["the collector install root", "C:\\Program Files\\Velociraptor\\Velociraptor.exe"],
    ["the corpus unpacked under the tool tree", "C:\\Program Files\\Velociraptor\\Tools\\tmp1\\x.evtx"],
    ["a corpus the analyst downloaded", "C:\\Users\\a\\Downloads\\EVTX-ATTACK-SAMPLES\\Lateral\\x.evtx"],
    ["the GitHub zip's -master suffix", "C:\\Users\\a\\EVTX-ATTACK-SAMPLES-master\\x.evtx"],
    ["the simulation repo", "C:\\Users\\a\\Digital-Forensic-Artifacts\\collect.ps1"],
    ["forward slashes", "/opt/Digital-Forensic-Artifacts/collect.sh"],
  ])("matches %s", (_label, path) => {
    expect(isDetectionToolLocation(path)).toBe(true);
  });

  // The bare `EVTX-ATTACK` substring matched any of these. Each is a name an intruder picks, and a
  // match here suppresses the finding — so each must miss.
  it.each([
    ["a longer word starting with the marker", "C:\\Users\\public\\EVTX-ATTACKER-kit\\evil.exe"],
    ["the marker mid-token, with no leading separator", "C:\\Temp\\my-EVTX-ATTACK-notes.exe"],
    ["the marker as a filename stem", "C:\\Users\\v\\EVTX-ATTACK.dll"],
    ["a truncated corpus name", "C:\\Users\\v\\EVTX-ATTACK-SAMP\\evil.exe"],
    ["the repo name as a longer token", "C:\\Users\\v\\Digital-Forensic-ArtifactsX\\evil.exe"],
  ])("does not match %s", (_label, path) => {
    expect(isDetectionToolLocation(path)).toBe(false);
  });
});

describe("isCollectorOwnedLocation — only the collector's own tree", () => {
  it("matches the install root", () => {
    expect(isCollectorOwnedLocation("C:\\Program Files\\Velociraptor\\Tools\\tmp1\\x.evtx")).toBe(true);
  });

  // A corpus directory is a name the attacker can supply, so it grades but never owns.
  it("does not match a sample-corpus directory", () => {
    expect(isCollectorOwnedLocation("C:\\Users\\a\\EVTX-ATTACK-SAMPLES\\x.evtx")).toBe(false);
    expect(isCollectorOwnedLocation("C:\\Users\\a\\Digital-Forensic-Artifacts\\x.ps1")).toBe(false);
  });
});

// A demotion may lower a grade. It may not delete the evidence, because the corpus markers are
// attacker-choosable: a payload under a planted EVTX-ATTACK-SAMPLES folder must still leave an IOC.
describe("mapYara self-scan — grades down without deleting indicators", () => {
  const yaraRow = (osPath: string) => ({
    _Source: "Windows.Detection.Yara.Glob",
    Rule: "DITEKSHEN_MALWARE_Win_Asyncrat",
    OSPath: osPath,
    Exe: "C:\\Users\\v\\loader.exe",
  });

  it("keeps the file and process IOCs for a hit under a sample-corpus folder", () => {
    const path = "C:\\Users\\public\\EVTX-ATTACK-SAMPLES\\evil.exe";
    const r = parseVelociraptorJson(JSON.stringify([yaraRow(path)]));
    expect(r.events[0].severity).toBe("Info");
    expect(r.iocs.some((i) => i.type === "file" && i.value === path)).toBe(true);
    expect(r.iocs.some((i) => i.type === "process" && i.value === "loader.exe")).toBe(true);
  });

  // The collector's own tree is not host evidence at all, so it keeps suppressing.
  it("still suppresses both IOCs for a hit inside the collector's own tree", () => {
    const path = "C:\\Program Files\\Velociraptor\\Tools\\tmp1\\rules\\x.exe";
    const r = parseVelociraptorJson(JSON.stringify([yaraRow(path)]));
    expect(r.events[0].severity).toBe("Info");
    expect(r.iocs.some((i) => i.type === "file" && i.value === path)).toBe(false);
    expect(r.iocs.some((i) => i.type === "process")).toBe(false);
  });
});
