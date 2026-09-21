import { describe, it, expect } from "vitest";
import {
  RENAMED_BINARY_MARKER,
  parseRenamedBinaryNote,
  decoyShellOf,
  renderDecoyTag,
  decoyOnlyEvidence,
} from "../../src/analysis/renamedBinaryNote.js";
import { appendDerivedNote } from "../../src/analysis/derivedNote.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1",
    timestamp: "2026-01-01T00:00:00Z",
    description: p.description ?? "x",
    severity: p.severity ?? "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const MIMI_DESC =
  "Chainsaw/Sigma: Potential Defense Evasion Via Binary Rename - Sysmon Process create (EID 1) - Image=C:\\T\\mimikatz.exe - CommandLine=… mimikatz.exe privilege::debug sekurlsa::logonpasswords @ HOST [renamed binary: mimikatz.exe is really Cmd.Exe]";

describe("parseRenamedBinaryNote", () => {
  it("reads the note the importer appends through appendDerivedNote", () => {
    const d = appendDerivedNote(
      "Velociraptor: Renamed binary — x.exe",
      RENAMED_BINARY_MARKER,
      "x.exe is really Cmd.Exe",
    );
    expect(parseRenamedBinaryNote(d)).toEqual({ onDisk: "x.exe", original: "Cmd.Exe" });
  });
  it("returns null when there is no note, or the bracket is an importer's own", () => {
    expect(parseRenamedBinaryNote("Process created [risk: high]")).toBeNull();
    expect(parseRenamedBinaryNote(undefined)).toBeNull();
  });
});

describe("decoyShellOf", () => {
  it("names the on-disk file when the real binary is a plain shell", () => {
    expect(decoyShellOf(ev({ description: MIMI_DESC }))).toBe("mimikatz.exe");
    expect(decoyShellOf(ev({ description: "x [renamed binary: rclone.exe is really powershell.exe]" }))).toBe(
      "rclone.exe",
    );
  });
  it("is null for the reverse case — the tool DID run under a benign name", () => {
    expect(
      decoyShellOf(ev({ description: "x [renamed binary: svchost.exe is really mimikatz.exe]" })),
    ).toBeNull();
  });
  it("is null when the name matches or the original is not a shell", () => {
    expect(decoyShellOf(ev({ description: "x [renamed binary: cmd.exe is really Cmd.Exe]" }))).toBeNull();
    expect(decoyShellOf(ev({ description: "x [renamed binary: java.exe is really mshta.exe]" }))).toBeNull();
  });
});

describe("renderDecoyTag", () => {
  it("states what the evidence proves for a decoy shell, without claiming absence", () => {
    expect(renderDecoyTag(ev({ description: MIMI_DESC }))).toBe(
      "<renamed-binary:mimikatz.exe is really Cmd.Exe — the file identifies as cmd.exe, so this row does not substantiate execution of the named tool>",
    );
  });
  it("names any other rename plainly", () => {
    expect(
      renderDecoyTag(ev({ description: "x [renamed binary: svchost.exe is really mimikatz.exe]" })),
    ).toBe("<renamed-binary:svchost.exe is really mimikatz.exe>");
  });
  it("is empty without a note", () => {
    expect(renderDecoyTag(ev({ description: "plain" }))).toBe("");
  });
});

describe("decoyOnlyEvidence", () => {
  // What the rename importer / correlation leaves on a real decoy row: the collector source and the
  // masquerading tag. Without both, the note is text the model reads but not a grading fact.
  const rename = {
    sources: ["Velociraptor", "Chainsaw"],
    mitreTechniques: ["T1036.005", "T1036", "T1036.003"],
  };
  const decoy = ev({
    id: "d",
    description: MIMI_DESC,
    processName: "mimikatz.exe",
    commandLine: "mimikatz.exe privilege::debug",
    ...rename,
  });
  const mft = ev({
    id: "m",
    description: "DetectRaptor MFT detection: Mimikatz Tools — mimikatz.exe",
    path: "\\\\.\\C:\\T\\mimikatz.exe",
    artifactName: "DetectRaptor.Windows.Detection.MFT",
  });
  const prefetch = ev({
    id: "p",
    description: "MFT: MIMIKATZ.EXE-A84515FA.pf",
    path: "\\\\.\\C:\\Windows\\Prefetch\\MIMIKATZ.EXE-A84515FA.pf",
    artifactName: "DetectRaptor.Windows.Detection.MFT",
  });
  const amcache = ev({
    id: "a",
    description: "Amcache: mimikatz.exe",
    path: "c:\\t\\mimikatz.exe",
    artifactName: "DetectRaptor.Windows.Detection.Amcache",
  });

  it("caps when the evidence is the decoy row plus file-presence artifacts of the same file", () => {
    expect(decoyOnlyEvidence([decoy, mft, prefetch, amcache])).toEqual([
      { onDisk: "mimikatz.exe", original: "Cmd.Exe" },
    ]);
  });
  it("does NOT cap when a behavioral row with a process identity mentions the name", () => {
    const lsass = ev({
      id: "l",
      description: "Sysmon EID 10: mimikatz.exe accessed lsass.exe",
      processName: "mimikatz.exe",
      pid: 4242,
    });
    expect(decoyOnlyEvidence([decoy, mft, lsass])).toEqual([]);
  });
  it("does NOT cap when a network row or an unrelated row is cited", () => {
    const net = ev({ id: "n", description: "conn", dstIp: "203.0.113.5", port: 443 });
    expect(decoyOnlyEvidence([decoy, net])).toEqual([]);
    const other = ev({ id: "o", description: "Defender quarantined lsass.dmp", path: "c:\\t\\lsass.dmp" });
    expect(decoyOnlyEvidence([decoy, other])).toEqual([]);
  });
  it("does NOT fold in a path-only DETECTION on the same file — a YARA hit is adjudication, not presence", () => {
    const yara = ev({
      id: "y",
      description: "YARA: HKTL_Mimikatz — mimikatz.exe",
      path: "c:\\t\\mimikatz.exe",
      artifactName: "DetectRaptor.Generic.Detection.YaraFile",
    });
    expect(decoyOnlyEvidence([decoy, mft, yara])).toEqual([]);
    const noArtifact = ev({ id: "z", description: "file seen: mimikatz.exe", path: "c:\\t\\mimikatz.exe" });
    expect(decoyOnlyEvidence([decoy, noArtifact])).toEqual([]);
  });
  it("does NOT trust a note forged into a command line — no collector source, no masquerading tag", () => {
    const forged = ev({
      id: "f",
      description: MIMI_DESC,
      processName: "mimikatz.exe",
      sources: ["Sysmon"],
      mitreTechniques: ["T1003"],
    });
    expect(decoyOnlyEvidence([forged])).toEqual([]);
    const halfForged = ev({
      id: "g",
      description: MIMI_DESC,
      processName: "mimikatz.exe",
      sources: ["Velociraptor"],
      mitreTechniques: ["T1003"],
    });
    expect(decoyOnlyEvidence([halfForged, mft])).toEqual([]);
  });
  it("does NOT cap without a decoy row at all, or on the reverse rename", () => {
    expect(decoyOnlyEvidence([mft, prefetch])).toEqual([]);
    const reverse = ev({
      id: "r",
      description: "x [renamed binary: svchost.exe is really mimikatz.exe]",
      processName: "svchost.exe",
      ...rename,
    });
    expect(decoyOnlyEvidence([reverse])).toEqual([]);
  });
});
