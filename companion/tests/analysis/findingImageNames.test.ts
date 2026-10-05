import { describe, it, expect } from "vitest";
import { exeLeavesIn, claimedImagesNotInEvidence } from "../../src/analysis/findingImageNames.js";
import {
  groundAndScoreFindings,
  CONTENT_MISMATCH_CONFIDENCE_CAP,
} from "../../src/analysis/findingGrounding.js";
import type { Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";

function f(p: Partial<Finding>): Finding {
  return {
    id: "f1",
    severity: "High",
    title: "A finding",
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
    confidence: 90,
    ...p,
  };
}
function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-01-01T00:00:00Z",
    description: "process ran",
    severity: "High",
    mitreTechniques: [],
    ...p,
  } as ForensicEvent;
}

describe("exeLeavesIn (#1954)", () => {
  it("returns the lowercased leaf of a path", () => {
    expect(exeLeavesIn(String.raw`ran C:\Tools\Evil.EXE -x`)).toEqual(["evil.exe"]);
    expect(exeLeavesIn("/mnt/c/windows/system32/cmd.exe")).toEqual(["cmd.exe"]);
  });
  it("does not match a longer name, a .com host, or a renamed .exe.bak", () => {
    expect(exeLeavesIn("data.exe")).toEqual(["data.exe"]);
    expect(exeLeavesIn("data.exe")).not.toContain("a.exe");
    expect(exeLeavesIn("beacon to evil.example.com")).toEqual([]);
    expect(exeLeavesIn("payload.exe.bak")).toEqual([]);
  });
  it("matches a name at the end of a sentence and de-duplicates", () => {
    expect(exeLeavesIn("It ran b.exe. Then B.exe again.")).toEqual(["b.exe"]);
  });
});

describe("claimedImagesNotInEvidence (#1954)", () => {
  it("flags a name no cited row carries", () => {
    const out = claimedImagesNotInEvidence(f({ description: "a.exe ran the echoed commands" }), [
      ev({ processName: "b.exe" }),
    ]);
    expect(out).toEqual(["a.exe"]);
  });
  it("accepts a name carried as the parent image", () => {
    const out = claimedImagesNotInEvidence(f({ title: "a.exe spawned a shell" }), [
      ev({ processName: "cmd.exe", parentName: String.raw`C:\Tools\a.exe` }),
    ]);
    expect(out).toEqual([]);
  });
  it("accepts a name carried only in the command line", () => {
    const out = claimedImagesNotInEvidence(f({ description: "a.exe was launched" }), [
      ev({ processName: "cmd.exe", commandLine: String.raw`cmd /c C:\x\a.exe -dump` }),
    ]);
    expect(out).toEqual([]);
  });
  it("skips a negated name", () => {
    const out = claimedImagesNotInEvidence(
      f({ description: "Unlike b.exe, this binary c.exe ran from Temp" }),
      [ev({ processName: "c.exe" })],
    );
    expect(out).toEqual([]);
  });
  it("skips a hedged name", () => {
    const out = claimedImagesNotInEvidence(
      f({ description: "Dump tools such as procdump.exe are often used; here x.exe ran" }),
      [ev({ processName: "x.exe" })],
    );
    expect(out).toEqual([]);
    expect(
      claimedImagesNotInEvidence(f({ description: "a dumper, e.g. procdump.exe, ran" }), [
        ev({ processName: "x.exe" }),
      ]),
    ).toEqual([]);
  });
  it("stops the look-back window at a clause break", () => {
    const out = claimedImagesNotInEvidence(f({ description: "Unlike svchost.exe, this binary b.exe ran" }), [
      ev({ processName: "c.exe" }),
    ]);
    expect(out).toEqual(["b.exe"]);
  });
  it("lets a renamed-binary row satisfy either name", () => {
    const row = ev({
      processName: "mimikatz.exe",
      description: "mimikatz.exe ran [renamed binary: mimikatz.exe is really Cmd.Exe]",
    });
    expect(claimedImagesNotInEvidence(f({ title: "mimikatz.exe dumped creds" }), [row])).toEqual([]);
    expect(claimedImagesNotInEvidence(f({ title: "cmd.exe echoed the command" }), [row])).toEqual([]);
  });
});

describe("groundAndScoreFindings program-name gate (#1954)", () => {
  const run = (fs: Finding[], events: ForensicEvent[]) =>
    groundAndScoreFindings({
      findings: fs,
      scopedEvents: events,
      iocs: [],
      graphLinkedEventIds: new Set(),
    });

  it("floors a High finding naming a program no cited row carries", () => {
    const [out] = run(
      [f({ description: "a.exe ran the echoed commands", relatedEventIds: ["e1"] })],
      [ev({ processName: "b.exe" })],
    );
    expect(out.contentMismatch).toBe(true);
    expect(out.severity).toBe("Medium");
    expect(out.confidence).toBeLessThanOrEqual(CONTENT_MISMATCH_CONFIDENCE_CAP);
    expect(out.confidenceReason).toMatch(/a\.exe/);
    expect(out.confidenceReason).toMatch(/the cited rows show b\.exe/);
  });
  it("leaves a Medium finding unflagged", () => {
    const [out] = run(
      [f({ severity: "Medium", description: "a.exe ran", relatedEventIds: ["e1"] })],
      [ev({ processName: "b.exe" })],
    );
    expect(out.contentMismatch).toBeUndefined();
  });
  it("does not flag when the parent image matches", () => {
    const [out] = run(
      [f({ description: "a.exe spawned cmd.exe", relatedEventIds: ["e1"] })],
      [ev({ processName: "cmd.exe", parentName: "a.exe" })],
    );
    expect(out.contentMismatch).toBeUndefined();
    expect(out.severity).toBe("High");
  });
  it("applies one floor with both reasons when IP and program both mismatch", () => {
    const [out] = run(
      [f({ description: "a.exe connected to 10.9.9.9", relatedEventIds: ["e1"] })],
      [ev({ processName: "b.exe", description: "b.exe connected to 10.1.1.1" })],
    );
    expect(out.severity).toBe("Medium");
    expect(out.confidenceReason).toMatch(/10\.9\.9\.9/);
    expect(out.confidenceReason).toMatch(/names a\.exe/);
  });
  it("is idempotent on its own output", () => {
    const events = [ev({ processName: "b.exe" })];
    const once = run([f({ description: "a.exe ran", relatedEventIds: ["e1"] })], events);
    const twice = run(once, events);
    expect(twice[0].severity).toBe(once[0].severity);
    expect(twice[0].confidence).toBe(once[0].confidence);
    expect(twice[0].confidenceReason).toBe(once[0].confidenceReason);
  });
});
