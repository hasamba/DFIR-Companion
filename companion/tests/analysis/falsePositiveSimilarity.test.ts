import { describe, it, expect } from "vitest";
import { findSimilarEvents, findSimilarFindings } from "../../src/analysis/falsePositiveSimilarity.js";
import type { ForensicEvent, Finding } from "../../src/analysis/stateTypes.js";

function event(overrides: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "",
    description: "an event",
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...overrides,
  };
}

function finding(overrides: Partial<Finding> & { id: string; title: string }): Finding {
  return {
    severity: "Low",
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
    ...overrides,
  };
}

describe("findSimilarEvents", () => {
  it("scores shared MITRE technique + same process above the default threshold", () => {
    const anchor = event({ id: "e1", mitreTechniques: ["T1569.002"], processName: "PsExec.exe" });
    const candidates = [
      event({ id: "e2", mitreTechniques: ["T1569.002"], processName: "PsExec.exe" }), // strong match
      event({ id: "e3", mitreTechniques: ["T1059.001"], processName: "powershell.exe" }), // no overlap
    ];
    const out = findSimilarEvents(anchor, candidates);
    expect(out.map((c) => c.id)).toEqual(["e2"]);
    expect(out[0].reasons.some((r) => r.includes("T1569.002"))).toBe(true);
    expect(out[0].reasons.some((r) => r.includes("PsExec.exe"))).toBe(true);
  });

  it("weighs a shared hash the highest and never returns the anchor itself", () => {
    const anchor = event({ id: "e1", sha256: "abc123" });
    const candidates = [event({ id: "e1", sha256: "abc123" }), event({ id: "e2", sha256: "abc123" })];
    const out = findSimilarEvents(anchor, candidates);
    expect(out.map((c) => c.id)).toEqual(["e2"]);
    expect(out[0].score).toBeGreaterThanOrEqual(3);
  });

  it("drops candidates below the minimum score", () => {
    const anchor = event({ id: "e1", asset: "HOST-A" });
    const candidates = [event({ id: "e2", asset: "HOST-A" })]; // asset-only overlap is weak
    expect(findSimilarEvents(anchor, candidates, { minScore: 2 })).toEqual([]);
  });

  it("caps results at maxResults, highest score first", () => {
    const anchor = event({ id: "e1", mitreTechniques: ["T1569"] });
    const candidates = Array.from({ length: 30 }, (_, i) =>
      event({ id: `e${i + 2}`, mitreTechniques: ["T1569"] }),
    );
    const out = findSimilarEvents(anchor, candidates, { maxResults: 5 });
    expect(out).toHaveLength(5);
  });

  it("returns no match for a zero-signal pair (no comparable fields on either side)", () => {
    const anchor = event({ id: "e1" });
    const candidates = [event({ id: "e2" })];
    expect(findSimilarEvents(anchor, candidates)).toEqual([]);
  });

  it("never suggests an event on host + source tool alone — that is context, not the same result", () => {
    const anchor = event({
      id: "e1",
      asset: "HOST-A",
      sources: ["Velociraptor"],
      description:
        "Velociraptor [DetectRaptor.Windows.Detection.Webhistory]: Phishing Hosting — www.canva.com - @ HOST-A",
    });
    const candidates = [
      event({
        id: "e2",
        asset: "HOST-A",
        sources: ["Velociraptor"],
        description: "Velociraptor [Windows.Detection.Malfind]: OUTLOOK.EXE - @ HOST-A",
      }),
      event({ id: "e3", asset: "HOST-A", sources: ["Velociraptor"], description: "Process created" }),
    ];
    expect(findSimilarEvents(anchor, candidates)).toEqual([]);
  });

  it("suggests only events with the same detection result (same rule and same matched value)", () => {
    const web = (id: string, domain: string, host: string, url = ""): ForensicEvent =>
      event({
        id,
        asset: host,
        sources: ["Velociraptor"],
        description:
          `Velociraptor [DetectRaptor.Windows.Detection.Webhistory]: Phishing Hosting — ${domain}` +
          (url ? ` - URL: ${url} @ ${host}` : ` - @ ${host}`),
      });
    const anchor = web("e1", "drive.google.com", "HOST-A");
    const candidates = [
      web("e2", "drive.google.com", "HOST-B", "https://drive.google.com/file/x"), // same result
      web("e3", "www.canva.com", "HOST-A"), // same rule, different domain
      web("e4", "DRIVE.GOOGLE.COM", "HOST-A"), // same result, case differs
    ];
    const out = findSimilarEvents(anchor, candidates);
    expect(out.map((c) => c.id).sort()).toEqual(["e2", "e4"]);
    expect(out[0].reasons.some((r) => r.startsWith("same detection"))).toBe(true);
  });

  it("does not let a shared MITRE technique pull in a different detection result", () => {
    const anchor = event({
      id: "e1",
      mitreTechniques: ["T1566"],
      description:
        "Velociraptor [DetectRaptor.Windows.Detection.Webhistory]: Phishing Hosting — drive.google.com",
    });
    const candidates = [
      event({
        id: "e2",
        mitreTechniques: ["T1566"],
        description:
          "Velociraptor [DetectRaptor.Windows.Detection.Webhistory]: Phishing Hosting — www.canva.com",
      }),
    ];
    expect(findSimilarEvents(anchor, candidates)).toEqual([]);
  });

  it("still suggests a different detection that carries the same file hash", () => {
    const anchor = event({
      id: "e1",
      sha256: "abc123",
      description: "Velociraptor [Windows.Detection.Yara]: rule_a — evil.dll",
    });
    const candidates = [
      event({
        id: "e2",
        sha256: "abc123",
        description: "THOR Alert [Filescan]: Malware file found — evil.dll",
      }),
    ];
    expect(findSimilarEvents(anchor, candidates).map((c) => c.id)).toEqual(["e2"]);
  });

  it("returns [] for an empty candidates array without throwing", () => {
    const anchor = event({ id: "e1", mitreTechniques: ["T1569"], sha256: "abc123" });
    expect(() => findSimilarEvents(anchor, [])).not.toThrow();
    expect(findSimilarEvents(anchor, [])).toEqual([]);
  });
});

describe("findSimilarFindings", () => {
  it("scores shared MITRE technique and overlapping related IOCs", () => {
    const anchor = finding({
      id: "f1",
      title: "PsExec lateral movement",
      mitreTechniques: ["T1569.002"],
      relatedIocs: ["i1"],
    });
    const candidates = [
      finding({
        id: "f2",
        title: "PsExec use on FILE-02",
        mitreTechniques: ["T1569.002"],
        relatedIocs: ["i1"],
      }),
      finding({
        id: "f3",
        title: "Unrelated persistence finding",
        mitreTechniques: ["T1547"],
        relatedIocs: [],
      }),
    ];
    const out = findSimilarFindings(anchor, candidates);
    expect(out.map((c) => c.id)).toEqual(["f2"]);
  });

  it("never returns the anchor itself even if present in candidates", () => {
    const anchor = finding({ id: "f1", title: "X", mitreTechniques: ["T1569"] });
    const out = findSimilarFindings(anchor, [anchor]);
    expect(out).toEqual([]);
  });

  it("returns no match for a zero-signal pair (no MITRE, no IOCs, no long title words)", () => {
    const anchor = finding({ id: "f1", title: "IP to IP" });
    const candidates = [finding({ id: "f2", title: "IP to IP" })];
    expect(findSimilarFindings(anchor, candidates)).toEqual([]);
  });

  it("returns [] for an empty candidates array without throwing", () => {
    const anchor = finding({ id: "f1", title: "PsExec lateral movement", mitreTechniques: ["T1569.002"] });
    expect(() => findSimilarFindings(anchor, [])).not.toThrow();
    expect(findSimilarFindings(anchor, [])).toEqual([]);
  });

  it("short titles with no words >=4 chars contribute nothing to the score (no crash, no false match)", () => {
    const anchor = finding({ id: "f1", title: "IP to IP", mitreTechniques: [] });
    const candidates = [finding({ id: "f2", title: "A to B", mitreTechniques: [] })];
    expect(findSimilarFindings(anchor, candidates)).toEqual([]);
  });
});
