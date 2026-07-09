import { describe, it, expect } from "vitest";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

const baseDelta: AnalysisDelta = {
  findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
  timelineNote: "", summary: "",
};

describe("mergeDelta", () => {
  it("adds a new finding with firstSeen and lastUpdated", () => {
    const state = emptyState("c1");
    const next = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "v1",
        relatedIocs: [], mitreTechniques: ["T1059"], status: "open" }],
      timelineNote: "window 1", summary: "s1",
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["000001_t.webp"] });

    expect(next.findings).toHaveLength(1);
    expect(next.findings[0].firstSeen).toBe("2026-05-28T10:00:00.000Z");
    expect(next.findings[0].lastUpdated).toBe("2026-05-28T10:00:00.000Z");
    expect(state.findings).toHaveLength(0); // original not mutated
  });

  it("updates an existing finding by id instead of duplicating (revisit)", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "Medium", title: "PS abuse", description: "v1",
        relatedIocs: [], mitreTechniques: [], status: "open" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["a.webp"] });

    state = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "v2 escalated",
        relatedIocs: ["i1"], mitreTechniques: ["T1059"], status: "confirmed" }],
    }, { windowSequence: 5, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: ["b.webp"] });

    expect(state.findings).toHaveLength(1);
    const f = state.findings[0];
    expect(f.severity).toBe("High");
    expect(f.description).toBe("v2 escalated");
    expect(f.status).toBe("confirmed");
    expect(f.firstSeen).toBe("2026-05-28T10:00:00.000Z"); // preserved
    expect(f.lastUpdated).toBe("2026-05-28T10:05:00.000Z"); // refreshed
    expect(f.relatedIocs).toContain("i1");
    expect(f.sourceScreenshots).toEqual(["a.webp", "b.webp"]); // accumulated, deduped
  });

  it("carries confidence + confidenceReason through both the new-finding and update branches", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", confidence: 60, confidenceReason: "One uncorroborated hit",
        title: "PS abuse", description: "v1", relatedIocs: [], mitreTechniques: [], status: "open" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });
    expect(state.findings[0].confidence).toBe(60);
    expect(state.findings[0].confidenceReason).toBe("One uncorroborated hit");

    state = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", confidence: 90, confidenceReason: "Now corroborated by a second tool",
        title: "PS abuse", description: "v2", relatedIocs: [], mitreTechniques: [], status: "confirmed" }],
    }, { windowSequence: 2, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: [] });
    expect(state.findings[0].confidence).toBe(90);
    expect(state.findings[0].confidenceReason).toBe("Now corroborated by a second tool");
  });

  it("carries relatedEventIds through both the new-finding and update branches, deduped", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "v1",
        relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: ["e1", "e2"] }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });
    expect(state.findings[0].relatedEventIds).toEqual(["e1", "e2"]);

    state = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "v2",
        relatedIocs: [], mitreTechniques: [], status: "confirmed", relatedEventIds: ["e2", "e3"] }],
    }, { windowSequence: 2, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: [] });
    expect(state.findings[0].relatedEventIds).toEqual(["e1", "e2", "e3"]);
  });

  it("leaves relatedEventIds undefined when the delta omits it (extraction deltas never set it)", () => {
    const state = emptyState("c1");
    const next = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "v1",
        relatedIocs: [], mitreTechniques: [], status: "open" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });
    expect(next.findings[0].relatedEventIds).toBeUndefined();
  });

  it("dedupes IOCs by value and closes threads", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i1", type: "ip", value: "10.0.0.5" }],
      threadsOpened: [{ id: "t1", description: "trace lateral movement" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });

    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i2", type: "ip", value: "10.0.0.5" }], // same value
      threadsClosed: ["t1"],
    }, { windowSequence: 2, timestamp: "2026-05-28T10:01:00.000Z", sourceScreenshots: [] });

    expect(state.iocs).toHaveLength(1);
    expect(state.iocs[0].id).toBe("i001"); // canonical 3-digit id
    expect(state.openThreads[0].status).toBe("closed");
    expect(state.openThreads[0].closedAt).toBe("2026-05-28T10:01:00.000Z");
  });

  it("dedupes IOCs case-insensitively — the same hostname/domain often arrives with different casing across importers/rows", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i1", type: "domain", value: "DESKTOP-MNNUHHU.localdomain" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });

    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i1", type: "domain", value: "desktop-mnnuhhu.localdomain" }], // same value, different case
    }, { windowSequence: 2, timestamp: "2026-05-28T10:01:00.000Z", sourceScreenshots: [] });

    expect(state.iocs).toHaveLength(1);
    expect(state.iocs[0].value).toBe("DESKTOP-MNNUHHU.localdomain"); // first-seen casing wins
  });

  it("drops an incoming IOC that matches a per-case exclude rule — never created, so it can't be enriched", () => {
    const state = {
      ...emptyState("c1"),
      iocExcludeRules: [{ id: "r1", match: "suffix" as const, pattern: ".lan", addedAt: "2026-01-01T00:00:00Z" }],
    };
    const next = mergeDelta(state, {
      ...baseDelta,
      iocs: [
        { id: "i1", type: "domain", value: "CLIENT01.lan" },
        { id: "i2", type: "ip", value: "10.0.0.5" },
      ],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });

    expect(next.iocs).toHaveLength(1);
    expect(next.iocs[0].value).toBe("10.0.0.5");
  });

  it("a finding referencing an excluded IOC's id doesn't throw — the reference just dangles harmlessly", () => {
    const state = {
      ...emptyState("c1"),
      iocExcludeRules: [{ id: "r1", match: "exact" as const, pattern: "client01.lan", addedAt: "2026-01-01T00:00:00Z" }],
    };
    const next = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i1", type: "domain", value: "client01.lan" }],
      findings: [{ id: "f1", severity: "Low", title: "t", description: "d", relatedIocs: ["i1"], mitreTechniques: [], status: "open" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });

    expect(next.iocs).toHaveLength(0);
    expect(next.findings[0].relatedIocs).toEqual(["i1"]); // dangling id, but no crash
  });

  it("assigns canonical 3-digit ids and remaps finding.relatedIocs even when the model reuses ids", () => {
    // The vision model often groups its output per-finding and emits i1/i2/i3
    // multiple times with different values. We must give each unique-value IOC
    // its own id and rewrite the finding's relatedIocs to match.
    const state = mergeDelta(emptyState("c1"), {
      ...baseDelta,
      iocs: [
        { id: "i1", type: "file", value: "Bubeus.exe" },
        { id: "i2", type: "file", value: "SharpHound.exe" },
        { id: "i1", type: "file", value: "Rubeus.exe" },     // model reused i1
        { id: "i2", type: "file", value: "mimikatz.exe" },   // model reused i2
        { id: "i1", type: "file", value: "Bubeus.exe" },     // duplicate value → dropped
      ],
      findings: [
        { id: "f1", severity: "High", title: "credential dumping", description: "...",
          relatedIocs: ["i1", "i2"], // refers to the FIRST i1/i2 the model emitted in the same response
          mitreTechniques: [], status: "confirmed" },
        { id: "f2", severity: "High", title: "AD recon", description: "...",
          relatedIocs: ["i2"], // ambiguous in the model's view; remapped to the *first* matching emission
          mitreTechniques: [], status: "open" },
      ],
    }, { windowSequence: 1, timestamp: "2026-06-01T10:00:00.000Z", sourceScreenshots: [] });

    expect(state.iocs.map((i) => i.id)).toEqual(["i001", "i002", "i003", "i004"]);
    expect(state.iocs.map((i) => i.value)).toEqual([
      "Bubeus.exe", "SharpHound.exe", "Rubeus.exe", "mimikatz.exe",
    ]);
    // First i1 = Bubeus → i001; first i2 = SharpHound → i002. relatedIocs rewritten.
    const f1 = state.findings.find((f) => f.id === "f1")!;
    expect(f1.relatedIocs).toEqual(["i001", "i002"]);
  });

  it("continues IOC numbering from the highest existing canonical id", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [
        { id: "i1", type: "ip", value: "10.0.0.5" },
        { id: "i2", type: "ip", value: "10.0.0.6" },
      ],
    }, { windowSequence: 1, timestamp: "2026-06-01T10:00:00.000Z", sourceScreenshots: [] });
    expect(state.iocs.map((i) => i.id)).toEqual(["i001", "i002"]);

    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i1", type: "ip", value: "10.0.0.7" }], // new value, model reused i1
    }, { windowSequence: 2, timestamp: "2026-06-01T10:01:00.000Z", sourceScreenshots: [] });

    expect(state.iocs.map((i) => i.id)).toEqual(["i001", "i002", "i003"]);
  });

  it("appends a timeline entry per window", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, { ...baseDelta, timelineNote: "did X" },
      { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["a.webp"] });
    expect(state.timeline).toHaveLength(1);
    expect(state.timeline[0].description).toBe("did X");
    expect(state.timeline[0].windowSequence).toBe(1);
  });

  it("replaces key questions wholesale when synthesis provides them, keeps them otherwise", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      keyQuestions: [
        { id: "q1", question: "Initial access?", status: "unknown", answer: "", pointer: "collect email logs" },
      ],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });
    expect(state.keyQuestions).toHaveLength(1);
    expect(state.keyQuestions[0].status).toBe("unknown");

    // A later synthesis updates the answer set (replace, not append).
    state = mergeDelta(state, {
      ...baseDelta,
      keyQuestions: [
        { id: "q1", question: "Initial access?", status: "answered", answer: "phishing", pointer: "finding f3" },
      ],
    }, { windowSequence: 2, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: [] });
    expect(state.keyQuestions).toHaveLength(1);
    expect(state.keyQuestions[0].status).toBe("answered");
    expect(state.keyQuestions[0].answer).toBe("phishing");

    // A per-window delta with no keyQuestions must NOT wipe them.
    state = mergeDelta(state, { ...baseDelta }, { windowSequence: 3, timestamp: "2026-05-28T10:10:00.000Z", sourceScreenshots: [] });
    expect(state.keyQuestions).toHaveLength(1);
  });

  it("replaces next steps wholesale when synthesis provides them, keeps them otherwise", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      nextSteps: [
        { id: "n1", priority: "high", action: "Pull $MFT on ALClient07", rationale: "confirm execution", pointer: "event e3" },
      ],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });
    expect(state.nextSteps).toHaveLength(1);
    expect(state.nextSteps[0].priority).toBe("high");

    // A later synthesis re-prioritizes (replace, not append).
    state = mergeDelta(state, {
      ...baseDelta,
      nextSteps: [
        { id: "n2", priority: "critical", action: "Sandbox-detonate Bubeus.exe", rationale: "find C2", pointer: "ioc i2" },
      ],
    }, { windowSequence: 2, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: [] });
    expect(state.nextSteps).toHaveLength(1);
    expect(state.nextSteps[0].priority).toBe("critical");
    expect(state.nextSteps[0].action).toBe("Sandbox-detonate Bubeus.exe");

    // A per-window delta with no nextSteps must NOT wipe them.
    state = mergeDelta(state, { ...baseDelta }, { windowSequence: 3, timestamp: "2026-05-28T10:10:00.000Z", sourceScreenshots: [] });
    expect(state.nextSteps).toHaveLength(1);
  });

  it("drops tool-usage narration from forensic events at merge time", () => {
    const state = mergeDelta(emptyState("c1"), {
      ...baseDelta,
      forensicEvents: [
        { id: "e1", timestamp: "2026-06-01T10:55:41Z", description: "Velociraptor Response and Monitoring session continued.",
          severity: "Info", mitreTechniques: [], relatedFindingIds: [] },
        { id: "e2", timestamp: "2026-06-01T10:56:13Z", description: "Suspicious Epmap Connection entry detected.",
          severity: "High", mitreTechniques: ["T1218.011"], relatedFindingIds: [] },
      ],
    }, { windowSequence: 1, timestamp: "2026-06-01T10:56:13Z", sourceScreenshots: ["s.webp"] });

    expect(state.forensicTimeline).toHaveLength(1);
    expect(state.forensicTimeline[0].description).toContain("Epmap");
  });

  it("merges forensic events, dedupes by id, and keeps them sorted by event time", () => {
    let state = emptyState("c1");
    // First window contributes a later event (15:00).
    state = mergeDelta(state, {
      ...baseDelta,
      forensicEvents: [{ id: "e2", timestamp: "2026-05-20T15:00:00Z", description: "encryptor ran",
        severity: "Critical", mitreTechniques: ["T1486"], relatedFindingIds: ["f1"] }],
      attackerPath: "phishing then ransomware",
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["s2.webp"] });

    // Second window contributes an EARLIER event (09:00) — must sort before e2.
    state = mergeDelta(state, {
      ...baseDelta,
      forensicEvents: [{ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "phish opened",
        severity: "High", mitreTechniques: ["T1566"], relatedFindingIds: [] }],
    }, { windowSequence: 2, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: ["s1.webp"] });

    expect(state.forensicTimeline).toHaveLength(2);
    expect(state.forensicTimeline.map((e) => e.id)).toEqual(["e1", "e2"]); // chronological
    expect(state.attackerPath).toBe("phishing then ransomware");          // preserved when new delta omits it

    // Re-reporting e1 updates in place (no duplicate) and accumulates evidence.
    state = mergeDelta(state, {
      ...baseDelta,
      forensicEvents: [{ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "phish opened (confirmed)",
        severity: "High", mitreTechniques: ["T1566.001"], relatedFindingIds: ["f2"] }],
    }, { windowSequence: 3, timestamp: "2026-05-28T10:10:00.000Z", sourceScreenshots: ["s3.webp"] });

    expect(state.forensicTimeline).toHaveLength(2);
    const e1 = state.forensicTimeline.find((e) => e.id === "e1")!;
    expect(e1.description).toBe("phish opened (confirmed)");
    expect(e1.mitreTechniques).toContain("T1566.001");
    expect(e1.sourceScreenshots).toEqual(["s1.webp", "s3.webp"]);
  });

  it("carries message + veloUrl through both the push and update forensic-event branches (#8/#9)", () => {
    let state = emptyState("c1");
    // Push branch: a NEW event with message + veloUrl.
    state = mergeDelta(state, {
      ...baseDelta,
      forensicEvents: [{ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "MFT: created evil.exe",
        severity: "Info", mitreTechniques: [], relatedFindingIds: [],
        message: "FULL rendered EVTX message that exceeds the description",
        veloUrl: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["s1.webp"] });
    const pushed = state.forensicTimeline.find((e) => e.id === "e1")!;
    expect(pushed.message).toContain("FULL rendered EVTX message");
    expect(pushed.veloUrl).toBe("https://velo.example/app/index.html?org_id=root#/hunts/H.ABC");

    // Update branch: re-reporting the same id supplies fresh message/veloUrl — they must persist.
    state = mergeDelta(state, {
      ...baseDelta,
      forensicEvents: [{ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "MFT: created evil.exe",
        severity: "Info", mitreTechniques: [], relatedFindingIds: [],
        message: "UPDATED full message text",
        veloUrl: "https://velo.example/app/index.html?org_id=root#/hunts/H.ZZZ" }],
    }, { windowSequence: 2, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: ["s2.webp"] });
    const updated = state.forensicTimeline.find((e) => e.id === "e1")!;
    expect(updated.message).toBe("UPDATED full message text");
    expect(updated.veloUrl).toBe("https://velo.example/app/index.html?org_id=root#/hunts/H.ZZZ");
  });

  it("carries narrativeTimeline from delta into state, preserving prior value when omitted", () => {
    let state = emptyState("c1");
    expect(state.narrativeTimeline).toBe("");

    // Synthesis provides a narrative — it should be stored.
    state = mergeDelta(state, {
      ...baseDelta,
      narrativeTimeline: "At 09:00 the attacker gained initial access. This was followed by credential dumping.",
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });
    expect(state.narrativeTimeline).toBe("At 09:00 the attacker gained initial access. This was followed by credential dumping.");

    // A per-window delta without narrativeTimeline must NOT clear it.
    state = mergeDelta(state, { ...baseDelta }, { windowSequence: 2, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: [] });
    expect(state.narrativeTimeline).toBe("At 09:00 the attacker gained initial access. This was followed by credential dumping.");

    // A later synthesis with a new narrative replaces the old one.
    state = mergeDelta(state, {
      ...baseDelta,
      narrativeTimeline: "Updated narrative after more evidence.",
    }, { windowSequence: 3, timestamp: "2026-05-28T10:10:00.000Z", sourceScreenshots: [] });
    expect(state.narrativeTimeline).toBe("Updated narrative after more evidence.");
  });
});

describe("mergeDelta — ioc extractedFrom", () => {
  it("carries extractedFrom onto a newly created IOC", () => {
    const state = emptyState("c1");
    const next = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "si1", type: "domain", value: "evil.example.com", extractedFrom: ["e001"] }],
    }, { windowSequence: -1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });
    expect(next.iocs).toHaveLength(1);
    expect(next.iocs[0].extractedFrom).toEqual(["e001"]);
  });

  it("unions extractedFrom when the same IOC value recurs across separate imports", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "si1", type: "domain", value: "evil.example.com", extractedFrom: ["e001"] }],
    }, { windowSequence: -1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });

    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "si1", type: "domain", value: "EVIL.example.com", extractedFrom: ["e050"] }],
    }, { windowSequence: -1, timestamp: "2026-05-28T11:00:00.000Z", sourceScreenshots: [] });

    expect(state.iocs).toHaveLength(1);
    expect(state.iocs[0].extractedFrom).toEqual(["e001", "e050"]);
  });

  it("leaves extractedFrom undefined for an IOC whose delta never sets it", () => {
    const state = emptyState("c1");
    const next = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "si1", type: "ip", value: "9.9.9.9" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });
    expect(next.iocs[0].extractedFrom).toBeUndefined();
  });
});
