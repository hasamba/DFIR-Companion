import { describe, it, expect } from "vitest";
import { backfillHighSeverityFindings, shortTitle } from "../../src/analysis/highSeverityFindings.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-05-26T12:25:36Z",
    description: "desc",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

describe("shortTitle", () => {
  it("takes the first sentence and caps the length", () => {
    expect(shortTitle("Defender flagged Rubeus.exe. More detail here.")).toBe("Defender flagged Rubeus.exe.");
    expect(shortTitle("x".repeat(200)).length).toBeLessThanOrEqual(90);
    expect(shortTitle("x".repeat(200)).endsWith("…")).toBe(true);
  });
});

describe("backfillHighSeverityFindings", () => {
  it("auto-creates a finding for an uncovered Critical/High event", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      ev({
        id: "e1",
        severity: "Critical",
        description: "Microsoft Defender flagged Rubeus.exe",
        mitreTechniques: ["T1003"],
        sourceScreenshots: ["s1.webp"],
      }),
    );
    const out = backfillHighSeverityFindings(state, new Set(["e1"]), "2026-05-26T13:00:00Z");
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      id: "f-auto-e1",
      severity: "Critical",
      status: "open",
      mitreTechniques: ["T1003"],
      sourceScreenshots: ["s1.webp"],
    });
    expect(out.findings[0].title).toBe("Microsoft Defender flagged Rubeus.exe");
    // A deterministic backfill is maximally confident — it's a graded artifact row, not a guess.
    expect(out.findings[0].confidence).toBe(100);
    expect(out.findings[0].confidenceReason).toMatch(/backfill/i);
    // The event is linked back to the new finding.
    expect(out.forensicTimeline[0].relatedFindingIds).toEqual(["f-auto-e1"]);
  });

  it("mentions tool corroboration in confidenceReason when 2+ distinct sources back the event", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev({ id: "e1", severity: "Critical", sources: ["Velociraptor", "THOR"] }));
    const out = backfillHighSeverityFindings(state, new Set(["e1"]), "t");
    expect(out.findings[0].confidenceReason).toMatch(/2 distinct tools/);
  });

  it("does NOT touch events already covered by a synthesis finding", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev({ id: "e1", severity: "High", relatedFindingIds: ["f1"] }));
    const out = backfillHighSeverityFindings(state, new Set(["e1"]), "t");
    expect(out.findings).toHaveLength(0);
    expect(out).toBe(state); // no change → same reference
  });

  it("ignores Medium/Low/Info events", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev({ id: "e1", severity: "Medium" }), ev({ id: "e2", severity: "Info" }));
    const out = backfillHighSeverityFindings(state, new Set(["e1", "e2"]), "t");
    expect(out.findings).toHaveLength(0);
  });

  it("respects eligibility (scope / legitimate excluded events are not backfilled)", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      ev({ id: "in", severity: "High" }),
      ev({ id: "out", severity: "Critical" }), // out of scope / legit → not eligible
    );
    const out = backfillHighSeverityFindings(state, new Set(["in"]), "t");
    expect(out.findings.map((f) => f.id)).toEqual(["f-auto-in"]);
  });

  it("is idempotent — re-running does not duplicate", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev({ id: "e1", severity: "Critical" }));
    const once = backfillHighSeverityFindings(state, new Set(["e1"]), "t");
    const twice = backfillHighSeverityFindings(once, new Set(["e1"]), "t");
    expect(twice.findings).toHaveLength(1);
    expect(twice).toBe(once); // already linked → no-op
  });

  it("groups near-identical events by shortTitle into a single finding", () => {
    const state = emptyState("c1");
    // Three events with the same first sentence (same Sigma rule, different threat IDs).
    const sharedDesc = "Windows Defender Threat Detected. Malware details vary per event.";
    state.forensicTimeline.push(
      ev({ id: "e1", severity: "High", description: sharedDesc, mitreTechniques: ["T1059"] }),
      ev({ id: "e2", severity: "High", description: sharedDesc, mitreTechniques: ["T1059", "T1027"] }),
      ev({ id: "e3", severity: "High", description: sharedDesc }),
    );
    const out = backfillHighSeverityFindings(state, new Set(["e1", "e2", "e3"]), "t");
    // All three collapse into one finding.
    expect(out.findings).toHaveLength(1);
    const f = out.findings[0];
    // Id uses the lex-first event id.
    expect(f.id).toBe("f-auto-e1");
    expect(f.title).toBe("Windows Defender Threat Detected.");
    // Description mentions the count.
    expect(f.description).toContain("3 similar");
    // MITRE union.
    expect(f.mitreTechniques).toEqual(expect.arrayContaining(["T1059", "T1027"]));
    // All events linked to the one finding.
    for (const e of out.forensicTimeline) {
      expect(e.relatedFindingIds).toEqual(["f-auto-e1"]);
    }
  });

  it("keeps distinct titles as separate findings", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      ev({ id: "e1", severity: "High", description: "Mimikatz credential dump detected." }),
      ev({ id: "e2", severity: "High", description: "Rubeus Kerberoasting detected." }),
    );
    const out = backfillHighSeverityFindings(state, new Set(["e1", "e2"]), "t");
    expect(out.findings).toHaveLength(2);
  });

  describe("folding uncovered events into an already-dismissed CORPUS-level finding", () => {
    // Regression for INC-2026-018: finding f7 dismissed a whole THOR/YARA false-positive wave under
    // Velociraptor's own bundled chainsaw test corpus, citing e0a/e0b/e0c (3 distinct files — an
    // established corpus dismissal). e1 sits in the same directory (a fourth rule file, never
    // individually cited by f7) — it must fold onto f7, not raise a new open High finding for the
    // exact same already-explained noise.
    const dir =
      "C:\\Program Files\\Velociraptor\\Tools\\tmp2370838011\\chainsaw\\sigma\\rules\\windows\\process_creation\\";
    const chainsawPathA = dir + "proc_creation_win_a.yml";
    const chainsawPathB = dir + "proc_creation_win_b.yml";
    const chainsawPathC = dir + "proc_creation_win_c.yml";
    // Same directory, a fresh randomly-named temp dir (as a later re-extraction would produce).
    const chainsawPathD =
      "C:\\Program Files\\Velociraptor\\Tools\\tmp481774682\\chainsaw\\sigma\\rules\\windows\\process_creation\\proc_creation_win_d.yml";

    function dismissedState(): ReturnType<typeof emptyState> {
      const state = emptyState("c1");
      state.forensicTimeline.push(
        ev({ id: "e0a", severity: "High", path: chainsawPathA, relatedFindingIds: ["f7"] }),
        ev({ id: "e0b", severity: "High", path: chainsawPathB, relatedFindingIds: ["f7"] }),
        ev({ id: "e0c", severity: "High", path: chainsawPathC, relatedFindingIds: ["f7"] }),
      );
      state.findings.push({
        id: "f7",
        severity: "Low",
        title: "FP wave from bundled chainsaw test corpus",
        description: "explained and dismissed",
        relatedIocs: [],
        mitreTechniques: [],
        sourceScreenshots: [],
        relatedEventIds: ["e0a", "e0b", "e0c"],
        firstSeen: "t0",
        lastUpdated: "t0",
        status: "dismissed",
      });
      return state;
    }

    it("folds a same-directory event onto the dismissed finding instead of raising a new open one", () => {
      const state = dismissedState();
      state.forensicTimeline.push(ev({ id: "e1", severity: "High", path: chainsawPathD }));
      const out = backfillHighSeverityFindings(state, new Set(["e1"]), "t");
      expect(out.findings).toHaveLength(1); // f7 only — no f-auto-e1 was created
      expect(out.findings[0].id).toBe("f7");
      expect(out.forensicTimeline.find((e) => e.id === "e1")?.relatedFindingIds).toEqual(["f7"]);
    });

    it("still backfills an unrelated event as a new open finding in the same run", () => {
      const state = dismissedState();
      state.forensicTimeline.push(
        ev({ id: "e1", severity: "High", path: chainsawPathD }),
        ev({ id: "e2", severity: "Critical", description: "Genuinely new detection." }),
      );
      const out = backfillHighSeverityFindings(state, new Set(["e1", "e2"]), "t");
      const ids = out.findings.map((f) => f.id).sort();
      expect(ids).toEqual(["f-auto-e2", "f7"]);
      expect(out.forensicTimeline.find((e) => e.id === "e1")?.relatedFindingIds).toEqual(["f7"]);
      expect(out.forensicTimeline.find((e) => e.id === "e2")?.relatedFindingIds).toEqual(["f-auto-e2"]);
    });

    it("does not fold an event under a merely similar but shallower shared path", () => {
      const state = dismissedState();
      // Shares only "C:/Program Files/Velociraptor/Tools/tmp#" (5 segments) — one short of the
      // required depth — because it's a different tool's own top-level directory, not the same
      // explained corpus.
      state.forensicTimeline.push(
        ev({
          id: "e1",
          severity: "High",
          path: "C:\\Program Files\\Velociraptor\\Tools\\tmp999999999\\some-other-tool\\file.exe",
        }),
      );
      const out = backfillHighSeverityFindings(state, new Set(["e1"]), "t");
      expect(out.findings.map((f) => f.id).sort()).toEqual(["f-auto-e1", "f7"]);
    });

    it("does not fold onto a finding that is open/confirmed, only dismissed", () => {
      const state = emptyState("c1");
      state.forensicTimeline.push(
        ev({ id: "e0a", severity: "High", path: chainsawPathA, relatedFindingIds: ["f7"] }),
        ev({ id: "e0b", severity: "High", path: chainsawPathB, relatedFindingIds: ["f7"] }),
        ev({ id: "e0c", severity: "High", path: chainsawPathC, relatedFindingIds: ["f7"] }),
      );
      state.findings.push({
        id: "f7",
        severity: "High",
        title: "Still-open finding covering the same directory",
        description: "not dismissed",
        relatedIocs: [],
        mitreTechniques: [],
        sourceScreenshots: [],
        relatedEventIds: ["e0a", "e0b", "e0c"],
        firstSeen: "t0",
        lastUpdated: "t0",
        status: "open",
      });
      state.forensicTimeline.push(ev({ id: "e1", severity: "High", path: chainsawPathD }));
      const out = backfillHighSeverityFindings(state, new Set(["e1"]), "t");
      expect(out.findings.map((f) => f.id).sort()).toEqual(["f-auto-e1", "f7"]);
    });

    // THE CORE SAFETY-NET REGRESSION (Codex review, P1): a single dismissal must never become a
    // directory-wide allowlist. A one-off dismissal — even one whose file happens to sit in a real
    // product/cache directory — must not silently swallow a genuinely NEW, unrelated High/Critical
    // detection planted in that same directory later.
    it("does NOT fold a same-directory event onto a dismissed finding that cited only ONE file", () => {
      const state = emptyState("c1");
      state.forensicTimeline.push(
        ev({ id: "e0", severity: "Critical", path: chainsawPathA, relatedFindingIds: ["f8"] }),
      );
      state.findings.push({
        id: "f8",
        severity: "Critical",
        title: "Velociraptor.exe flagged as malicious (self-signature collision)",
        description: "a one-off dismissal of a single file, not a corpus-level wave",
        relatedIocs: [],
        mitreTechniques: [],
        sourceScreenshots: [],
        relatedEventIds: ["e0"], // exactly ONE distinct path — below MIN_DISMISSED_CORPUS_FILES
        firstSeen: "t0",
        lastUpdated: "t0",
        status: "dismissed",
      });
      // A genuinely new, unrelated High detection planted in the SAME directory (e.g. an attacker
      // dropping a payload beside a legitimate tool) must still be backfilled as its own open finding.
      state.forensicTimeline.push(ev({ id: "e1", severity: "Critical", path: chainsawPathB }));
      const out = backfillHighSeverityFindings(state, new Set(["e1"]), "t");
      expect(out.findings.map((f) => f.id).sort()).toEqual(["f-auto-e1", "f8"]);
      expect(out.forensicTimeline.find((e) => e.id === "e1")?.relatedFindingIds).toEqual(["f-auto-e1"]);
    });

    it("does NOT fold when the dismissed finding cited 2 distinct files (still below the corpus threshold)", () => {
      const state = emptyState("c1");
      state.forensicTimeline.push(
        ev({ id: "e0a", severity: "High", path: chainsawPathA, relatedFindingIds: ["f9"] }),
        ev({ id: "e0b", severity: "High", path: chainsawPathB, relatedFindingIds: ["f9"] }),
      );
      state.findings.push({
        id: "f9",
        severity: "Low",
        title: "Two related files dismissed together",
        description: "2 distinct paths — still below MIN_DISMISSED_CORPUS_FILES",
        relatedIocs: [],
        mitreTechniques: [],
        sourceScreenshots: [],
        relatedEventIds: ["e0a", "e0b"],
        firstSeen: "t0",
        lastUpdated: "t0",
        status: "dismissed",
      });
      state.forensicTimeline.push(ev({ id: "e1", severity: "High", path: chainsawPathC }));
      const out = backfillHighSeverityFindings(state, new Set(["e1"]), "t");
      expect(out.findings.map((f) => f.id).sort()).toEqual(["f-auto-e1", "f9"]);
    });
  });
});
