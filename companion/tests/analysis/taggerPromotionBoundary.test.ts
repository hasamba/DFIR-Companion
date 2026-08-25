import { describe, it, expect } from "vitest";
import { compileRuleset } from "../../src/analysis/taggerRules.js";
import { runAndApplyTagger } from "../../src/analysis/taggerRun.js";
import { demoteBelowSeverity } from "../../src/analysis/forensicGate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// WHEN a severity-raising rule can promote an event, and when it cannot.
//
// This is a characterization test: it pins behaviour that is easy to describe wrongly, and was.
// The tagger promotes Info telemetry into the forensic timeline by RAISING the severity of an event
// the timeline already holds — `runAndApplyTagger` maps over `forensicTimeline` and never appends to
// it. So the promotion window is the one import in which merge-all has placed the event in the
// timeline and demote has not yet removed it (merge-all → tag → demote).
//
// Once demote has run, the Info event lives in the super-timeline only. A later "Run tagger" still
// EVALUATES it — the manual route reads super-timeline events — and still writes its tags, so it
// becomes findable by tag. It cannot raise it back into the forensic timeline. Adding a new rule
// therefore changes what FUTURE collections surface to the AI, not what past ones do.
//
// Do not "fix" this by appending to the timeline inside runAndApplyTagger. Promoting historical
// super-timeline rows in bulk is the flooding the forensic/super boundary exists to prevent
// (ARCHITECTURE.md → "The forensic / super-timeline boundary"); a backfill needs to be
// analyst-initiated, previewed and capped, like every other promotion path.

const RULES = compileRuleset({
  usb: {
    any: [{ field: "artifactName", contains: "Mounted.Mass.Storage" }],
    tags: ["removable-media"],
    severity: "Low",
  },
});

// The tag writes are not what this test is about; a no-op store keeps it to the promotion question.
const tagsStore = { load: async () => [], add: async () => undefined } as never;

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const usb = ev({ id: "usb1", artifactName: "Windows.Mounted.Mass.Storage" });

describe("tagger promotion boundary", () => {
  it("promotes during the import that collected the event, and it then survives demote", async () => {
    const applied = await runAndApplyTagger({
      caseId: "c1",
      events: [usb],
      ruleset: RULES,
      forensicTimeline: [usb], // merge-all placed it here as Info; demote has not run yet
      tagsStore,
      mutateForensic: true,
    });

    expect(applied.forensicTimeline[0].severity).toBe("Low");
    expect(applied.mutatedCount).toBe(1);
    expect(demoteBelowSeverity(applied.forensicTimeline, "Low").kept).toHaveLength(1);
  });

  it("cannot promote an event demote already removed — it matches, and nothing moves", async () => {
    const { kept, demoted } = demoteBelowSeverity([usb], "Low");
    expect(kept).toHaveLength(0);
    expect(demoted).toHaveLength(1); // super-timeline only from here on

    const applied = await runAndApplyTagger({
      caseId: "c1",
      events: [usb], // the manual route does evaluate super-timeline events
      ruleset: RULES,
      forensicTimeline: kept, // ...but this is what gets mapped, and it is empty
      tagsStore,
      mutateForensic: true,
    });

    expect(applied.result.totalMatched).toBe(1); // the rule matched
    expect(applied.forensicTimeline).toHaveLength(0); // and promoted nothing
    expect(applied.mutatedCount).toBe(0);
  });

  it("never appends to the forensic timeline, even when every evaluated event matches", async () => {
    const applied = await runAndApplyTagger({
      caseId: "c1",
      events: [usb, ev({ id: "usb2", artifactName: "Windows.Mounted.Mass.Storage" })],
      ruleset: RULES,
      forensicTimeline: [],
      tagsStore,
      mutateForensic: true,
    });

    expect(applied.result.totalMatched).toBe(2);
    expect(applied.forensicTimeline).toHaveLength(0);
  });
});
