import { describe, expect, it } from "vitest";
import { withEventTechniques } from "../../src/analysis/eventTechniques.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

/**
 * #878's problem: a deterministic importer puts its technique ids on the EVENTS, so a case that has
 * never run synthesis shows an empty MITRE panel while Kill Chain shows the techniques.
 *
 * #878's fix stored the union during the merge, which made it permanent — dismissing the only event
 * carrying a technique could not remove it. Deriving it after the filters instead means the table is
 * a function of the timeline it is shown beside, and cannot disagree with it. #893.
 */

const event = (id: string, techniques: string[]): ForensicEvent => ({
  id,
  timestamp: "2026-06-01T10:00:00.000Z",
  description: `event ${id}`,
  severity: "High",
  mitreTechniques: techniques,
  relatedFindingIds: [],
  sourceScreenshots: [],
});

describe("withEventTechniques (#893)", () => {
  it("completes the table from the events, so an import-only case is not empty (#878)", () => {
    const state = { ...emptyState("c1"), forensicTimeline: [event("e1", ["T1003.003"])] };

    const out = withEventTechniques(state);

    expect(out.mitreTechniques.map((t) => t.id)).toEqual(["T1003.003"]);
  });

  it("names what it collects", () => {
    const state = { ...emptyState("c1"), forensicTimeline: [event("e1", ["T1003.003"])] };

    expect(withEventTechniques(state).mitreTechniques[0].name).toBe("OS Credential Dumping: NTDS");
  });

  it("omits a technique whose events the caller already filtered out", () => {
    // The whole mechanism: hand it the surviving timeline and the answer is right by construction.
    const state = { ...emptyState("c1"), forensicTimeline: [event("kept", ["T1003.003"])] };

    const out = withEventTechniques(state);

    expect(out.mitreTechniques.map((t) => t.id)).not.toContain("T1021.002");
  });

  it("keeps an asserted technique's name and finding links rather than restating it", () => {
    const state = {
      ...emptyState("c1"),
      mitreTechniques: [{ id: "T1003.003", name: "NTDS", findingIds: ["f1"] }],
      forensicTimeline: [event("e1", ["T1003.003"])],
    };

    const out = withEventTechniques(state);

    expect(out.mitreTechniques).toHaveLength(1);
    expect(out.mitreTechniques[0]).toMatchObject({ name: "NTDS", findingIds: ["f1"] });
  });

  it("is idempotent, and does not mutate the state it is given", () => {
    const state = { ...emptyState("c1"), forensicTimeline: [event("e1", ["T1003.003"])] };

    const once = withEventTechniques(state);
    const twice = withEventTechniques(once);

    expect(twice.mitreTechniques).toEqual(once.mitreTechniques);
    expect(state.mitreTechniques).toEqual([]);
  });

  it("hides a synthesized technique once the event it was drawn from is gone", () => {
    // The row synthesis persisted outlived the dismissal of its own evidence: the analyst removed
    // the event and the technique stayed in the panel and the report.
    const state = {
      ...emptyState("c1"),
      mitreTechniques: [{ id: "T1486", name: "Data Encrypted for Impact", findingIds: [] }],
      forensicTimeline: [event("kept", ["T1003.003"])],
    };

    expect(withEventTechniques(state).mitreTechniques.map((t) => t.id)).toEqual(["T1003.003"]);
  });

  it("brings it back the moment the event is in the projection again", () => {
    // Why hiding is safe here and pruning the stored table never was: this is a VIEW. The
    // assertion is untouched in state, so un-dismissing restores it with no merge.
    const asserted = [{ id: "T1486", name: "Data Encrypted for Impact", findingIds: [] }];
    const hidden = { ...emptyState("c1"), mitreTechniques: asserted, forensicTimeline: [] };
    expect(withEventTechniques(hidden).mitreTechniques).toEqual([]);

    const restored = { ...hidden, forensicTimeline: [event("back", ["T1486"])] };

    expect(withEventTechniques(restored).mitreTechniques).toEqual(asserted);
  });

  it("keeps a technique a surviving finding still cites, with no event carrying it", () => {
    const state = {
      ...emptyState("c1"),
      findings: [{ id: "f1" }] as never,
      mitreTechniques: [{ id: "T1486", name: "Data Encrypted for Impact", findingIds: ["f1"] }],
      forensicTimeline: [],
    };

    expect(withEventTechniques(state).mitreTechniques.map((t) => t.id)).toEqual(["T1486"]);
  });

  it("hides one whose only finding the filters dropped", () => {
    const state = {
      ...emptyState("c1"),
      findings: [],
      mitreTechniques: [{ id: "T1486", name: "Data Encrypted for Impact", findingIds: ["gone"] }],
      forensicTimeline: [],
    };

    expect(withEventTechniques(state).mitreTechniques).toEqual([]);
  });

  it("keeps a technique the analyst accepted, which by construction has nothing else behind it", () => {
    // An accepted second-opinion addition is the analyst overruling both models: no finding cites
    // it and no event carries it, so a support test alone would hide it the moment it was added.
    const state = {
      ...emptyState("c1"),
      mitreTechniques: [
        { id: "T1486", name: "Data Encrypted for Impact", findingIds: [], analystAccepted: true as const },
      ],
      forensicTimeline: [],
    };

    expect(withEventTechniques(state).mitreTechniques.map((t) => t.id)).toEqual(["T1486"]);
  });

  it("is what the hunt prompt uses, so an import-only case still has techniques to pivot from", () => {
    // hunts.ts reads the case table to tell the model which techniques are in play. Nothing
    // persists event-carried ones any more, so reading the stored table there offered "(none)" on
    // exactly the cases — deterministic imports, no synthesis — that #878 was filed about.
    const state = {
      ...emptyState("c1"),
      forensicTimeline: [event("e1", ["T1003.003"]), event("e2", ["T1021.002"])],
    };

    const text = withEventTechniques(state)
      .mitreTechniques.map((t) => `${t.id} ${t.name}`)
      .join(", ");

    expect(text).toContain("T1003.003 OS Credential Dumping: NTDS");
    expect(text).toContain("T1021.002");
  });
});
