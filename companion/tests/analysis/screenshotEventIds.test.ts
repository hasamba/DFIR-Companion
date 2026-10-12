import { describe, expect, it } from "vitest";
import { renumberScreenshotEvents } from "../../src/analysis/ai/screenshotEventIds.js";
import { SUMMARY_EVENT_COUNT, summarizedEventIds } from "../../src/analysis/summary.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// #2175 — a screenshot window must not overwrite an unrelated earlier event by reusing its id.

const T1 = "2026-05-20T10:00:00Z";
const T2 = "2026-05-21T09:00:00Z";

function stored(id: string, timestamp: string): ForensicEvent {
  return {
    id,
    timestamp,
    description: `stored ${id}`,
    severity: "Critical",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: ["s1.png"],
  };
}

type DeltaEvent = NonNullable<AnalysisDelta["forensicEvents"]>[number];

function incoming(id: string, timestamp: string): DeltaEvent {
  return {
    id,
    timestamp,
    description: `incoming ${id}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
  };
}

function delta(events: DeltaEvent[], extra: Partial<AnalysisDelta> = {}): AnalysisDelta {
  return { findings: [], iocs: [], forensicEvents: events, ...extra } as unknown as AnalysisDelta;
}

const ids = (d: AnalysisDelta): string[] => (d.forensicEvents ?? []).map((e) => e.id);

describe("renumberScreenshotEvents (#2175)", () => {
  it("renumbers every event on an empty timeline", () => {
    const out = renumberScreenshotEvents(
      delta([incoming("e1", T1), incoming("e2", T1)]),
      [],
      new Set(),
      "s7",
    );
    expect(ids(out)).toEqual(["s7e1", "s7e2"]);
  });

  it("renumbers a shown id whose timestamp differs from the stored event", () => {
    const timeline = [stored("e1", T1)];
    const out = renumberScreenshotEvents(delta([incoming("e1", T2)]), timeline, new Set(["e1"]), "s7");
    expect(ids(out)).toEqual(["s7e1"]);
  });

  it("keeps a shown id at the same timestamp (extend-by-id)", () => {
    const timeline = [stored("e1", T1)];
    const out = renumberScreenshotEvents(delta([incoming("e1", T1)]), timeline, new Set(["e1"]), "s7");
    expect(ids(out)).toEqual(["e1"]);
  });

  it("keeps a shown id when either side is undated", () => {
    const timeline = [stored("e1", "")];
    const out = renumberScreenshotEvents(delta([incoming("e1", T2)]), timeline, new Set(["e1"]), "s7");
    expect(ids(out)).toEqual(["e1"]);
  });

  it("renumbers an id the model was never shown", () => {
    const timeline = Array.from({ length: SUMMARY_EVENT_COUNT + 1 }, (_, i) =>
      stored(`e${i + 1}`, `2026-05-${String(i + 1).padStart(2, "0")}T00:00:00Z`),
    );
    const state = { forensicTimeline: timeline } as unknown as InvestigationState;
    const shown = summarizedEventIds(state);
    expect(shown.has("e1")).toBe(false);
    const out = renumberScreenshotEvents(
      delta([incoming("e1", timeline[0].timestamp)]),
      timeline,
      shown,
      "s7",
    );
    expect(ids(out)).toEqual(["s7e1"]);
  });

  it("renumbers the second occurrence of an id within one delta", () => {
    const timeline = [stored("e1", T1)];
    const out = renumberScreenshotEvents(
      delta([incoming("e1", T1), incoming("e1", T1)]),
      timeline,
      new Set(["e1"]),
      "s7",
    );
    expect(ids(out)).toEqual(["e1", "s7e1"]);
  });

  it("leaves citations alone when the first occurrence of a duplicated id kept it", () => {
    const input = delta([incoming("e1", T1), incoming("e1", T2)], {
      findings: [
        {
          id: "f1",
          severity: "High",
          title: "t",
          description: "d",
          relatedIocs: [],
          mitreTechniques: [],
          status: "open",
          relatedEventIds: ["e1"],
        },
      ],
    } as unknown as Partial<AnalysisDelta>);
    const out = renumberScreenshotEvents(input, [stored("e1", T1)], new Set(["e1"]), "s7");
    expect(ids(out)).toEqual(["e1", "s7e1"]);
    expect(out.findings[0].relatedEventIds).toEqual(["e1"]);
  });

  it("continues the sequence after events already stored under the prefix", () => {
    const timeline = [stored("s7e1", T1), stored("s7e2", T1)];
    const out = renumberScreenshotEvents(delta([incoming("e1", T1)]), timeline, new Set(), "s7");
    expect(ids(out)).toEqual(["s7e3"]);
  });

  it("remaps finding and hypothesis citations of renumbered ids, leaving kept ids alone", () => {
    const timeline = [stored("e9", T1)];
    const input = delta([incoming("e1", T2), incoming("e9", T1)], {
      findings: [
        {
          id: "f1",
          severity: "High",
          title: "t",
          description: "d",
          relatedIocs: [],
          mitreTechniques: [],
          status: "open",
          relatedEventIds: ["e1", "e9"],
        },
      ],
      hypotheses: [{ relatedEventIds: ["e1"], contradictingEventIds: ["e9", "e1"] }],
    } as unknown as Partial<AnalysisDelta>);
    const out = renumberScreenshotEvents(input, timeline, new Set(["e9"]), "s7");
    expect(ids(out)).toEqual(["s7e1", "e9"]);
    expect(out.findings[0].relatedEventIds).toEqual(["s7e1", "e9"]);
    const hyp = (
      out as unknown as { hypotheses: { relatedEventIds: string[]; contradictingEventIds: string[] }[] }
    ).hypotheses[0];
    expect(hyp.relatedEventIds).toEqual(["s7e1"]);
    expect(hyp.contradictingEventIds).toEqual(["e9", "s7e1"]);
  });

  it("does not mutate its input", () => {
    const input = delta([incoming("e1", T1), incoming("e1", T2)]);
    const before = structuredClone(input);
    renumberScreenshotEvents(input, [stored("e1", T1)], new Set(["e1"]), "s7");
    expect(input).toEqual(before);
  });
});

describe("summarizedEventIds", () => {
  it("returns the ids of the last SUMMARY_EVENT_COUNT timeline events", () => {
    const timeline = Array.from({ length: SUMMARY_EVENT_COUNT + 2 }, (_, i) => stored(`x${i}`, T1));
    const state = { forensicTimeline: timeline } as unknown as InvestigationState;
    const shown = summarizedEventIds(state);
    expect(shown.size).toBe(SUMMARY_EVENT_COUNT);
    expect(shown.has("x0")).toBe(false);
    expect(shown.has(`x${SUMMARY_EVENT_COUNT + 1}`)).toBe(true);
  });
});
