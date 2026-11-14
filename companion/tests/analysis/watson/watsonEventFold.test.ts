// F1: correlation may fold a Watson-marked row into an ordinary one (or the reverse). The survivor
// carries the folded row's provenance, `[watson]` included. Reconciling the run with the store must
// never drop that survivor: only a row Watson created that the store no longer holds goes.
import { describe, expect, it } from "vitest";
import { correlateEventsTracked } from "../../../src/analysis/correlate.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../../src/analysis/stateTypes.js";
import { keepWatsonItems, WATSON_MARKER } from "../../../src/analysis/timeline/watsonItems.js";

const HASH = "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-05-26T08:35:23Z",
    description: "event",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}
// The pair correlates on the hash; the Critical THOR row is the group's primary (it keeps its id).
const velo = (id: string, over: Partial<ForensicEvent> = {}) =>
  ev({ id, description: `Downloaded file evil.exe flagged, sha256 ${HASH}`, ...over });
const thor = (id: string, over: Partial<ForensicEvent> = {}) =>
  ev({
    id,
    severity: "Critical",
    sha256: HASH,
    description: "THOR Alert: Malware file found C:\\Tools\\evil.exe",
    ...over,
  });
const marked = { provenance: [WATSON_MARKER] };

const state = (timeline: ForensicEvent[], over: Partial<InvestigationState> = {}): InvestigationState => ({
  ...emptyState("c1"),
  forensicTimeline: timeline,
  ...over,
});

/** The run: the snapshot's timeline correlated, with the fold recorded as eventAliases. */
function run(timeline: ForensicEvent[]): { next: InvestigationState; absorbedInto: Map<string, string> } {
  const { events, absorbedInto } = correlateEventsTracked(timeline);
  return { next: state(events, { eventAliases: Object.fromEntries(absorbedInto) }), absorbedInto };
}

describe("keepWatsonItems across a correlation fold", () => {
  it("keeps an ordinary survivor that absorbed a Watson row, with its evidence", () => {
    const watsonRow = velo("ev-watson-p1-3", marked);
    const ordinary = thor("t2e5");
    const { next, absorbedInto } = run([watsonRow, ordinary]);
    expect(absorbedInto.get(watsonRow.id)).toBe(ordinary.id); // precondition: the fold direction
    const survivor = next.forensicTimeline.find((e) => e.id === ordinary.id);
    expect(survivor?.provenance).toContain(WATSON_MARKER); // inherited from the folded row

    const out = keepWatsonItems(next, state([watsonRow, ordinary]));
    // Kept with its evidence, but not marked as Watson's: it is the case's own event.
    const { provenance, ...evidence } = survivor!;
    const left = (provenance ?? []).filter((p) => p !== WATSON_MARKER);
    expect(out.forensicTimeline).toEqual([left.length ? { ...evidence, provenance: left } : evidence]);
    expect(out.forensicTimeline[0].provenance ?? []).not.toContain(WATSON_MARKER);
  });

  it("an ordinary survivor that absorbed a Watson row stays ordinary: a later synthesis's fields win", () => {
    const watsonRow = velo("ev-watson-p1-3", marked);
    const ordinary = thor("t2e5");
    const { next } = run([watsonRow, ordinary]);
    const persisted = keepWatsonItems(next, state([watsonRow, ordinary]));

    const later = state(
      persisted.forensicTimeline.map((e) => ({ ...e, severity: "Medium" as const, description: "regraded" })),
    );
    const out = keepWatsonItems(later, persisted);
    expect(out.forensicTimeline).toEqual(later.forensicTimeline);
    // A run that drops it does not see it re-added as a stored Watson row.
    expect(keepWatsonItems(state([]), persisted).forensicTimeline).toEqual([]);
  });

  it("keeps the merged evidence when a Watson row is the survivor of the fold", () => {
    const watsonRow = thor("ev-watson-p1-4", marked);
    const ordinary = velo("m1e1", { provenance: ["velociraptor"], mitreTechniques: ["T1105"] });
    const { next, absorbedInto } = run([watsonRow, ordinary]);
    expect(absorbedInto.get(ordinary.id)).toBe(watsonRow.id);
    const survivor = next.forensicTimeline.find((e) => e.id === watsonRow.id);

    const out = keepWatsonItems(next, state([watsonRow, ordinary]));
    expect(out.forensicTimeline).toEqual([survivor]);
  });

  it("does not resurrect a paste-line row undone while the run worked", () => {
    const undone = ev({ id: "ev-watson-p1-9", description: "Pasted a.log line 9: x", ...marked });
    const other = ev({ id: "e1" });
    const { next } = run([undone, other]);
    const out = keepWatsonItems(next, state([other]));
    expect(out.forensicTimeline.map((e) => e.id)).toEqual(["e1"]);
  });

  it("does not resurrect a promoted held row (super-timeline id) undone while the run worked", () => {
    const promoted = ev({ id: "st-row-17", description: "held row", ...marked });
    const other = ev({ id: "e1" });
    const { next } = run([promoted, other]);
    const out = keepWatsonItems(next, state([other]));
    expect(out.forensicTimeline.map((e) => e.id)).toEqual(["e1"]);
  });

  it("an older fold the store already records is not this run's: the store copy wins, an undone row goes", () => {
    const row = ev({ id: "ev-watson-p1-5", ...marked, severity: "High" });
    const runCopy = { ...row, severity: "Low" as const };
    const aliases = { "m-old": row.id };
    const out = keepWatsonItems(state([runCopy], { eventAliases: aliases }), {
      ...state([row]),
      eventAliases: aliases,
    });
    expect(out.forensicTimeline).toEqual([row]);
    const undone = keepWatsonItems(state([runCopy, ev({ id: "e1" })], { eventAliases: aliases }), {
      ...state([ev({ id: "e1" })]),
      eventAliases: aliases,
    });
    expect(undone.forensicTimeline.map((e) => e.id)).toEqual(["e1"]);
  });

  it("keeps the store's copy of a Watson row the run did not fold", () => {
    const row = ev({ id: "ev-watson-p1-2", ...marked, severity: "High" });
    const runCopy = { ...row, severity: "Low" as const, relatedFindingIds: ["f-watson-1a2b3c4d"] };
    const out = keepWatsonItems(state([runCopy]), state([row]));
    expect(out.forensicTimeline).toEqual([{ ...row, relatedFindingIds: ["f-watson-1a2b3c4d"] }]);
  });
});
