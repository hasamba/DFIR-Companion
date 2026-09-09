import { unionEventTechniques } from "./attackTechniqueNames.js";
import type { InvestigationState } from "./stateTypes.js";

// The case MITRE table, completed from the techniques the forensic events carry (#893).
//
// Every deterministic importer hardcodes its delta's top-level `mitreTechniques` to [] and puts the
// real ids on the events it produces, so a case that has never run AI synthesis has an empty
// aggregate and an empty MITRE panel while Kill Chain and the ATT&CK Navigator export — which read
// the events directly — show the techniques. That was #878.
//
// #878 fixed it by unioning those ids into the aggregate during the merge. The aggregate is
// PERSISTED, and scope and the false-positive filter drop events at projection rather than from
// state, so once a technique was in it there was no way back out: dismissing the only event that
// carried it changed nothing, and every later import re-added it. Chasing that with provenance
// meant rebuilding, alongside the timeline, a second model of which event a technique came from and
// when — through a correlation step whose whole job is to collapse exactly that.
//
// So it is derived instead of stored. Applied AFTER the scope window and the false-positive filter,
// over the events that survive them, it cannot disagree with the timeline it is shown beside: an
// event the analyst dismissed is not there to contribute, and one they scope back in contributes
// again with no healing pass required. Nothing is written, so nothing can go stale.
//
// Pure and idempotent — unionEventTechniques skips ids the table already holds, so a technique a
// model asserted at a delta's top level keeps its finding links and is not duplicated.
export function withEventTechniques(state: InvestigationState): InvestigationState {
  // What the surviving evidence still supports. A technique SYNTHESIS asserted is persisted, so
  // without this it outlived the dismissal of the very event it was drawn from: the analyst
  // dismissed the evidence and the row stayed in the panel and the report.
  //
  // Hiding it here is safe in a way that pruning the stored table never was — and that is the whole
  // difference this rework makes. This is a VIEW: state is untouched, so widening the scope window
  // or un-marking the event brings the technique straight back, with no merge and nothing to heal.
  // The old design had to choose between leaving stale rows and deleting analysis for good.
  const surviving = new Set(state.findings.map((f) => f.id));
  const carried = new Set(state.forensicTimeline.flatMap((e) => e.mitreTechniques));
  const supported = state.mitreTechniques.filter(
    (t) => t.findingIds.some((id) => surviving.has(id)) || carried.has(t.id),
  );
  return { ...state, mitreTechniques: unionEventTechniques(supported, state.forensicTimeline) };
}
