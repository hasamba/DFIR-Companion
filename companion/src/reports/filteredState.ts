import type { InvestigationState } from "../analysis/stateTypes.js";
import type { StateStore } from "../analysis/stateStore.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { ClockSkewStore } from "../analysis/clockSkewStore.js";
import { NO_SCOPE, type ScopeStore } from "../analysis/scope.js";
import type { FalsePositiveStore } from "../analysis/falsePositive.js";
import { projectAlignment } from "../analysis/clockSkew.js";
import { projectScope } from "../analysis/scopeProject.js";
import { applyFalsePositive, filterFalsePositiveEvents } from "../analysis/falsePositive.js";
import { withEventTechniques } from "../analysis/eventTechniques.js";
import { FindingOutcomeStore, withAnalystOutcomes } from "../analysis/findingOutcome.js";

// The one state projection every report artifact reads — markdown, HTML, docx, the CSV and
// Timesketch exports, the evidence graph, the lateral-movement paths. It was a private method on
// ReportWriter until that file reached its size ledger; it lives here now so the projection has a
// name and a home, and so the analyst-set attack outcome (#930 item 8) could join it without the
// report writer growing.
//
// Everything here is a PROJECTION: nothing is written back to the case.

export interface FilteredStateSources {
  state: StateStore;
  cases: CaseStore;
  clockSkew?: ClockSkewStore;
  scope?: ScopeStore;
  falsePositives?: FalsePositiveStore;
}

export async function loadFilteredState(
  src: FilteredStateSources,
  caseId: string,
): Promise<InvestigationState> {
  const loaded = await src.state.load(caseId);
  // Clock-skew alignment (#228) applies FIRST, so every consumer reasons over one time axis. Each
  // shifted event keeps its recorded time in `originalTimestamp`. Scope filtering follows, so an
  // alignment that moves an event across the investigation window is honoured by the window too.
  const skew = src.clockSkew ? await src.clockSkew.load(caseId) : undefined;
  const aligned = { ...loaded, forensicTimeline: projectAlignment(skew, loaded.forensicTimeline) };
  const scoped = projectScope(aligned, src.scope ? await src.scope.load(caseId) : NO_SCOPE);
  const markers = src.falsePositives ? await src.falsePositives.load(caseId) : [];
  const kept = filterFalsePositiveEvents(scoped.forensicTimeline, markers);
  // The analyst's attack-outcome statements are a side file, never part of the saved state (a
  // re-synthesis would wipe them). Applied here so every report surface attributes a blocked or
  // executed attack the way the analyst said, over whatever the machine derived.
  const outcomes = await new FindingOutcomeStore(src.cases).load(caseId);
  const withOutcomes = withAnalystOutcomes({ ...scoped, forensicTimeline: kept }, outcomes);
  // MITRE completed LAST, from the events that survived both filters — see eventTechniques.ts (#893).
  return withEventTechniques(applyFalsePositive(withOutcomes, markers));
}
