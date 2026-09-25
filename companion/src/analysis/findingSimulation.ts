// How the simulation verdict (#1595) changed one finding. Set post-synthesis by
// applySimulationVerdict (analysis/simulationVerdict.ts) when the case's own findings conclude it is
// an authorized simulation; never model-set. Its own shared file because stateTypes.ts sits at the
// size limit.
//
// `originalSeverity` is the live-intrusion severity before the step; `appliedSeverity` is what the
// step set, so a later rewrite of the severity (a model re-run, an accepted second opinion) is
// recognised and wins.
type SimulationSeverity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface FindingSimulation {
  role: "verdict" | "simulated" | "live-exposure";
  originalSeverity: SimulationSeverity;
  appliedSeverity: SimulationSeverity;
  verdictId?: string; // simulated / live-exposure: the verdict finding that explains it
  overridden?: boolean; // verdict only: the analyst said "treat as real intrusion"
}
