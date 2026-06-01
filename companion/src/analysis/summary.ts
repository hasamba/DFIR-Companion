import type { InvestigationState } from "./stateTypes.js";

export function buildStateSummary(state: InvestigationState): string {
  if (
    state.findings.length === 0 &&
    state.openThreads.length === 0 &&
    state.forensicTimeline.length === 0
  ) {
    return "No findings yet. This is early in the investigation.";
  }
  const findings = state.findings
    .map((f) => `- [${f.id}] (${f.severity}) ${f.title}: ${f.description}`)
    .join("\n");
  const threads = state.openThreads
    .filter((t) => t.status === "open")
    .map((t) => `- [${t.id}] ${t.description}`)
    .join("\n");
  const iocs = state.iocs.map((i) => `${i.type}:${i.value}`).join(", ");
  // Show the most recent dated events so the model extends (not duplicates) the timeline.
  const events = state.forensicTimeline
    .slice(-12)
    .map((e) => `- [${e.id}] ${e.timestamp || "(undated)"} ${e.description}`)
    .join("\n");

  return [
    "EXISTING FINDINGS (update by id; do not duplicate):",
    findings || "(none)",
    "",
    "OPEN THREADS (close by id when resolved):",
    threads || "(none)",
    "",
    "FORENSIC EVENTS ALREADY ON THE TIMELINE (extend by id; do not duplicate):",
    events || "(none)",
    "",
    `KNOWN IOCS: ${iocs || "(none)"}`,
  ].join("\n");
}
