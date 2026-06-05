import type { InvestigationState } from "./stateTypes.js";

// This summary is prepended to EVERY import batch (CSV/log) so the model extends rather than
// duplicates. It must stay compact: a big case can hold hundreds of findings/IOCs, and an
// unbounded list here was a real contributor to blowing past the model's context window. We
// keep the MOST RECENT of each (the ones a new batch is most likely to touch) and note the
// rest as a count — the full set still lives in state and feeds synthesis.
const MAX_FINDINGS = 40;
const MAX_IOCS = 80;

function withMore<T>(items: readonly T[], max: number, render: (t: T) => string): string {
  const shown = items.slice(-max).map(render).join("\n");
  const extra = items.length - Math.min(items.length, max);
  return extra > 0 ? `${shown}\n- (+${extra} more not shown)` : shown;
}

export function buildStateSummary(state: InvestigationState): string {
  if (
    state.findings.length === 0 &&
    state.openThreads.length === 0 &&
    state.forensicTimeline.length === 0
  ) {
    return "No findings yet. This is early in the investigation.";
  }
  const findings = withMore(state.findings, MAX_FINDINGS, (f) => `- [${f.id}] (${f.severity}) ${f.title}: ${f.description}`);
  const threads = state.openThreads
    .filter((t) => t.status === "open")
    .map((t) => `- [${t.id}] ${t.description}`)
    .join("\n");
  const shownIocs = state.iocs.slice(-MAX_IOCS).map((i) => `${i.type}:${i.value}`).join(", ");
  const extraIocs = state.iocs.length - Math.min(state.iocs.length, MAX_IOCS);
  const iocs = extraIocs > 0 ? `${shownIocs} (+${extraIocs} more)` : shownIocs;
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
