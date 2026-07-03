import type { ForensicEvent, Severity } from "./stateTypes.js";

// Info is the "don't know / not suspicious" floor; Low+ is a deliberate signal (source verdict or
// one of our deterministic rules). The forensic timeline keeps Low+ and above; Info telemetry is
// routed to the super-timeline only. See docs/superpowers/specs/2026-07-03-forensic-severity-gate-ioc-provenance-design.md.
export const SEVERITY_RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

const VALID: readonly Severity[] = ["Info", "Low", "Medium", "High", "Critical"];

// Partition events by the forensic cut: `kept` (rank >= min) stay in the forensic timeline, `demoted`
// (below min) are super-timeline-only. Pure; preserves order; never mutates inputs.
export function demoteBelowSeverity(
  events: readonly ForensicEvent[],
  min: Severity,
): { kept: ForensicEvent[]; demoted: ForensicEvent[] } {
  const floor = SEVERITY_RANK[min];
  const kept: ForensicEvent[] = [];
  const demoted: ForensicEvent[] = [];
  for (const e of events) (SEVERITY_RANK[e.severity] >= floor ? kept : demoted).push(e);
  return { kept, demoted };
}

// per-case override ?? global env ?? "Low". An unrecognized env value falls back to "Low".
export function resolveForensicMinSeverity(perCase: Severity | undefined, envValue: string | undefined): Severity {
  if (perCase && VALID.includes(perCase)) return perCase;
  if (envValue && (VALID as readonly string[]).includes(envValue)) return envValue as Severity;
  return "Low";
}
