// Gate-aware "minimum severity to import" floor, applied uniformly to every importer by the
// unified Import button (POST /cases/:id/import). Restores the old per-format "which minimum
// severity?" prompt — but generalized to our canonical Severity and made gate-aware so it is
// safe across importers that don't grade severity.
//
// The rule (per import):
//   • No floor, or an "Info" floor                  → import everything (Info = the lowest rung).
//   • The import carries NO graded severity          → import everything ("if there are no
//     (every event is Info — KAPE / Plaso / plain      severities, import everything"). A floor
//     telemetry)                                       would otherwise wrongly nuke the whole feed.
//   • The import HAS graded severity (≥1 event       → keep only events at or above the floor
//     above Info — THOR / SIEM / Chainsaw / sandbox    ("import only those the user selected and
//     / …)                                             above"); below-floor rows (incl. Info) drop.
//
// Why "any event above Info" = "has severities": in DFIR triage, Info means telemetry / no
// verdict, not a severity rating. So an all-Info import has nothing to discriminate on, while a
// mixed import (e.g. Velociraptor: Sigma detections + EventLog Info, or Cyber Triage: scored +
// unscored) is correctly treated as graded and floored. The gate is computed at runtime from the
// produced events, so it stays correct for mixed importers and any importer added later.

import type { Severity } from "./stateTypes.js";

// Lower number = more severe. Matches the ranking used across the codebase (correlate, assetGraph…).
export const SEVERITY_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// True when at least one event carries a real (above-Info) severity verdict — i.e. the import
// grades severity and a floor is meaningful. All-Info / empty → false (nothing to discriminate on).
export function hasGradedSeverity(events: ReadonlyArray<{ severity: Severity }>): boolean {
  return events.some((e) => SEVERITY_RANK[e.severity] < SEVERITY_RANK.Info);
}

// Apply the minimum-severity floor with the gate above. Returns the input unchanged when there is
// no meaningful floor to apply (no/Info floor, or an ungraded import); otherwise keeps only events
// at or above `minSeverity`. Pure — never mutates the input array.
export function applySeverityFloor<T extends { severity: Severity }>(events: T[], minSeverity?: Severity): T[] {
  if (!minSeverity || minSeverity === "Info") return events;   // no floor / "import everything"
  if (!hasGradedSeverity(events)) return events;               // no severities → import everything
  const floor = SEVERITY_RANK[minSeverity];
  return events.filter((e) => SEVERITY_RANK[e.severity] <= floor);
}

// Normalize free-form user input (a dashboard prompt / request body) to a canonical Severity.
// Unrecognized input → undefined (treated as "import everything"), so a typo never drops evidence.
export function parseMinSeverity(raw: unknown): Severity | undefined {
  switch (String(raw ?? "").trim().toLowerCase()) {
    case "critical": return "Critical";
    case "high": return "High";
    case "medium": return "Medium";
    case "low": return "Low";
    case "info": return "Info";
    default: return undefined;
  }
}
