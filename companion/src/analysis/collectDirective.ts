// Helpers for the structured collection directive (investigation-guidance #8). Kept separate so the
// playbook (task seeding), the deploy UI, and the import-satisfaction matcher all share one rendering
// and one stable target key. PURE — no I/O.

import type { CollectDirective } from "./stateTypes.js";

// A one-line human summary, e.g. "collect Security.evtx 4624 (Windows.EventLogs.Evtx) from ALClient07 —
// expected: the logon chain". "" when the directive names nothing useful.
export function collectSummary(c: CollectDirective | undefined): string {
  if (!c) return "";
  const what = c.logSource || c.artifact || "";
  const artifactSuffix = c.logSource && c.artifact && c.artifact !== c.logSource ? ` (${c.artifact})` : "";
  const from = c.host ? ` from ${c.host}` : "";
  const expected = c.expectedOutcome ? ` — expected: ${c.expectedOutcome}` : "";
  const lead = what ? `collect ${what}${artifactSuffix}` : (c.host ? "collect from" : "");
  const text = `${lead}${from}${expected}`.trim();
  return text;
}

// A stable, case-insensitive key identifying WHAT is being collected WHERE — used to (a) dedup task
// seeds and (b) match a later import back to the open directive it satisfies. Keyed on host +
// logSource/artifact so "Security.evtx on HOST7" and "Sysmon on HOST7" are distinct targets. Returns ""
// when there is no host (an unanchored directive can't be deployed or satisfaction-matched).
export function collectTargetKey(c: CollectDirective | undefined): string {
  if (!c || !c.host) return "";
  const host = c.host.trim().toLowerCase();
  const src = (c.logSource || c.artifact || "").trim().toLowerCase();
  return `${host}|${src}`;
}

// Whether a directive is deployable/actionable at all — it must at least name a host to collect from.
export function isActionableCollect(c: CollectDirective | undefined): c is CollectDirective {
  return !!c && !!c.host && !!c.host.trim();
}
