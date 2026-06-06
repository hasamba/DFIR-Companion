import type { Finding, Severity } from "./stateTypes.js";

// What changed in the findings between two synthesis runs. Synthesis REWRITES findings (new ids
// each run — see pipeline.synthesize), so we diff by normalized TITLE, not id: a finding that
// keeps its title across runs is "the same finding", and a severity change on it is surfaced
// rather than shown as a remove+add pair.

export interface SeverityChange {
  title: string;
  from: Severity;
  to: Severity;
}

export interface FindingsDiff {
  added: string[];                    // titles present after, not before
  removed: string[];                  // titles present before, not after
  severityChanged: SeverityChange[];  // same title, different severity
}

const norm = (title: string): string => String(title).trim().toLowerCase().replace(/\s+/g, " ");

// First occurrence of each normalized title wins (keeps the displayed title + its severity).
function byTitle(findings: readonly Finding[]): Map<string, { title: string; severity: Severity }> {
  const map = new Map<string, { title: string; severity: Severity }>();
  for (const f of findings) {
    const key = norm(f.title);
    if (!key || map.has(key)) continue;
    map.set(key, { title: f.title, severity: f.severity });
  }
  return map;
}

// Compute added / removed / severity-changed findings from `before` → `after`.
export function diffFindings(before: readonly Finding[], after: readonly Finding[]): FindingsDiff {
  const a = byTitle(before);
  const b = byTitle(after);
  const added: string[] = [];
  const removed: string[] = [];
  const severityChanged: SeverityChange[] = [];

  for (const [key, cur] of b) {
    const prev = a.get(key);
    if (!prev) added.push(cur.title);
    else if (prev.severity !== cur.severity) severityChanged.push({ title: cur.title, from: prev.severity, to: cur.severity });
  }
  for (const [key, prev] of a) {
    if (!b.has(key)) removed.push(prev.title);
  }
  return { added, removed, severityChanged };
}

// True when nothing changed — lets callers skip rendering an empty diff.
export function isEmptyDiff(diff: FindingsDiff): boolean {
  return diff.added.length === 0 && diff.removed.length === 0 && diff.severityChanged.length === 0;
}
