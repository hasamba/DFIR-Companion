import type { Finding, Severity } from "./stateTypes.js";

// What changed in the findings between two synthesis runs. A finding is "the same finding" when
// both runs carry the same id — the model updates findings by id, and deterministic backfills
// (f-gap-*, f-waves) keep a fixed id — so a retitled same-id finding is not a remove+add pair (bug
// #5). When the ids differ or one is missing, the normalized TITLE decides, because a model that
// rewrote a finding under a new id still names it the same. A severity change on a matched pair is
// surfaced under its new title.

export interface SeverityChange {
  title: string;
  from: Severity;
  to: Severity;
}

export interface FindingsDiff {
  added: string[]; // titles present after, not before
  removed: string[]; // titles present before, not after
  severityChanged: SeverityChange[]; // same finding (id, else title), different severity
}

interface Entry {
  id: string;
  key: string; // normalized title
  title: string;
  severity: Severity;
}

const norm = (title: string): string => String(title).trim().toLowerCase().replace(/\s+/g, " ");

// First occurrence of each normalized title wins (keeps the displayed title + its severity).
function entries(findings: readonly Finding[]): Entry[] {
  const seen = new Set<string>();
  const out: Entry[] = [];
  for (const f of findings) {
    const key = norm(f.title);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push({ id: typeof f.id === "string" ? f.id : "", key, title: f.title, severity: f.severity });
  }
  return out;
}

// Pair each `after` entry with its `before` entry: by id first, then by title among the entries no id
// claimed. Each `before` entry pairs at most once.
function pairEntries(before: readonly Entry[], after: readonly Entry[]): Map<Entry, Entry> {
  const byId = new Map(before.filter((e) => e.id).map((e) => [e.id, e] as const));
  const pairs = new Map<Entry, Entry>();
  const taken = new Set<Entry>();
  for (const cur of after) {
    const prev = cur.id ? byId.get(cur.id) : undefined;
    if (prev && !taken.has(prev)) {
      pairs.set(cur, prev);
      taken.add(prev);
    }
  }
  const byTitle = new Map(before.filter((e) => !taken.has(e)).map((e) => [e.key, e] as const));
  for (const cur of after) {
    if (pairs.has(cur)) continue;
    const prev = byTitle.get(cur.key);
    if (prev && !taken.has(prev)) {
      pairs.set(cur, prev);
      taken.add(prev);
    }
  }
  return pairs;
}

// Compute added / removed / severity-changed findings from `before` → `after`.
export function diffFindings(before: readonly Finding[], after: readonly Finding[]): FindingsDiff {
  const a = entries(before);
  const b = entries(after);
  const pairs = pairEntries(a, b);
  const matched = new Set(pairs.values());
  const added: string[] = [];
  const severityChanged: SeverityChange[] = [];
  for (const cur of b) {
    const prev = pairs.get(cur);
    if (!prev) added.push(cur.title);
    else if (prev.severity !== cur.severity)
      severityChanged.push({ title: cur.title, from: prev.severity, to: cur.severity });
  }
  const removed = a.filter((e) => !matched.has(e)).map((e) => e.title);
  return { added, removed, severityChanged };
}

// True when nothing changed — lets callers skip rendering an empty diff.
export function isEmptyDiff(diff: FindingsDiff): boolean {
  return diff.added.length === 0 && diff.removed.length === 0 && diff.severityChanged.length === 0;
}
