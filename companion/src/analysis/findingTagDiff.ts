import type { Finding } from "./stateTypes.js";

/**
 * What a re-synthesis did to the ATT&CK tags of the findings it KEPT (#1684).
 *
 * Synthesis rebuilds findings wholesale, so a technique could leave a finding whose facts did not
 * change and nothing recorded it. This compares the findings present both before and after the run
 * (same id) and reports each one whose tag set moved. A new or removed finding is not a tag change.
 * Pure.
 */
export interface FindingTagDiff {
  findingId: string;
  added: string[];
  removed: string[];
}

/** Activity-log lines per run; a case with hundreds of findings must not flood the log. */
export const MAX_TAG_DIFF_LINES = 25;

export function diffFindingTags(before: readonly Finding[], after: readonly Finding[]): FindingTagDiff[] {
  const prior = new Map(before.map((f) => [f.id, new Set(f.mitreTechniques)] as const));
  const out: FindingTagDiff[] = [];
  for (const f of after) {
    const was = prior.get(f.id);
    if (!was) continue;
    const now = new Set(f.mitreTechniques);
    const added = [...now].filter((t) => !was.has(t)).sort();
    const removed = [...was].filter((t) => !now.has(t)).sort();
    if (added.length || removed.length) out.push({ findingId: f.id, added, removed });
  }
  return out;
}

/** One line per changed finding, capped at MAX_TAG_DIFF_LINES plus one line counting the rest. */
export function describeFindingTagDiffs(diffs: readonly FindingTagDiff[]): string[] {
  const lines = diffs.slice(0, MAX_TAG_DIFF_LINES).map((d) => {
    const parts = [
      d.added.length ? `added ${d.added.join(", ")}` : "",
      d.removed.length ? `removed ${d.removed.join(", ")}` : "",
    ].filter(Boolean);
    return `finding ${d.findingId} ATT&CK tags changed on re-synthesis — ${parts.join("; ")}`;
  });
  const rest = diffs.length - MAX_TAG_DIFF_LINES;
  return rest > 0 ? [...lines, `${rest} more finding(s) had ATT&CK tag changes on re-synthesis`] : lines;
}
