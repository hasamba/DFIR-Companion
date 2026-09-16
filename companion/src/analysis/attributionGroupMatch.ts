import type { AdversaryGroup } from "./adversaryTechniques.js";

// Optional, read-time-only, informational cross-reference from an attribution assertion's own
// free-text `label` to a known MITRE ATT&CK group (#933 item 20). Never written to the stored
// record, never used to validate or auto-fill a label — the exact "reference, never derive"
// posture already established for adversaryHints.ts's own hints. Exact (case-insensitive) match
// only, never a substring — a label that happens to contain a group's name is not the same claim
// as a label that IS that group's name/alias.
export function matchAdversaryGroupId(label: string, groups: readonly AdversaryGroup[]): string | null {
  const target = label.trim().toLowerCase();
  if (!target) return null;
  for (const group of groups) {
    if (group.name.toLowerCase() === target) return group.id;
    if (group.aliases.some((a) => a.toLowerCase() === target)) return group.id;
  }
  return null;
}
