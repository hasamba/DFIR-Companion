// Rows whose severity IS a security product's own verdict (#2361): a GuardDuty finding is graded by
// GuardDuty's score, and an archived one is Info on purpose. The content tagger reads the row's text,
// which here carries adversary-reachable resource names and descriptions — a bucket called
// `ntds.dit` would otherwise match the Windows NTDS rule, raise an archived finding to High and add
// a credential-dumping technique the finding never established. So, like a collector row (#1477),
// such a row keeps its import grade and its MITRE through the stream pre-grade and the settle
// tagger; tags still describe it. Matched on the row's source name, which only the importer sets.

/** The source names (ForensicEvent.sources) whose rows carry a vendor's own grade. */
export const GUARDDUTY_SOURCE = "AWS GuardDuty";
// AI Agent Forensics rows (#2690) carry the run's provisional grade, and their text is attacker-
// planted by design: a tagger rule must not raise a hit on it, nor lift an inventory row (Info, so
// super-timeline only) into the forensic timeline.
export const AI_AGENT_FORENSICS_SOURCE = "AI Agent Forensics";
const VENDOR_GRADED = new Set<string>([GUARDDUTY_SOURCE, AI_AGENT_FORENSICS_SOURCE]);

/** True when the row's severity and MITRE are the vendor's own and no tagger rule may change them. */
export function keepsVendorGrade(row: { sources?: readonly string[] }): boolean {
  return !!row.sources?.some((s) => VENDOR_GRADED.has(s));
}
