// The vocabulary adversary hints and adversary emulation BOTH speak: what a group is, what a ranked
// hint is, and how a technique id is normalized.
//
// It exists to break a cycle rather than to add a layer. adversaryHints.ts called
// suggestNextTechniques() from adversaryEmulation.ts, and adversaryEmulation.ts imported the id
// helpers and the two record shapes back from adversaryHints.ts — so each module needed the other
// loaded first. Node tolerates that until an import is evaluated at module scope rather than call
// time, at which point one side sees `undefined` and the failure looks like a data bug rather than
// a load-order bug. The ratchet in scripts/check-imports.mjs recorded it as the one known cycle.
//
// The direction is now: hints -> emulation -> here, and hints -> here. Nothing imports back.
//
// What belongs here is only what BOTH sides need. suggestNextTechniques stays in emulation and
// rankAdversaryHints stays in hints — moving either would make this a dumping ground instead of a
// shared vocabulary, and the next cycle would form inside it.

/** One adversary group's slimmed record from the bundled dataset. `techniques` carries ATT&CK ids at
 *  full granularity — sub-technique (T1059.001) where MITRE maps it, base (T1486) otherwise. */
export interface AdversaryGroup {
  id: string; // ATT&CK group id, e.g. "G0016"
  name: string; // e.g. "APT29"
  aliases: string[]; // other names, e.g. ["Cozy Bear", "The Dukes"]
  description: string; // short attribution/sector context
  techniques: string[]; // technique ids (sub-technique where mapped), e.g. ["T1059.001", "T1486"]
}

/** A ranked match: a group whose technique set overlaps the case's by at least `minOverlap`
 *  (counted at base-or-better), ordered by a weighted score that rewards exact sub-technique
 *  agreement.
 *
 *  CRUCIAL FRAMING, repeated here because this is the shape that travels: this is statistical
 *  technique-overlap similarity, NOT attribution. `groupTechniqueCount` rides along precisely so a
 *  reader can weigh "4 of 12" (focused) against "4 of 150" (diffuse). */
export interface AdversaryHint {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  url: string; // attack.mitre.org group page
  overlapCount: number; // distinct case techniques the group shares at base-or-better (breadth)
  exactCount: number; // of those, EXACT (same sub-technique / id) matches — the strong signal
  overlapTechniques: string[]; // all matched case technique ids (full granularity), sorted
  exactTechniques: string[]; // the subset matched exactly (full-id equality), sorted
  groupTechniqueCount: number; // distinct techniques attributed to the group (context for the ratio)
  score: number; // weighted: exactCount + BASE_MATCH_WEIGHT × (overlapCount − exactCount)
}

const TECHNIQUE_RE = /^T(\d{4})(?:\.(\d{3}))?$/; // technique or sub-technique id

/** Normalize a technique id to its full, validated form, KEEPING the sub-technique:
 *  "t1059.001" → "T1059.001", "T1486" → "T1486". Null when it isn't a valid technique id. */
export function normalizeTechniqueId(raw: string): string | null {
  const m = TECHNIQUE_RE.exec(raw.trim().toUpperCase());
  if (!m) return null;
  return m[2] ? `T${m[1]}.${m[2]}` : `T${m[1]}`;
}

/** The BASE technique of an id ("T1059.001" → "T1059", "T1486" → "T1486"), or null when invalid.
 *  Used to award partial credit when the case and a group share a technique but differ on the sub. */
export function baseTechniqueId(raw: string): string | null {
  const m = TECHNIQUE_RE.exec(raw.trim().toUpperCase());
  return m ? `T${m[1]}` : null;
}
