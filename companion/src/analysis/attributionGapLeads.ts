// Gap leads from an analyst's own attribution assertion (#1405).
//
// An assertion whose free-text label IS a known ATT&CK group's name or alias (attributionGroupMatch.ts —
// exact match, never a substring, never written to the record) names the techniques that group is
// documented to use. The ones this case's graded evidence has NOT shown are hunt leads: something
// to look for, never evidence of absence, and never attribution — the assertion is the analyst's
// claim, this list only says what that claim would predict and the case has not yet shown.
//
// Distinct from adversaryEmulation.ts (#121), which does the same subtraction for the groups a
// STATISTICAL overlap matched. Here the anchor is the analyst's decision. Read-time only: nothing is
// stored, nothing is scored, no AI path reads it.

import { matchAdversaryGroupId } from "./attributionGroupMatch.js";
import { attackTechniqueUrl } from "./attack.js";
import { collectCaseTechniques } from "./adversaryHints.js";
import { adversaryGroupUrl } from "./adversaryHints.js";
import { baseTechniqueId, normalizeTechniqueId, type AdversaryGroup } from "./adversaryTechniques.js";
import { tacticForTechniques } from "./mitreTactics.js";
import type { InvestigationState } from "./stateTypes.js";

/** Techniques listed per assertion; the rest are counted in `total`. */
export const GAP_LEADS_MAX = 15;

export const GAP_LEADS_CAVEAT =
  "hunt leads from your own assertion — never evidence of absence, never attribution";
export const GAP_LEADS_BASIS =
  "the group's ATT&CK technique list against this case's graded evidence (findings, forensic-timeline events, case techniques); not observed ≠ did not happen";

// The same kill-chain order adversaryEmulation.ts ranks by: the stages that cost most first.
const TACTIC_RANK: Record<string, number> = {
  Impact: 0,
  Exfiltration: 1,
  "Credential Access": 2,
  "Lateral Movement": 3,
  "Privilege Escalation": 4,
  Persistence: 5,
  Collection: 6,
  "Command and Control": 7,
  "Initial Access": 8,
  Discovery: 9,
  "Defense Evasion": 10,
  Execution: 11,
};
const UNSPECIFIED = "Unspecified";

export interface GapLeadTechnique {
  id: string;
  name?: string;
  url: string | null;
  tactic: string;
  dataSources?: string[];
}

export interface AttributionGapLead {
  assertionId: string;
  tier: string;
  label: string;
  group: { id: string; name: string; url: string };
  techniques: GapLeadTechnique[];
  /** Group techniques the case has shown (at base-or-better) — counted, not listed. */
  observedCount: number;
  /** Group techniques not shown, before the bound. */
  total: number;
  basis: typeof GAP_LEADS_BASIS;
  caveat: typeof GAP_LEADS_CAVEAT;
}

export interface AttributionGapLeadsResult {
  leads: AttributionGapLead[];
  /** Active assertions with no matching group — counted so the panel can say so. */
  unmatchedAssertions: number;
}

interface AssertionShape {
  id: string;
  tier: string;
  label: string;
  status?: string;
}
interface DatasetShape {
  groups: readonly AdversaryGroup[];
  techniqueInfo: Record<string, { name?: string; dataSources?: string[] }>;
}

/**
 * Observed at base-or-better in either direction: a case sub-technique covers the group's base
 * (T1059.001 shown → T1059 is not a gap); a case base covers the group's sub-techniques (T1059
 * shown → T1059.001 is not a gap). A SIBLING sub-technique is another technique: PowerShell shown
 * does not cover Windows Command Shell.
 */
function observed(id: string, exact: ReadonlySet<string>, bases: ReadonlySet<string>): boolean {
  if (exact.has(id)) return true;
  const base = baseTechniqueId(id);
  if (base === null) return false;
  return base === id ? bases.has(id) : exact.has(base);
}

export function attributionGapLeads(
  state: InvestigationState,
  assertions: readonly AssertionShape[],
  dataset: DatasetShape,
): AttributionGapLeadsResult {
  const caseTechniques = collectCaseTechniques(state);
  const exact = new Set(caseTechniques);
  const bases = new Set(caseTechniques.map((t) => baseTechniqueId(t)).filter((b): b is string => b !== null));
  const byId = new Map(dataset.groups.map((g) => [g.id, g]));
  const leads: AttributionGapLead[] = [];
  let unmatched = 0;
  for (const a of assertions) {
    if (a.status === "retracted") continue;
    const gid = matchAdversaryGroupId(a.label, dataset.groups);
    const group = gid ? byId.get(gid) : undefined;
    if (!group) {
      unmatched += 1;
      continue;
    }
    const ids = [
      ...new Set(group.techniques.map((t) => normalizeTechniqueId(t)).filter((t): t is string => t !== null)),
    ];
    const missing = ids.filter((id) => !observed(id, exact, bases));
    const rows = missing
      .map((id) => {
        const info = dataset.techniqueInfo[id] ?? dataset.techniqueInfo[baseTechniqueId(id) ?? ""];
        return {
          id,
          ...(info?.name ? { name: info.name } : {}),
          url: attackTechniqueUrl(id),
          tactic: tacticForTechniques([id]) ?? UNSPECIFIED,
          ...(info?.dataSources?.length ? { dataSources: info.dataSources } : {}),
        };
      })
      .sort(
        (x, y) => (TACTIC_RANK[x.tactic] ?? 99) - (TACTIC_RANK[y.tactic] ?? 99) || x.id.localeCompare(y.id),
      );
    leads.push({
      assertionId: a.id,
      tier: a.tier,
      label: a.label,
      group: { id: group.id, name: group.name, url: adversaryGroupUrl(group.id) },
      techniques: rows.slice(0, GAP_LEADS_MAX),
      observedCount: ids.length - missing.length,
      total: missing.length,
      basis: GAP_LEADS_BASIS,
      caveat: GAP_LEADS_CAVEAT,
    });
  }
  return { leads, unmatchedAssertions: unmatched };
}
