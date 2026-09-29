import { techniqueName } from "./attackTechniqueNames.js";
import { isDeterministicFindingId } from "./responseSchema.js";
import type { Finding, InvestigationState, Technique } from "./stateTypes.js";

// The ATT&CK techniques a finding's own words name (#1873).
//
// On scenario 023 one synthesis grouped 19 staged batch scripts into one finding whose text said
// "shadow-copy deletion, log clearing, Defender tampering, backup deletion and forced logoff" — and
// tagged it with staging and PowerShell only. Earlier runs had split the same roles into separate
// findings and tagged them, so the MITRE panel, the reports and the exports lost five techniques on
// a grouping choice alone.
//
// Derived at projection, never stored — the same rule as event-carried techniques (#893). The
// synthesis fold only ever LOWERS a model claim, and a regex over prose is not a model assertion,
// so writing these into state would make an inference indistinguishable from a conclusion and
// leave it behind when the finding changes. As a view it follows the finding: dismiss or reword the
// finding and the technique goes with it, and an accepted referee removal (#1742) still hides it,
// because every seam applies that projection afterwards.
//
// Deliberately narrow: capability PHRASES only, never file names (shadow.bat was a backdoor in
// scenario 023, not a shadow-copy wiper), and only five techniques, each with an unambiguous phrase.

const CAPABILITIES: ReadonlyArray<{ id: string; re: RegExp }> = [
  {
    id: "T1490",
    re: /\bshadow[- ]cop(?:y|ies)\s+(?:deletion|removal|wip\w*)|\bshadow[- ]cop(?:y|ies)\s+(?:were|was|are|is)\s+(?:deleted|removed|wiped)|\bdelet\w*\s+(?:(?:the|all|volume)\s+)*shadow[- ]cop(?:y|ies)|\binhibit\w*\s+(?:system\s+)?recovery|\bbackup\s+(?:catalog\s+)?(?:deletion|removal|wip\w*)|\bdelet\w*\s+(?:(?:the|all)\s+)*backups?\b|\bvssadmin\b[^.;]*\bdelete\s+shadows\b/i,
  },
  {
    id: "T1070.001",
    re: /\b(?:event[- ])?log[- ]clear\w*|\bclear\w*\s+(?:the\s+)?(?:(?:windows|event|security|system|application)\s+)*logs?\b|\bwevtutil(?:\.exe)?\s+cl\b/i,
  },
  {
    id: "T1562.001",
    re: /\bdefender\s+tamper\w*|\btamper\w*\s+with\s+(?:microsoft\s+)?defender|\bdisabl\w*\s+(?:(?:microsoft|windows)\s+)?defender|\bdisabl\w*\s+(?:the\s+)?(?:antivirus|anti-virus|edr|security\s+tools?)\b/i,
  },
  {
    id: "T1489",
    re: /\b(?:stop\w*|kill\w*|terminat\w*)\s+(?:[\w-]+\s+){0,3}services?\b|\bservice\s+(?:termination|stopping|shutdown)\b/i,
  },
  {
    id: "T1531",
    re: /\bforc\w*\s+log\s*-?\s*offs?\b|\blog\s*-?\s*off\s+(?:of\s+)?all\s+(?:users|sessions)\b|\block\w*\s+out\s+(?:all\s+)?users\b|\baccount\s+access\s+removal\b/i,
  },
];

// A sentence ends at . ! ? followed by space, or at a line break — the findingCitations.ts rule, so
// the dot in shadow.bat does not split. Title and description are joined by a line break for it.
const SENTENCE_END = /(?<=[.!?])\s+|\n+/;

// A contrast or a semicolon opens a new claim: "staged log clearing, but none ran" keeps the first.
const CLAUSE_END = /;|\b(?:but|however|although|though|yet|whereas|while)\b/i;

// A clause that denies the capability, or only asks, prevents, detects or imagines it, asserts
// nothing about the attacker. Conservative: a missed tag costs less than an invented one.
const NOT_ASSERTED =
  /\b(?:no|not|never|none|nothing|neither|nor|without|absent|lacks?|lacking|lacked|prevent\w*|block\w*|detect\w*|whether|if|unless|could|would|might|may|investigate\w*|check\w*|verify|confirm\w*|fail\w*|designed)\b|n't\b/i;

/** The capability techniques a text asserts, in the order it first names them. */
export function capabilityTechniques(text: string): string[] {
  const hits: Array<{ id: string; at: number }> = [];
  let offset = 0;
  for (const sentence of text.split(SENTENCE_END)) {
    for (const clause of sentence.split(CLAUSE_END)) {
      if (clause && !NOT_ASSERTED.test(clause)) {
        for (const { id, re } of CAPABILITIES) {
          const m = re.exec(clause);
          if (m) hits.push({ id, at: offset + m.index });
        }
      }
      offset += clause.length + 1;
    }
  }
  const ordered = hits.sort((a, b) => a.at - b.at).map((h) => h.id);
  return [...new Set(ordered)];
}

// A backfill's finding re-derives its tags from its events (#1684), dismissed findings are not
// conclusions, and Info is this product's "not attacker activity" grade — the benign-noise and
// lab-build notes — so none of them may add an attacker technique from its prose.
function eligible(f: Finding): boolean {
  return !isDeterministicFindingId(f.id) && f.status !== "dismissed" && f.severity !== "Info";
}

function linkRow(rows: Technique[], id: string, findingId: string): Technique[] {
  const at = rows.findIndex((t) => t.id === id);
  if (at < 0) return [...rows, { id, name: techniqueName(id), findingIds: [findingId] }];
  const row = rows[at];
  if (row.findingIds.includes(findingId)) return rows;
  return rows.map((t, i) => (i === at ? { ...t, findingIds: [...t.findingIds, findingId] } : t));
}

/**
 * The state with each eligible finding's text-named techniques on the finding and in the table.
 * A VIEW: pure and idempotent. Apply it before `withoutRejectedTechniques`.
 */
export function withFindingTextTechniques(state: InvestigationState): InvestigationState {
  // `?? []` because the live push is transport and may be handed a partial state (live/hub.ts).
  if (!state.findings?.length) return state;
  let rows = state.mitreTechniques ?? [];
  const findings = state.findings.map((f) => {
    if (!eligible(f)) return f;
    const named = capabilityTechniques(`${f.title ?? ""}\n${f.description ?? ""}`);
    for (const id of named) rows = linkRow(rows, id, f.id);
    const tags = f.mitreTechniques ?? [];
    const missing = named.filter((id) => !tags.includes(id));
    return missing.length ? { ...f, mitreTechniques: [...tags, ...missing] } : f;
  });
  return { ...state, findings, mitreTechniques: rows };
}
