// The deterministic finding for commands nobody accounted for (#1531).
//
// On INC-2026-001 the Phase-2 script block was read by the model and folded into f3 — a finding
// about mimikatz and LSASS. The block's `nltest /dclist:`, `Get-ADGroupMember "Domain Admins"`,
// `Get-GPResultantSetOfPolicy`, `ntdsutil … ifm` and psexec_psh pipe are in none of the case's 23
// findings and none of its 32 techniques. The row was not UNCOVERED in the sense the High backfill
// means — it had a finding — so no safety net fired.
//
// So coverage here is asked of the FINDING'S CONTENT, not of the link: a row's commands are
// accounted for when a finding the row is linked to carries the technique they map to. What is left
// over is the gap, and it earns one Medium finding per host, per script signature, per day, naming
// the literal commands.
//
// ORDER. Runs AFTER backfillHighSeverityFindings (ai/synthesisMerge.ts). Running before it would
// let this Medium finding claim an uncovered High row and rob that row of the confidence-100 High
// backfill that exists to stop a severe detection being missed. Running after costs nothing,
// because the f-auto finding a High row gets carries that row's own techniques — so this pass then
// reads them as covered and stays quiet.
//
// WHAT IT CLAIMS. A 4104 record is compiled script TEXT. The block this was written for says
// `executed=$false` and `blockedBy='Windows Defender'` about its own ntdsutil attempt. The finding
// therefore says the commands are PRESENT in logged script content, repeats any such qualifier it
// finds, and states plainly that logged content is not proof the commands ran. Severity is Medium
// and nothing is ever raised.
//
// Pure: returns a new state, never mutates. Idempotent: the id is derived from the lex-first event
// id in each group, and a second run reads its own finding as coverage.

import { AUTO_FINDING_ID_PREFIX, SCRIPT_COMMAND_FINDING_ID_PREFIX } from "./responseSchema.js";
import { scriptCommandFacts, type ScriptCommandMatch } from "./scriptBlockCommands.js";
import type { Finding, ForensicEvent, InvestigationState } from "./stateTypes.js";

/** A lead about content, not a confirmed action — the same moderate footing a coverage gap gets. */
const CONFIDENCE = 55;
/** Commands named in the description; the row itself holds the rest. */
const COMMANDS_NAMED = 6;
/** Status qualifiers repeated verbatim, so "blocked" never disappears between the row and the finding. */
const QUALIFIER =
  /\b(?:executed|remote|pipeCreated|ntdsAccessed|actualInjection|actualAccess)\s*=\s*\$?false\b|\bblockedBy\s*=\s*'[^'\n]{1,40}'|\bblocked\s+by\s+[\w ]{1,30}/gi;
const MAX_QUALIFIERS = 3;

/** The techniques every finding this row is linked to already carries. */
function coveredTechniques(e: ForensicEvent, findingById: Map<string, Finding>): Set<string> {
  const out = new Set<string>();
  for (const fid of e.relatedFindingIds) {
    for (const t of findingById.get(fid)?.mitreTechniques ?? []) out.add(t);
  }
  return out;
}

/**
 * Is what is left over worth a finding of its own?
 *
 * One HIGH-specificity command is (trust enumeration, an IFM dump, a pipe or shadow copy with its
 * corroborating context). One low-specificity command is not: `Get-Process` in a script block is
 * ordinary administration, and minting a finding for it would bury the real ones. Two distinct
 * uncovered techniques clear the bar together — a sweep is a sweep.
 */
function worthAFinding(facts: readonly ScriptCommandMatch[], uncovered: ReadonlySet<string>): boolean {
  if (uncovered.size === 0) return false;
  if (uncovered.size >= 2) return true;
  return facts.some((f) => f.specificity === "high" && f.techniques.some((t) => uncovered.has(t)));
}

/** The status qualifiers the row's own text states about these commands, verbatim and deduped. */
function qualifiers(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(QUALIFIER)) {
    const q = m[0].replace(/\s+/gu, " ").trim();
    if (!out.some((x) => x.toLowerCase() === q.toLowerCase())) out.push(q);
    if (out.length >= MAX_QUALIFIERS) break;
  }
  return out;
}

interface Group {
  events: ForensicEvent[];
  facts: ScriptCommandMatch[];
  uncovered: Set<string>;
}

// One group per host, per set of commands, per UTC day: the five detector views of ONE script block
// collapse into one finding, while two different scripts — or the same script months later — stay
// apart. A host the record did not name groups under "(host not recorded)" with the commands still
// separating it, never with every hostless row in the case.
function groupKey(e: ForensicEvent, facts: readonly ScriptCommandMatch[]): string {
  const host = e.asset || "(host not recorded)";
  const day = (e.timestamp || "").slice(0, 10);
  const signature = facts
    .map((f) => f.command.toLowerCase())
    .sort()
    .join("|");
  return `${host}\n${day}\n${signature}`;
}

function describe(g: Group, repEvent: ForensicEvent): string {
  const named = g.facts.slice(0, COMMANDS_NAMED).map((f) => f.command);
  const more = g.facts.length > named.length ? `, +${g.facts.length - named.length} more` : "";
  const host = repEvent.asset ? ` on ${repEvent.asset}` : "";
  const views =
    g.events.length > 1 ? ` The same script content was reported by ${g.events.length} rows.` : "";
  const notes = qualifiers(`${repEvent.description ?? ""}\n${(repEvent.message ?? "").slice(0, 20000)}`);
  const status = notes.length
    ? ` The script's own text records: ${notes.join("; ")} — read those before treating any of this as an action that completed.`
    : "";
  return (
    `A logged PowerShell script record${host} contains discovery and credential-access commands that no ` +
    `other finding in this case accounts for: ${named.join("; ")}${more}. ` +
    `A script-block record is the COMPILED TEXT of a script — a function body, a string array, a branch ` +
    `that may never have run — so this is evidence the commands were present, not that they executed.` +
    `${status}${views} Corroborate against process creations, 4688/Sysmon EID 1, and the artifacts each ` +
    `command would leave before reporting any of them as performed.`
  );
}

/**
 * Mint the Medium "commands present in logged script content" finding for every script record whose
 * commands no linked finding accounts for. `eligibleIds` is the synthesis scope; the collector and
 * non-script guards live in scriptBlockCommands.ts. Pure + idempotent.
 */
export function backfillScriptCommandFindings(
  state: InvestigationState,
  eligibleIds: ReadonlySet<string>,
  timestamp: string,
): InvestigationState {
  const findingById = new Map(state.findings.map((f) => [f.id, f] as const));
  const groups = new Map<string, Group>();
  // Techniques to fold into a finding the HIGH backfill just minted for the same row, instead of
  // minting a second one beside it.
  const enrich = new Map<string, Set<string>>();
  for (const e of state.forensicTimeline) {
    if (!eligibleIds.has(e.id)) continue;
    const facts = scriptCommandFacts(e);
    if (!facts.length) continue;
    const covered = coveredTechniques(e, findingById);
    const uncovered = new Set(facts.flatMap((f) => f.techniques).filter((t) => !covered.has(t)));
    if (!worthAFinding(facts, uncovered)) continue;
    // A row imported BEFORE this feature carries none of the new techniques, so the f-auto finding
    // the High backfill built from it a moment ago does not carry them either — and the rule above
    // would then read them as uncovered and raise a Medium finding on a row that already has one.
    // Two findings for one script block is noise, so the techniques go INTO the f-auto finding,
    // which is machine-owned and rebuilt on every run (highSeverityFindings.ts).
    const autoId = e.relatedFindingIds.find((id) => id.startsWith(AUTO_FINDING_ID_PREFIX));
    if (autoId && findingById.has(autoId)) {
      const set = enrich.get(autoId) ?? new Set<string>();
      for (const t of uncovered) set.add(t);
      enrich.set(autoId, set);
      continue;
    }
    const key = groupKey(e, facts);
    const group = groups.get(key);
    if (!group) {
      groups.set(key, { events: [e], facts, uncovered });
      continue;
    }
    group.events.push(e);
    // The group's claim is the INTERSECTION of what its rows still need: a technique one row's own
    // finding already carries is covered for that row, and the group must not re-assert it.
    for (const t of [...group.uncovered]) if (!uncovered.has(t)) group.uncovered.delete(t);
  }
  if (!groups.size && !enrich.size) return state;

  const existingIds = new Set(state.findings.map((f) => f.id));
  const newFindings: Finding[] = [];
  const linkByEvent = new Map<string, string>();
  for (const g of groups.values()) {
    if (!g.uncovered.size) continue;
    const repId = [...g.events].map((e) => e.id).sort((a, b) => a.localeCompare(b))[0];
    const id = `${SCRIPT_COMMAND_FINDING_ID_PREFIX}${repId}`;
    const repEvent = g.events.find((e) => e.id === repId)!;
    for (const e of g.events) linkByEvent.set(e.id, id);
    if (existingIds.has(id)) continue; // already in the case — link to it, do not mint a second
    existingIds.add(id);
    const host = repEvent.asset ? ` on ${repEvent.asset}` : "";
    newFindings.push({
      id,
      severity: "Medium",
      confidence: CONFIDENCE,
      confidenceReason:
        "Deterministic: the commands are read from the logged script text itself, but a logged script block does not establish that they ran.",
      title: `Discovery and credential-access commands present in logged PowerShell script content${host}`,
      description: describe(g, repEvent),
      relatedIocs: [],
      mitreTechniques: [...g.uncovered],
      sourceScreenshots: [...new Set(g.events.flatMap((e) => e.sourceScreenshots ?? []))],
      firstSeen:
        g.events
          .map((e) => e.timestamp)
          .filter(Boolean)
          .sort()[0] || timestamp,
      lastUpdated: timestamp,
      status: "open",
    });
  }
  if (!linkByEvent.size && !enrich.size) return state;

  const enriched = state.findings.map((f) => {
    const add = enrich.get(f.id);
    if (!add?.size) return f;
    const mitreTechniques = [...new Set([...f.mitreTechniques, ...add])];
    return mitreTechniques.length === f.mitreTechniques.length ? f : { ...f, mitreTechniques };
  });

  return {
    ...state,
    findings: [...enriched, ...newFindings],
    forensicTimeline: state.forensicTimeline.map((e) => {
      const id = linkByEvent.get(e.id);
      return id && !e.relatedFindingIds.includes(id)
        ? { ...e, relatedFindingIds: [...e.relatedFindingIds, id] }
        : e;
    }),
  };
}
