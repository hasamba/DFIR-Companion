// The deterministic finding for C2 settings a logged script block defines (#1959).
//
// On INC-2026-001 a script block held a whole beacon configuration — domains, addresses, a port,
// sleep/jitter, GET/POST paths and a watermark. The model linked the row to a C2 finding that named
// none of those values; they reached only the IOC list. This pass turns "the script defines C2
// infrastructure" into a finding whenever no finding linked to the row already names it.
//
// COVERAGE is asked of a linked finding's TEXT: the row is covered when ONE linked finding's title or
// description names every infrastructure value (domain / address) the config holds. That is also
// what makes the pass idempotent — the finding it mints names them all.
//
// ORDER. Runs after backfillScriptCommandFindings (ai/synthesisMerge.ts), so an f-auto finding the
// High backfill built for the row — which repeats the row's own text — counts as coverage first.
//
// WHAT IT CLAIMS. A 4104 record is script TEXT. The real block this was written for says
// `actualConnections='127.0.0.1 only'; beaconIncluded=$false` about itself. So the finding repeats
// any such qualifier, says plainly the settings are script content and not a proven connection,
// claims no technique, and is Medium. Nothing is ever raised.
//
// Pure: returns a new state, never mutates. One finding per host, per config signature, per UTC day.

import { SCRIPT_C2_FINDING_ID_PREFIX } from "./responseSchema.js";
import { scriptC2Config, type ScriptC2Config } from "./scriptBlockC2Config.js";
import type { Finding, ForensicEvent, InvestigationState } from "./stateTypes.js";

/** A lead about content, not a confirmed connection — the same footing as the #1531 finding. */
const CONFIDENCE = 55;
/** Status qualifiers repeated verbatim, so "only localhost" never disappears between row and finding. */
const QUALIFIER =
  /\b(?:executed|beaconIncluded|connected|actualConnection|remote)\s*=\s*\$?false\b|\b(?:blockedBy|actualConnections?)\s*=\s*'[^'\n]{1,40}'|\bblocked\s+by\s+[\w ]{1,30}/gi;
const MAX_QUALIFIERS = 3;
const QUALIFIER_SCAN = 20000;

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

/** Does this text name the value as a whole token — not inside a longer name or address? */
function names(text: string, value: string): boolean {
  return new RegExp(`(?<![\\w.-])${escapeRe(value)}(?!\\.?[\\w-])`, "iu").test(text);
}

function coveredBy(e: ForensicEvent, config: ScriptC2Config, findingById: Map<string, Finding>): boolean {
  return e.relatedFindingIds.some((fid) => {
    const f = findingById.get(fid);
    if (!f) return false;
    const text = `${f.title}\n${f.description}`;
    return config.infrastructure.every((v) => names(text, v));
  });
}

/** The status qualifiers the row's own text states about itself, cleaned and deduped. */
function qualifiers(e: ForensicEvent): string[] {
  const text = `${e.description ?? ""}\n${(e.message ?? "").slice(0, QUALIFIER_SCAN)}`;
  const out: string[] = [];
  for (const m of text.matchAll(QUALIFIER)) {
    const q = m[0]
      .replace(/[<>\u0000-\u001f\u007f]/gu, " ")
      .replace(/\s+/gu, " ")
      .trim();
    if (!out.some((x) => x.toLowerCase() === q.toLowerCase())) out.push(q);
    if (out.length >= MAX_QUALIFIERS) break;
  }
  return out;
}

interface Group {
  events: ForensicEvent[];
  config: ScriptC2Config;
}

function groupKey(e: ForensicEvent, config: ScriptC2Config): string {
  const host = e.asset || "(host not recorded)";
  const day = (e.timestamp || "").slice(0, 10);
  const signature = config.entries
    .map((x) => `${x.key.toLowerCase()}=${x.value.toLowerCase()}`)
    .sort()
    .join("|");
  return `${host}\n${day}\n${signature}`;
}

function describe(g: Group, repEvent: ForensicEvent): string {
  const host = repEvent.asset ? ` on ${repEvent.asset}` : "";
  const settings = g.config.entries.map((x) => `${x.key}=${x.value}`).join("; ");
  const views =
    g.events.length > 1 ? ` The same script content was reported by ${g.events.length} rows.` : "";
  const notes = qualifiers(repEvent);
  const status = notes.length
    ? ` The script's own text records: ${notes.join("; ")} — read those before treating any of this as traffic that happened.`
    : "";
  return (
    `A logged PowerShell script record${host} defines C2-style settings that no other finding in this ` +
    `case names: ${settings}. Infrastructure named: ${g.config.infrastructure.join(", ")}. ` +
    `A script-block record is the COMPILED TEXT of a script, so these settings are script content, ` +
    `not a proven connection.${status}${views} Corroborate against network telemetry (Sysmon EID 3, ` +
    `DNS, proxy and firewall logs) before reporting any connection to this infrastructure.`
  );
}

/**
 * Mint the Medium "C2 settings defined in logged script content" finding for every script record
 * whose C2 infrastructure no linked finding names. `eligibleIds` is the synthesis scope; the collector
 * and non-script guards live in scriptBlockC2Config.ts. Pure + idempotent.
 */
export function backfillScriptC2Findings(
  state: InvestigationState,
  eligibleIds: ReadonlySet<string>,
  timestamp: string,
): InvestigationState {
  const findingById = new Map(state.findings.map((f) => [f.id, f] as const));
  const groups = new Map<string, Group>();
  for (const e of state.forensicTimeline) {
    if (!eligibleIds.has(e.id)) continue;
    const config = scriptC2Config(e);
    if (!config || coveredBy(e, config, findingById)) continue;
    const key = groupKey(e, config);
    const group = groups.get(key);
    if (group) group.events.push(e);
    else groups.set(key, { events: [e], config });
  }
  if (!groups.size) return state;

  const existingIds = new Set(state.findings.map((f) => f.id));
  const newFindings: Finding[] = [];
  const linkByEvent = new Map<string, string>();
  for (const g of groups.values()) {
    const repId = g.events.map((e) => e.id).sort((a, b) => a.localeCompare(b))[0];
    const id = `${SCRIPT_C2_FINDING_ID_PREFIX}${repId}`;
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
        "Deterministic: the settings are read from the logged script text itself, but script content does not establish that any connection was made.",
      title: `C2 settings defined in logged PowerShell script content${host}`,
      description: describe(g, repEvent),
      relatedIocs: [],
      mitreTechniques: [],
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

  const forensicTimeline = state.forensicTimeline.map((e) => {
    const id = linkByEvent.get(e.id);
    return id && !e.relatedFindingIds.includes(id)
      ? { ...e, relatedFindingIds: [...e.relatedFindingIds, id] }
      : e;
  });
  if (!newFindings.length && forensicTimeline.every((e, i) => e === state.forensicTimeline[i])) return state;
  return { ...state, findings: [...state.findings, ...newFindings], forensicTimeline };
}
