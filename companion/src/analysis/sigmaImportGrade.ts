// The import-time Sigma overlay (#2202): what a Sigma match does to an imported event.
//
// A match at or above the minimum level grades the event to the rule's level — never down, so a
// hand-graded High stays High. A match below it only TAGS: the severity is untouched, so an Info
// row stays Info, is demoted to the super-timeline like any other Info row, and never reaches the
// AI. Either way the rule's ATT&CK techniques join the event, the description leads with the rule,
// and the message records the rule's id, level, status, author, release and link — the DRL 1.1
// requires the author and a link on every match.
//
// The overlay rewrites the SAME event the importer's own tables graded, so a record both grade is
// one row. `sources` is deliberately untouched: a "Sigma" entry there would read as an independent
// tool corroborating the row, and it is the same record read twice.

import { worstSeverity, type Severity } from "./stateTypes.js";
import {
  matchSigmaRecord,
  SIGMA_LEVELS,
  type SigmaLevel,
  type SigmaRuleRef,
  type SigmaRuleSet,
} from "./sigmaRuleSet.js";
import type { MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

/** The minimum level that raises severity until #2204 makes it a setting. */
export const DEFAULT_SIGMA_MIN_LEVEL: SigmaLevel = "high";

const LEVEL_SEVERITY: Record<SigmaLevel, Severity> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
};

const rank = (level: SigmaLevel): number => SIGMA_LEVELS.indexOf(level);

/**
 * The rules and settings ONE import is graded with, taken once before parsing (#2204, Codex plan
 * review): installing a release or changing a setting mid-import can never mix two configurations
 * in one import, and the import's note is rendered from the same snapshot that graded it.
 */
export interface SigmaGradingSnapshot {
  ruleSet: SigmaRuleSet;
  minLevel: SigmaLevel;
  /** `sigma:<release>:<content>:<statuses>:<min level>:<disabled>` — stamped on every graded event. */
  token: string;
}

export interface SigmaImportGrader {
  /** The snapshot for the next import, or undefined while Sigma grading is switched off. */
  snapshot(): SigmaGradingSnapshot | undefined;
}

const tokenPart = (s: string): string => s.replace(/[^A-Za-z0-9._-]/g, "_") || "_";

export function sigmaProvenanceToken(set: SigmaRuleSet, minLevel: SigmaLevel): string {
  return [
    "sigma",
    tokenPart(set.release),
    set.contentSha,
    set.statuses.map(tokenPart).join("+") || "_",
    minLevel,
    set.disabledHash,
  ].join(":");
}

export function createSigmaImportGrader(
  set: SigmaRuleSet | (() => SigmaRuleSet),
  opts: { enabled?: () => boolean; minLevel?: () => SigmaLevel } = {},
): SigmaImportGrader {
  const ruleSet = typeof set === "function" ? set : () => set;
  return {
    snapshot() {
      if (opts.enabled && !opts.enabled()) return undefined;
      const current = ruleSet();
      const minLevel = opts.minLevel?.() ?? DEFAULT_SIGMA_MIN_LEVEL;
      return { ruleSet: current, minLevel, token: sigmaProvenanceToken(current, minLevel) };
    },
  };
}

/** The rules that definitely match one raw record; [] without a snapshot (Sigma off). */
export function sigmaMatchesFor(
  snapshot: SigmaGradingSnapshot | undefined,
  sourceId: string,
  record: Row,
  onIncomplete?: (n: number) => void,
): SigmaRuleRef[] {
  if (!snapshot) return [];
  const { matches, incomplete } = matchSigmaRecord(snapshot.ruleSet, sourceId, record);
  if (incomplete) onIncomplete?.(incomplete);
  return matches.map((m) => m.ref);
}

/** The union of several match lists, first occurrence kept (replicas of one CloudTrail action). */
export function unionSigmaMatches(lists: readonly (readonly SigmaRuleRef[])[]): SigmaRuleRef[] {
  const seen = new Map<string, SigmaRuleRef>();
  for (const list of lists) for (const r of list) if (!seen.has(r.id)) seen.set(r.id, r);
  return [...seen.values()];
}

function messageLine(r: SigmaRuleRef): string {
  const author = r.author ? `, author ${r.author}` : "";
  const modified = r.modified ? `, modified ${r.modified}` : "";
  const hunting = r.huntingOnly ? ", threat-hunting rule (tag only)" : "";
  return `Sigma rule: ${r.title} [${r.id}] — level ${r.level}, status ${r.status}${modified}${hunting}${author}, SigmaHQ ${r.release}, ${r.url}`;
}

/** The event with the snapshot's provenance token on its canonical producer (once). */
function stamp(event: MappedEvent, token: string): MappedEvent {
  // An envelope without a producer (older stored data) has nowhere to record provenance.
  if (!event.canonical?.producer) return event;
  const versions = event.canonical.producer.ruleVersions ?? [];
  if (versions.includes(token)) return event;
  return {
    ...event,
    canonical: {
      ...event.canonical,
      producer: { ...event.canonical.producer, ruleVersions: [...versions, token] },
    },
  };
}

/**
 * The event graded by one snapshot: the provenance token is always stamped (the event WAS checked,
 * even when nothing matched), and the matches are applied. Never mutates.
 */
export function applySigmaMatches(
  event: MappedEvent,
  matches: readonly SigmaRuleRef[],
  snapshot: Pick<SigmaGradingSnapshot, "minLevel" | "token">,
  note?: string,
): MappedEvent {
  const stamped = stamp(event, snapshot.token);
  if (matches.length === 0) return stamped;
  const minLevel = snapshot.minLevel;
  const byLevel = [...matches].sort((a, b) => rank(b.level) - rank(a.level));
  // A threat-hunting rule is low-fidelity by design: it tags, it never grades (#2204).
  const graded = byLevel.filter((r) => !r.huntingOnly && rank(r.level) >= rank(minLevel));
  const lead = byLevel[0];
  const more = matches.length > 1 ? ` (+${matches.length - 1} more)` : "";
  const head = graded.length
    ? `Sigma: ${lead.title}${more}`
    : `Sigma (${lead.level}, tag only): ${lead.title}${more}`;
  const severity = graded.reduce((s, r) => worstSeverity(s, LEVEL_SEVERITY[r.level]), stamped.severity);
  const mitre = [...stamped.mitre];
  for (const t of matches.flatMap((r) => r.mitre)) if (!mitre.includes(t)) mitre.push(t);
  const lines = [...byLevel.map(messageLine), ...(note ? [`Sigma note: ${note}`] : [])];
  return {
    ...stamped,
    severity,
    mitre,
    description: `${head} - ${stamped.description}`.slice(0, 600),
    message: [stamped.message, ...lines].filter(Boolean).join("\n"),
    aggKey: `${stamped.aggKey}|sigma:${matches
      .map((r) => r.id)
      .sort()
      .join(",")}`,
  };
}

/**
 * One raw record that became several rows (an Entra audit record yields one row per atomic change):
 * the verdict is about the whole record, so it goes on the FIRST row only, with a note saying so —
 * never stamped on every sibling, which would label unrelated changes and inflate High rows.
 */
export function applySigmaToRecordRows(
  rows: readonly MappedEvent[],
  matches: readonly SigmaRuleRef[],
  snapshot: Pick<SigmaGradingSnapshot, "minLevel" | "token">,
): MappedEvent[] {
  if (rows.length === 0) return [];
  const stamped = rows.map((r) => applySigmaMatches(r, [], snapshot));
  if (matches.length === 0) return stamped;
  const note =
    rows.length > 1
      ? `the rule matched the whole audit record, which produced ${rows.length} timeline rows; it is shown on the first`
      : undefined;
  return [applySigmaMatches(stamped[0], matches, snapshot, note), ...stamped.slice(1)];
}

/** The import-note sentence for one snapshot, e.g. "; Sigma: SigmaHQ r2026-07-01 …, 3 row(s) matched". */
export function sigmaImportNote(snapshot: SigmaGradingSnapshot | undefined, rowsMatched = 0): string {
  if (!snapshot) return "";
  const set = snapshot.ruleSet;
  return (
    `; Sigma: SigmaHQ ${set.release} (content ${set.contentSha}), statuses ${set.statuses.join(", ")}, ` +
    `raises at ${snapshot.minLevel} and above, disabled list ${set.disabledHash}, ${rowsMatched} row(s) matched`
  );
}
