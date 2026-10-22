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

export interface SigmaImportGrader {
  readonly set: SigmaRuleSet;
  enabled(): boolean;
  minLevel(): SigmaLevel;
}

export function createSigmaImportGrader(
  set: SigmaRuleSet,
  opts: { enabled?: () => boolean; minLevel?: () => SigmaLevel } = {},
): SigmaImportGrader {
  return {
    set,
    enabled: opts.enabled ?? (() => true),
    minLevel: opts.minLevel ?? (() => DEFAULT_SIGMA_MIN_LEVEL),
  };
}

/** The rules that definitely match one raw record; [] without a grader or while it is off. */
export function sigmaMatchesFor(
  grader: SigmaImportGrader | undefined,
  sourceId: string,
  record: Row,
  onIncomplete?: (n: number) => void,
): SigmaRuleRef[] {
  if (!grader?.enabled()) return [];
  const { matches, incomplete } = matchSigmaRecord(grader.set, sourceId, record);
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
  return `Sigma rule: ${r.title} [${r.id}] — level ${r.level}, status ${r.status}${author}, SigmaHQ ${r.release}, ${r.url}`;
}

/** The event with the matches applied; the same object when nothing matched. Never mutates. */
export function applySigmaMatches(
  event: MappedEvent,
  matches: readonly SigmaRuleRef[],
  minLevel: SigmaLevel,
  note?: string,
): MappedEvent {
  if (matches.length === 0) return event;
  const byLevel = [...matches].sort((a, b) => rank(b.level) - rank(a.level));
  const graded = byLevel.filter((r) => rank(r.level) >= rank(minLevel));
  const lead = byLevel[0];
  const more = matches.length > 1 ? ` (+${matches.length - 1} more)` : "";
  const head = graded.length
    ? `Sigma: ${lead.title}${more}`
    : `Sigma (${lead.level}, tag only): ${lead.title}${more}`;
  const severity = graded.reduce((s, r) => worstSeverity(s, LEVEL_SEVERITY[r.level]), event.severity);
  const mitre = [...event.mitre];
  for (const t of matches.flatMap((r) => r.mitre)) if (!mitre.includes(t)) mitre.push(t);
  const lines = [...byLevel.map(messageLine), ...(note ? [`Sigma note: ${note}`] : [])];
  const releases = [...new Set(matches.map((r) => `sigma-${r.release}`))];
  const canonical = event.canonical
    ? {
        ...event.canonical,
        producer: {
          ...event.canonical.producer,
          ruleVersions: [
            ...(event.canonical.producer.ruleVersions ?? []),
            ...releases.filter((v) => !event.canonical?.producer.ruleVersions?.includes(v)),
          ],
        },
      }
    : undefined;
  return {
    ...event,
    severity,
    mitre,
    description: `${head} - ${event.description}`.slice(0, 600),
    message: [event.message, ...lines].filter(Boolean).join("\n"),
    aggKey: `${event.aggKey}|sigma:${matches
      .map((r) => r.id)
      .sort()
      .join(",")}`,
    ...(canonical ? { canonical } : {}),
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
  minLevel: SigmaLevel,
): MappedEvent[] {
  if (rows.length === 0 || matches.length === 0) return [...rows];
  const note =
    rows.length > 1
      ? `the rule matched the whole audit record, which produced ${rows.length} timeline rows; it is shown on the first`
      : undefined;
  return [applySigmaMatches(rows[0], matches, minLevel, note), ...rows.slice(1)];
}
