// The detection-overlap engine (#2348): run one raw record through the importer, the bundled Sigma
// rules (default settings) and the shipped tagger rules, and record which grading paths graded each
// resulting row, and with what. Pure apart from reading data/tags.yaml and the bundled Sigma set.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { lookupAwsAction, parseCloudTrail } from "../../../../src/analysis/awsImport.js";
import { parseCloudActivity } from "../../../../src/analysis/cloudActivityImport.js";
import { matchGcpRule } from "../../../../src/analysis/gcpSeverityRules.js";
import { parseM365Audit } from "../../../../src/analysis/m365Import.js";
import { loadBundledSigmaRuleSet } from "../../../../src/analysis/sigmaBundledRules.js";
import { cloudTrailSigmaVeto } from "../../../../src/analysis/sigmaCloudTrailVeto.js";
import { createSigmaImportGrader } from "../../../../src/analysis/sigmaImportGrade.js";
import { SIGMA_LEVELS, type SigmaLevel, type SigmaRuleRef } from "../../../../src/analysis/sigmaRuleSet.js";
import type { SiemEvent } from "../../../../src/analysis/siemImport.js";
import type { ForensicEvent, Severity } from "../../../../src/analysis/stateTypes.js";
import { runTagger } from "../../../../src/analysis/tagger.js";
import { compileText } from "../../../../src/analysis/taggerStore.js";
import type { DetectionSample } from "./types.js";

type Row = Record<string, unknown>;

export const TAGGER_RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../../../data/tags.yaml", import.meta.url)), "utf8"),
);
export const SIGMA_SET = loadBundledSigmaRuleSet().set;
/** Default settings: Sigma on, statuses stable + test, raises at high and above. */
export const SIGMA = createSigmaImportGrader(SIGMA_SET).snapshot();

const SIGMA_REFS: ReadonlyMap<string, SigmaRuleRef> = new Map(
  [...SIGMA_SET.sources.values()].flatMap((s) =>
    [...s.always, ...[...s.index.values()].flatMap((m) => [...m.values()].flat())].map(
      (r) => [r.ref.id, r.ref] as const,
    ),
  ),
);

const LEVEL_SEVERITY: Record<SigmaLevel, Severity> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
};

/** One grading path that assigned a grade to one row. */
export interface GradeEntry {
  /** `importer:<kind>`, `sigma:<rule id>` or `tagger:<rule id>`. */
  path: string;
  label: string;
  grade: Severity;
  mitre: string[];
}

export interface RowResult {
  sampleId: string;
  row: number;
  description: string;
  entries: GradeEntry[];
  /** Sigma rules that matched but only tag (below the minimum level, hunting-only, or vetoed). */
  tagOnly: string[];
}

export interface Overlap {
  sampleId: string;
  row: number;
  a: GradeEntry;
  b: GradeEntry;
}

const text = (s: DetectionSample, rec: Row): string =>
  s.kind === "cloudtrail" ? JSON.stringify({ Records: [rec] }) : JSON.stringify([rec]);

function parse(s: DetectionSample, rec: Row, withSigma: boolean): SiemEvent[] {
  const sigma = withSigma ? SIGMA : undefined;
  if (s.kind === "cloudtrail") return parseCloudTrail(text(s, rec), { sigma }).events;
  if (s.kind === "m365") return parseM365Audit(text(s, rec), { aggregate: false, sigma }).events;
  return parseCloudActivity(text(s, rec), { aggregate: false, sigma }).events;
}

const PROBE = "DetectionOverlapProbe";
const strField = (rec: Row, key: string): string => {
  const v = rec[key];
  return typeof v === "string" ? v : "";
};

/**
 * The grade the importer gives a record whose operation it does not recognise — its floor, not a
 * decision. CloudTrail and GCP floor an unknown write at Low; M365 / Entra floor at Info. The floor
 * is measured by renaming the operation, so the importer's generic bumps (a failed call, root) stay
 * in it.
 */
function importerFloor(s: DetectionSample): Severity {
  if (s.kind === "m365") return "Info";
  const rec = s.record;
  const probe =
    s.kind === "cloudtrail"
      ? { ...rec, eventName: PROBE }
      : s.kind === "azure"
        ? { ...rec, operationName: { value: `Microsoft.${PROBE}/things/write` } }
        : { ...rec, protoPayload: { ...(rec.protoPayload as Row), methodName: PROBE } };
  return parse(s, probe, false)[0]?.severity ?? "Info";
}

/**
 * Did the importer decide this grade itself, even at floor level? True when the operation is in its
 * own grading table, or (CloudTrail) when the logging / AWS Config decoder read the call — that
 * decoder grades a failed call on purpose (#931, #1071, #1081).
 */
function importerListed(s: DetectionSample, row: SiemEvent | undefined): boolean {
  if (s.kind === "cloudtrail")
    return (
      lookupAwsAction(strField(s.record, "eventSource"), strField(s.record, "eventName")) !== undefined ||
      !!row?.canonical?.loggingChange
    );
  if (s.kind === "gcp") return matchGcpRule(strField(s.record.protoPayload as Row, "methodName")) !== null;
  return false;
}

const SIGMA_RULE_LINE = /^Sigma rule: .* \[([^\]]+)\] — level /gm;

function sigmaEntries(s: DetectionSample, sigmaRow: SiemEvent, importerRow: SiemEvent) {
  const ids = [...(sigmaRow.message ?? "").matchAll(SIGMA_RULE_LINE)].map((m) => m[1]);
  const veto = s.kind === "cloudtrail" ? cloudTrailSigmaVeto(importerRow) : undefined;
  const entries: GradeEntry[] = [];
  const tagOnly: string[] = [];
  for (const id of ids) {
    const ref = SIGMA_REFS.get(id);
    if (!ref) throw new Error(`sample ${s.id}: Sigma rule ${id} matched but is not in the loaded set`);
    const raises =
      !ref.huntingOnly &&
      // A source with its own floor (#2499: Suzaku) raises only at or above it, as the grader does.
      SIGMA_LEVELS.indexOf(ref.level) >= SIGMA_LEVELS.indexOf(ref.gradeFloor ?? SIGMA?.minLevel ?? "high") &&
      (veto ? veto.mayGrade(ref) : true);
    if (raises)
      entries.push({
        path: `sigma:${id}`,
        label: ref.title,
        grade: LEVEL_SEVERITY[ref.level],
        mitre: ref.mitre,
      });
    else tagOnly.push(`sigma:${id} (${ref.title}, ${ref.level})`);
  }
  return { entries, tagOnly, ids };
}

function taggerEntries(row: SiemEvent, i: number): GradeEntry[] {
  const event = {
    ...row,
    id: `e${i}`,
    relatedFindingIds: [],
    sourceScreenshots: [],
  } as unknown as ForensicEvent;
  const hit = runTagger([event], TAGGER_RULES).perEvent[0];
  return (hit?.ruleIds ?? []).flatMap((id) => {
    const rule = TAGGER_RULES.rules.find((r) => r.id === id);
    if (!rule?.severity || rule.severity === "Info") return [];
    return [{ path: `tagger:${id}`, label: rule.description ?? id, grade: rule.severity, mitre: rule.mitre }];
  });
}

/** Every row the record produced, with every path that graded it. */
export function gradeSample(s: DetectionSample): { rows: RowResult[]; sigmaMatched: string[] } {
  const plain = parse(s, s.record, false);
  const graded = parse(s, s.record, true);
  if (plain.length !== graded.length)
    throw new Error(`sample ${s.id}: ${plain.length} rows without Sigma but ${graded.length} with it`);
  const floor = importerFloor(s);
  const sigmaMatched: string[] = [];
  const rows = plain.map((imp, i): RowResult => {
    const sg = graded[i];
    const entries: GradeEntry[] = [];
    if (imp.severity !== "Info" && (imp.severity !== floor || importerListed(s, imp)))
      entries.push({
        path: `importer:${s.kind}`,
        label: "importer grading",
        grade: imp.severity,
        mitre: imp.mitreTechniques ?? [],
      });
    const sig = sigmaEntries(s, sg, imp);
    sigmaMatched.push(...sig.ids);
    return {
      sampleId: s.id,
      row: i,
      description: imp.description,
      entries: [...entries, ...sig.entries, ...taggerEntries(sg, i)],
      tagOnly: sig.tagOnly,
    };
  });
  return { rows, sigmaMatched };
}

const sameSet = (a: string[], b: string[]) =>
  a.length === b.length && [...a].sort().join() === [...b].sort().join();

/** Pairs of paths on one row that both graded it: `conflicts` disagree, `duplicates` agree (grade and MITRE). */
export function findOverlaps(rows: readonly RowResult[]): { conflicts: Overlap[]; duplicates: Overlap[] } {
  const conflicts: Overlap[] = [];
  const duplicates: Overlap[] = [];
  for (const r of rows)
    r.entries.forEach((a, i) =>
      r.entries.slice(i + 1).forEach((b) => {
        const o = { sampleId: r.sampleId, row: r.row, a, b };
        if (a.grade !== b.grade) conflicts.push(o);
        else if (sameSet(a.mitre, b.mitre)) duplicates.push(o);
      }),
    );
  return { conflicts, duplicates };
}

/** The allowlist key for a pair of paths — order-free. */
export const pairKey = (a: string, b: string): string => [a, b].sort().join(" + ");

export const describeOverlap = (o: Overlap): string =>
  `${o.sampleId}#${o.row}: ${o.a.path} (${o.a.label}) = ${o.a.grade}  vs  ${o.b.path} (${o.b.label}) = ${o.b.grade}`;
