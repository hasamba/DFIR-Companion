// What a streamed cloud import says about itself (#2303): every cap reached, row skipped, parse
// error, repair and aggregation — in the import note (the case timeline), on the "last import"
// record and in the Cloud Coverage panel, never only in the server log. One shape, one wording.

import { z } from "zod";
import type { OutputDisclosure } from "./cloudOutputBudget.js";
import { describeJsonRepairs, type JsonRepairs } from "./tolerantJson.js";

export const cloudStreamDisclosureSchema = z.object({
  kind: z.string().max(40),
  format: z.string().max(40),
  gzip: z.boolean(),
  bytesRead: z.number().nonnegative(),
  bytesDecoded: z.number().nonnegative(),
  records: z.number().int().nonnegative(),
  duplicates: z.number().int().nonnegative(),
  conflicts: z.number().int().nonnegative(),
  unmapped: z.number().int().nonnegative(),
  parseErrors: z.number().int().nonnegative(),
  oversizeSkipped: z.number().int().nonnegative(),
  bomStripped: z.number().int().nonnegative(),
  documentsJoined: z.number().int().nonnegative(),
  belowFloor: z.number().int().nonnegative(),
  preGradeRaised: z.number().int().nonnegative(),
  individual: z.object({ critical: z.number(), high: z.number(), medium: z.number() }),
  aggregatedRows: z.object({ medium: z.number(), low: z.number(), info: z.number() }),
  mediumOverflow: z.object({ ruleActorBudget: z.number(), importBudget: z.number() }),
  groups: z.object({ detailed: z.number(), coarse: z.number(), catchAll: z.number() }),
  superWritten: z.number().int().nonnegative(),
  superBudgetExceeded: z.number().int().nonnegative(),
  superEvicted: z.number().int().nonnegative(),
  summaryWindow: z.object({ max: z.number(), records: z.number(), truncated: z.boolean() }),
  sprayHistoryTruncated: z.boolean(),
  budgets: z.object({
    mediumPerRuleActor: z.number(),
    mediumMax: z.number(),
    aggregateGroupsMax: z.number(),
    coarseGroupsMax: z.number(),
    superRows: z.number(),
  }),
});
export type CloudStreamDisclosure = z.infer<typeof cloudStreamDisclosureSchema>;

export interface DisclosureInputs {
  kind: string;
  format: string;
  gzip: boolean;
  bytesRead: number;
  bytesDecoded: number;
  records: number;
  duplicates: number;
  conflicts: number;
  unmapped: number;
  repairs: JsonRepairs;
  oversizeSkipped: number;
  preGradeRaised: number;
  output: OutputDisclosure;
  superWritten: number;
  superEvicted: number;
  summaryWindow: { max: number; records: number; truncated: boolean };
  sprayHistoryTruncated: boolean;
}

export function buildCloudStreamDisclosure(i: DisclosureInputs): CloudStreamDisclosure {
  const o = i.output;
  return {
    kind: i.kind,
    format: i.format,
    gzip: i.gzip,
    bytesRead: i.bytesRead,
    bytesDecoded: i.bytesDecoded,
    records: i.records,
    duplicates: i.duplicates,
    conflicts: i.conflicts,
    unmapped: i.unmapped,
    parseErrors: i.repairs.garbageSkipped,
    oversizeSkipped: i.oversizeSkipped,
    bomStripped: i.repairs.bomStripped,
    documentsJoined: i.repairs.documentsJoined,
    belowFloor: o.belowFloor,
    preGradeRaised: i.preGradeRaised,
    individual: { ...o.individual },
    aggregatedRows: { ...o.aggregatedRows },
    mediumOverflow: { ...o.mediumOverflow },
    groups: { ...o.groups },
    superWritten: i.superWritten,
    superBudgetExceeded: o.superBudgetExceeded,
    superEvicted: i.superEvicted,
    summaryWindow: { ...i.summaryWindow },
    sprayHistoryTruncated: i.sprayHistoryTruncated,
    budgets: { ...o.budgets },
  };
}

const n = (x: number): string => x.toLocaleString("en-US");

/** The disclosure as clauses, for the import note and the coverage panel. Only what happened. */
export function describeCloudStreamDisclosure(d: CloudStreamDisclosure): string[] {
  const agg = d.aggregatedRows.medium + d.aggregatedRows.low + d.aggregatedRows.info;
  const repairs = describeJsonRepairs({
    bomStripped: d.bomStripped,
    documentsJoined: d.documentsJoined,
    garbageSkipped: d.parseErrors,
  });
  return [
    `streamed from disk${d.gzip ? " (gzip, decompressed on read)" : ""}: ${n(d.records)} record(s), ${d.format}`,
    `kept individually: ${n(d.individual.critical)} Critical, ${n(d.individual.high)} High, ${n(d.individual.medium)} Medium`,
    d.superWritten ? `${n(d.superWritten)} Low/Info row(s) written to the super-timeline individually` : "",
    agg
      ? `${n(agg)} row(s) aggregated (${n(d.aggregatedRows.medium)} Medium, ${n(d.aggregatedRows.low)} Low, ${n(d.aggregatedRows.info)} Info) into ${n(d.groups.detailed + d.groups.coarse + d.groups.catchAll)} counted event(s)`
      : "",
    d.mediumOverflow.ruleActorBudget
      ? `${n(d.mediumOverflow.ruleActorBudget)} Medium row(s) past the budget of ${n(d.budgets.mediumPerRuleActor)} per rule and actor`
      : "",
    d.mediumOverflow.importBudget
      ? `${n(d.mediumOverflow.importBudget)} Medium row(s) past the budget of ${n(d.budgets.mediumMax)} individual Medium rows per import`
      : "",
    d.groups.coarse || d.groups.catchAll
      ? `aggregation detail capped at ${n(d.budgets.aggregateGroupsMax)} groups: ${n(d.groups.coarse)} coarser group(s) by rule${d.groups.catchAll ? `, ${n(d.groups.catchAll)} catch-all group(s) past ${n(d.budgets.coarseGroupsMax)} coarse groups` : ""}`
      : "",
    d.superBudgetExceeded
      ? `${n(d.superBudgetExceeded)} Low/Info row(s) not written individually — the super-timeline room for this import (${n(d.budgets.superRows)} rows) was used; they are in the aggregated rows and the stored evidence file`
      : "",
    d.superEvicted ? `the super-timeline cap evicted ${n(d.superEvicted)} older row(s)` : "",
    d.duplicates ? `${n(d.duplicates)} duplicate record(s) skipped` : "",
    d.conflicts ? `${n(d.conflicts)} conflicting record(s) kept and flagged` : "",
    d.unmapped ? `${n(d.unmapped)} record(s) not recognised and not mapped` : "",
    d.belowFloor ? `${n(d.belowFloor)} row(s) below the import's minimum severity dropped` : "",
    d.oversizeSkipped ? `${n(d.oversizeSkipped)} record(s) over the per-record size bound skipped` : "",
    d.preGradeRaised ? `${n(d.preGradeRaised)} row(s) raised by tagger rules before aggregation` : "",
    d.summaryWindow.truncated
      ? `whole-export summaries built over the first ${n(d.summaryWindow.max)} of ${n(d.records)} records`
      : "",
    d.sprayHistoryTruncated ? "password-spray detection read a truncated sign-in history" : "",
    repairs,
  ].filter(Boolean);
}
