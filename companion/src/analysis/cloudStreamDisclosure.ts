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
  /** Optional: disclosures stored before #2502 lack it. */
  mediumMerged: z.number().int().nonnegative().optional(),
  /** failedReadBudget and failedReads are optional: disclosures stored before #2481 lack them. */
  mediumOverflow: z.object({
    ruleActorBudget: z.number(),
    importBudget: z.number(),
    failedReadBudget: z.number().int().nonnegative().optional(),
  }),
  failedReads: z
    .object({ folded: z.number().int().nonnegative(), toSuper: z.number().int().nonnegative() })
    .optional(),
  groups: z.object({ detailed: z.number(), coarse: z.number(), catchAll: z.number() }),
  superWritten: z.number().int().nonnegative(),
  superBudgetExceeded: z.number().int().nonnegative(),
  superEvicted: z.number().int().nonnegative(),
  iocsDropped: z.number().int().nonnegative(),
  iocsMax: z.number().int().nonnegative(),
  summaryWindow: z.object({ max: z.number(), records: z.number(), truncated: z.boolean() }),
  sprayHistoryTruncated: z.boolean(),
  budgets: z.object({
    mediumPerRuleActor: z.number(),
    mediumMax: z.number(),
    aggregateGroupsMax: z.number(),
    coarseGroupsMax: z.number(),
    failedReadsPerActor: z.number().optional(),
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
  iocsDropped: number;
  iocsMax: number;
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
    mediumMerged: o.mediumMerged,
    mediumOverflow: { ...o.mediumOverflow },
    failedReads: { ...o.failedReads },
    groups: { ...o.groups },
    superWritten: i.superWritten,
    superBudgetExceeded: o.superBudgetExceeded,
    superEvicted: i.superEvicted,
    iocsDropped: i.iocsDropped,
    iocsMax: i.iocsMax,
    summaryWindow: { ...i.summaryWindow },
    sprayHistoryTruncated: i.sprayHistoryTruncated,
    budgets: { ...o.budgets },
  };
}

const FORMAT_MAX = 40;
type Counts<T extends string> = Record<T, number>;
type NumberKey = {
  [K in keyof CloudStreamDisclosure]-?: CloudStreamDisclosure[K] extends number ? K : never;
}[keyof CloudStreamDisclosure];
function addCounts<T extends string>(a: Counts<T>, b: Counts<T>, keys: readonly T[]): Counts<T> {
  return Object.fromEntries(keys.map((k) => [k, a[k] + b[k]])) as Counts<T>;
}

/**
 * Two disclosures as one (#2546): a live collection's Cloud Coverage row states the running sum of
 * its pages, summed as numbers BEFORE they become sentences. Counts add, "it happened" flags OR,
 * formats union; budgets, caps and kind are per-page constants, so the later page's value is kept.
 * Optional fields missing from older stored shapes count as 0. Pure: neither input changes.
 */
export function sumCloudStreamDisclosure(
  a: CloudStreamDisclosure,
  b: CloudStreamDisclosure,
): CloudStreamDisclosure {
  const formats = [...new Set([...a.format.split("+"), ...b.format.split("+")])];
  const add = (k: NumberKey): number => a[k] + b[k];
  return {
    kind: b.kind,
    format: formats.join("+").slice(0, FORMAT_MAX),
    gzip: a.gzip || b.gzip,
    bytesRead: add("bytesRead"),
    bytesDecoded: add("bytesDecoded"),
    records: add("records"),
    duplicates: add("duplicates"),
    conflicts: add("conflicts"),
    unmapped: add("unmapped"),
    parseErrors: add("parseErrors"),
    oversizeSkipped: add("oversizeSkipped"),
    bomStripped: add("bomStripped"),
    documentsJoined: add("documentsJoined"),
    belowFloor: add("belowFloor"),
    preGradeRaised: add("preGradeRaised"),
    individual: addCounts(a.individual, b.individual, ["critical", "high", "medium"]),
    aggregatedRows: addCounts(a.aggregatedRows, b.aggregatedRows, ["medium", "low", "info"]),
    mediumMerged: (a.mediumMerged ?? 0) + (b.mediumMerged ?? 0),
    mediumOverflow: {
      ruleActorBudget: a.mediumOverflow.ruleActorBudget + b.mediumOverflow.ruleActorBudget,
      importBudget: a.mediumOverflow.importBudget + b.mediumOverflow.importBudget,
      failedReadBudget: (a.mediumOverflow.failedReadBudget ?? 0) + (b.mediumOverflow.failedReadBudget ?? 0),
    },
    failedReads: {
      folded: (a.failedReads?.folded ?? 0) + (b.failedReads?.folded ?? 0),
      toSuper: (a.failedReads?.toSuper ?? 0) + (b.failedReads?.toSuper ?? 0),
    },
    groups: addCounts(a.groups, b.groups, ["detailed", "coarse", "catchAll"]),
    superWritten: add("superWritten"),
    superBudgetExceeded: add("superBudgetExceeded"),
    superEvicted: add("superEvicted"),
    iocsDropped: add("iocsDropped"),
    iocsMax: b.iocsMax,
    summaryWindow: {
      max: b.summaryWindow.max,
      records: a.summaryWindow.records + b.summaryWindow.records,
      truncated: a.summaryWindow.truncated || b.summaryWindow.truncated,
    },
    sprayHistoryTruncated: a.sprayHistoryTruncated || b.sprayHistoryTruncated,
    budgets: { ...b.budgets },
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
  const folded = d.failedReads?.folded ?? 0;
  // Folded failed reads (#2481) are Medium rows in the super-timeline beside the Low/Info ones.
  const superKinds = folded ? "Low/Info and folded Medium" : "Low/Info";
  return [
    `streamed from disk${d.gzip ? " (gzip, decompressed on read)" : ""}: ${n(d.records)} record(s), ${d.format}`,
    `kept in detail: ${n(d.individual.critical)} Critical, ${n(d.individual.high)} High, ${n(d.individual.medium)} Medium row(s)`,
    d.mediumMerged
      ? `${n(d.mediumMerged)} of those Medium row(s) merged into a matching kept row (same grouping key as a small-file import)`
      : "",
    d.superWritten
      ? `${n(d.superWritten)} ${superKinds} row(s) written to the super-timeline individually`
      : "",
    agg
      ? `${n(agg)} row(s) aggregated (${n(d.aggregatedRows.medium)} Medium, ${n(d.aggregatedRows.low)} Low, ${n(d.aggregatedRows.info)} Info) into ${n(d.groups.detailed + d.groups.coarse + d.groups.catchAll)} counted event(s)`
      : "",
    d.mediumOverflow.ruleActorBudget
      ? `${n(d.mediumOverflow.ruleActorBudget)} Medium row(s) past the budget of ${n(d.budgets.mediumPerRuleActor)} per rule and actor`
      : "",
    d.mediumOverflow.importBudget
      ? `${n(d.mediumOverflow.importBudget)} Medium row(s) past the budget of ${n(d.budgets.mediumMax)} individual Medium rows per import`
      : "",
    d.mediumOverflow.failedReadBudget
      ? `${n(d.mediumOverflow.failedReadBudget)} failed read-only Medium call(s) past the budget of ${n(d.budgets.failedReadsPerActor ?? 0)} per actor`
      : "",
    folded
      ? `${n(folded)} failed read-only call(s) folded into one counted event per actor, ${n(d.failedReads?.toSuper ?? 0)} of them sent to the super-timeline individually`
      : "",
    d.groups.coarse || d.groups.catchAll
      ? `aggregation detail capped at ${n(d.budgets.aggregateGroupsMax)} groups: ${n(d.groups.coarse)} coarser group(s) by rule${d.groups.catchAll ? `, ${n(d.groups.catchAll)} catch-all group(s) past ${n(d.budgets.coarseGroupsMax)} coarse groups` : ""}`
      : "",
    d.superBudgetExceeded
      ? `${n(d.superBudgetExceeded)} ${superKinds} row(s) not written individually — the super-timeline room for this import (${n(d.budgets.superRows)} rows) was used; they are in the aggregated rows and the stored evidence file`
      : "",
    d.superEvicted ? `the super-timeline cap evicted ${n(d.superEvicted)} older row(s)` : "",
    d.iocsDropped
      ? `${n(d.iocsDropped)} IOC(s) over the per-import cap of ${n(d.iocsMax)} not kept — the rows that name them are still imported`
      : "",
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
