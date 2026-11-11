// The last grading steps of a CloudTrail upload, after mapping and the replica merge (#2542). Kept
// beside the importer, which is at its size bound. In order:
//   1. the Sigma overlay, with CloudTrail's veto on raising a not-found logging row (#2351);
//   2. CloudTrail's veto on ATT&CK techniques its own reading proves wrong (cloudTrailTagVeto.ts) —
//      after Sigma, so a rule's technique and the importer's own are withheld alike;
//   3. the ransomware-precursor raise (awsPrecursorGrade.ts).
// `records[row.recordIndex]` is the raw record behind each row. Pure.

import type { MappedEvent } from "./siemImport.js";
import type { SigmaRuleRef } from "./sigmaRuleSet.js";
import { applySigmaMatches, type SigmaGradingSnapshot } from "./sigmaImportGrade.js";
import { cloudTrailSigmaVeto } from "./sigmaCloudTrailVeto.js";
import { cloudTrailTagVeto, loneFailedSignIns, withholdTechniques } from "./cloudTrailTagVeto.js";
import { raiseRansomwarePrecursors } from "./awsPrecursorGrade.js";

type Row = Record<string, unknown>;

export interface CloudTrailRow {
  event: MappedEvent;
  sigma: SigmaRuleRef[];
  recordIndex: number;
}

export function gradeCloudTrailRows(
  rows: readonly CloudTrailRow[],
  records: readonly Row[],
  snapshot: SigmaGradingSnapshot | undefined,
): MappedEvent[] {
  const lone = loneFailedSignIns(records);
  const graded = rows.map((g) => {
    const event = snapshot
      ? applySigmaMatches(g.event, g.sigma, snapshot, undefined, cloudTrailSigmaVeto(g.event))
      : g.event;
    return withholdTechniques(event, cloudTrailTagVeto(records[g.recordIndex], lone.has(g.recordIndex)));
  });
  return raiseRansomwarePrecursors(
    graded,
    rows.map((g) => records[g.recordIndex]),
  );
}
