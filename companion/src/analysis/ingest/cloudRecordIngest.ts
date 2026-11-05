// The ingest-layer half of cloud-record dedup and provenance (#2301), shared by the M365, AWS and
// GCP / Azure Activity importers so the classify → parse → merge → commit order lives in one place.
//
//   const plan = await planCloudRecords(ctx, caseId, opts.idPrefix, identities); // before parsing
//   parse(records, { recordGate: plan.gate, provenance: plan.provenance });       // skips duplicates
//   …merge and save…
//   await settleCloudRecords(ctx, caseId, plan, opts.idPrefix, events, debug);    // after the save
//
// The ledger is written only after the merge saved, so a failed import never marks its records as
// seen. A streaming import (#2303) runs the same three calls once per batch. Without a
// cloudRecordStore (minimal/test wirings) the plan is inert: no gate, no provenance, no note.

import { createHash } from "node:crypto";
import type { ImportContext } from "./importContext.js";
import type { CloudRecordIdentity } from "../cloudRecordIdentity.js";
import type { RecordVerdicts, SourceRecordMember } from "../cloudRecordStore.js";
import type { RecordGate } from "../cloudRecordGate.js";
import type { AggregateProvenance } from "../eventAggregate.js";
import type { SiemEvent } from "../siemImport.js";
import type { ImportDebugRecorder } from "../importDebug.js";

export interface CloudRecordPlan {
  gate?: RecordGate;
  provenance?: AggregateProvenance;
  identities: readonly CloudRecordIdentity[];
  verdicts?: RecordVerdicts;
  members: SourceRecordMember[]; // filled by the aggregator through `provenance`
}

/** Classifies an upload's records against the case ledger. Read-only; nothing is marked seen. */
export async function planCloudRecords(
  ctx: ImportContext,
  caseId: string,
  idPrefix: string,
  identify: () => readonly CloudRecordIdentity[], // only called when the case has a ledger
): Promise<CloudRecordPlan> {
  const store = ctx.opts.cloudRecordStore;
  if (!store) return { identities: [], members: [] };
  const identities = identify();
  const verdicts = await store.classify(caseId, identities);
  const members: SourceRecordMember[] = [];
  const provenance: AggregateProvenance = {
    groupOf: (key) => `${idPrefix}:${createHash("sha256").update(key).digest("hex").slice(0, 24)}`,
    onMember: (group, ref, locator) => members.push({ group, ref, ...(locator ? { locator } : {}) }),
  };
  return { gate: { identities, verdicts: verdicts.verdicts }, provenance, identities, verdicts, members };
}

/** The import-result clause: "N duplicate record(s) skipped, M conflicting record(s) kept and flagged", or "". */
export function cloudRecordNote(plan: CloudRecordPlan): string {
  const v = plan.verdicts;
  if (!v) return "";
  return [
    v.duplicates ? `${v.duplicates} duplicate record(s) skipped` : "",
    v.conflicts ? `${v.conflicts} conflicting record(s) kept and flagged` : "",
  ]
    .filter(Boolean)
    .join(", ");
}

/** Reports the plan's counts to the import debug recorder. */
export function recordCloudRecordDebug(plan: CloudRecordPlan, debug?: ImportDebugRecorder): void {
  const v = plan.verdicts;
  if (!v) return;
  if (v.duplicates) debug?.skipped("duplicate_record", v.duplicates);
  if (v.conflicts) debug?.observed("record_id_conflict", v.conflicts);
  const hashed = plan.identities.filter((id, i) => id.hashIdentified && v.verdicts[i] !== "duplicate").length;
  if (hashed) debug?.observed("hash_identified_record", hashed);
}

/**
 * After the merge saved: records the kept identities in the ledger and the group → record relation
 * of every event that survived the cap. A failure here cannot undo the saved import, so it is
 * reported on the import's debug record instead of failing an import whose events are already in.
 */
export async function settleCloudRecords(
  ctx: ImportContext,
  caseId: string,
  plan: CloudRecordPlan,
  idPrefix: string,
  events: readonly SiemEvent[],
  debug?: ImportDebugRecorder,
): Promise<void> {
  const store = ctx.opts.cloudRecordStore;
  if (!store || !plan.verdicts) return;
  // Only records whose rows reached the case count as seen: a record whose rows a severity floor or
  // the event cap dropped is not in the case, and marking it seen would make it unrecoverable.
  const kept = new Set(events.flatMap((e) => (e.sourceRecords ? [e.sourceRecords.group] : [])));
  const members = plan.members.filter((m) => kept.has(m.group));
  const keptRefs = new Set(members.map((m) => m.ref));
  const verdicts = plan.verdicts.verdicts.map((v, i) =>
    keptRefs.has(plan.identities[i]?.key ?? "") ? v : ("duplicate" as const),
  );
  try {
    await store.commit(caseId, plan.identities, verdicts, idPrefix);
    await store.recordMembers(caseId, members);
  } catch {
    debug?.observed("record_ledger_write_failed");
  }
}
