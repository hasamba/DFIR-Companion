// The dedicated cloud import routes' 202 preview, counted AFTER dedup (#2301): the analyst is told
// how many events the import will add and how many records the case already holds, not the raw
// parse. Read-only — the ledger is classified, never written; the real import commits it later.
// An upload that is all duplicates previews as format "duplicates-only" with zero events, so the
// route accepts it (the timeline note then says "N duplicate record(s) skipped") instead of
// refusing it as unparseable.

import {
  parseCloudTrail,
  readCloudTrailRecords,
  type AwsImportOptions,
  type AwsParseResult,
} from "../awsImport.js";
import {
  parseCloudActivity,
  type CloudActivityImportOptions,
  type CloudActivityParseResult,
} from "../cloudActivityImport.js";
import {
  extractM365Records,
  m365RecordIdentities,
  parseM365Audit,
  type M365ImportOptions,
  type M365ParseResult,
} from "../m365Import.js";
import { readCloudRecords } from "../cloudRecords.js";
import {
  cloudActivityRecordProvider,
  cloudRecordIdentity,
  type CloudRecordIdentity,
} from "../cloudRecordIdentity.js";
import type { CloudRecordStore } from "../cloudRecordStore.js";
import type { RecordGate } from "../cloudRecordGate.js";

type Row = Record<string, unknown>;
type Previewed<T> = T & { duplicates: number };

async function gateFor(
  store: CloudRecordStore | undefined,
  caseId: string,
  identify: () => CloudRecordIdentity[],
): Promise<{ gate?: RecordGate; duplicates: number }> {
  if (!store) return { duplicates: 0 };
  const identities = identify();
  const v = await store.classify(caseId, identities);
  return { gate: { identities, verdicts: v.verdicts }, duplicates: v.duplicates };
}

function withDuplicates<T extends { format: string }>(parsed: T, duplicates: number): Previewed<T> {
  const format = duplicates && parsed.format === "empty" ? "duplicates-only" : parsed.format;
  return { ...parsed, format, duplicates };
}

export async function previewM365(
  store: CloudRecordStore | undefined,
  caseId: string,
  text: string,
  opts?: M365ImportOptions,
): Promise<Previewed<M365ParseResult>> {
  const prepared = extractM365Records(text);
  const { gate, duplicates } = await gateFor(store, caseId, () => m365RecordIdentities(prepared.normalized));
  return withDuplicates(parseM365Audit(text, { ...opts, prepared, recordGate: gate }), duplicates);
}

export async function previewCloudTrail(
  store: CloudRecordStore | undefined,
  caseId: string,
  text: string,
  opts?: AwsImportOptions,
): Promise<Previewed<AwsParseResult>> {
  const { records, repairs } = readCloudTrailRecords(text);
  const identify = () => records.map((rec: Row) => cloudRecordIdentity("cloudtrail", rec));
  const { gate, duplicates } = await gateFor(store, caseId, identify);
  return withDuplicates(parseCloudTrail(text, { ...opts, records, repairs, recordGate: gate }), duplicates);
}

export async function previewCloudActivity(
  store: CloudRecordStore | undefined,
  caseId: string,
  text: string,
  opts?: CloudActivityImportOptions,
): Promise<Previewed<CloudActivityParseResult>> {
  const { records, repairs } = readCloudRecords(text);
  const identify = () =>
    records.map((rec: Row) => cloudRecordIdentity(cloudActivityRecordProvider(rec), rec));
  const { gate, duplicates } = await gateFor(store, caseId, identify);
  return withDuplicates(
    parseCloudActivity(text, { ...opts, records, repairs, recordGate: gate }),
    duplicates,
  );
}

/** One import name for the routes, so routes/import.ts (at its size ledger) adds a single line. */
export const cloudPreview = {
  m365: previewM365,
  cloudTrail: previewCloudTrail,
  cloudActivity: previewCloudActivity,
};
