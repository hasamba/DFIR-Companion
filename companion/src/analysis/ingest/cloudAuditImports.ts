// The cloud audit importers that dedup by record identity (#2301) and read through the tolerant
// cloud reader (#2302): AWS CloudTrail, and GCP Cloud Audit Logs + Azure Activity Log. Moved out of
// cloudImports.ts (at the 800-line cap) unchanged in behaviour; ingest/index.ts re-exports them.

import { parseCloudTrail, readCloudTrailRecords, type AwsImportOptions } from "../awsImport.js";
import { parseCloudActivity, type CloudActivityImportOptions } from "../cloudActivityImport.js";
import { readCloudRecords } from "../cloudRecords.js";
import { cloudActivityRecordProvider, cloudRecordIdentity } from "../cloudRecordIdentity.js";
import { deltaSchema } from "../responseSchema.js";
import { resolveExtractedFrom } from "../siemImport.js";
import { describeJsonRepairs, jsonRepairNote } from "../tolerantJson.js";
import { applySeverityFloor } from "../severityFloor.js";
import type { Severity } from "../stateTypes.js";
import { describeFloor } from "./floorNote.js";
import { noteEmptyImport, abortIfCancelled, mergeAndSaveDelta } from "./importState.js";
import type { ImportContext } from "./importContext.js";
import { recordParsedImport } from "./parsedDebug.js";
import { sigmaImportNote } from "../sigmaImportGrade.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import {
  cloudRecordNote,
  planCloudRecords,
  recordCloudRecordDebug,
  settleCloudRecords,
} from "./cloudRecordIngest.js";
import type { ImportWithCoverage } from "./cloudImports.js";

// Import AWS CloudTrail logs. Deterministic (no AI call): each API-call record is mapped,
// severity derived from the action (IAM persistence, logging/detection tampering, S3
// exposure, secrets access) + denied/root/console-failure bumps; the caller IP → IOC.
export async function importAws(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "a3") so ids never collide
    importedAt: string;
    aws?: AwsImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    debug?: ImportDebugRecorder;
    onProgress?: (done: number, total: number) => void;
    signal?: AbortSignal; // #2425: the import job's Cancel — checked right before the merge
  },
): Promise<ImportWithCoverage> {
  // One Sigma snapshot for this whole import, taken before parsing (#2204).
  const sigma = ctx.opts.sigmaGrader?.snapshot();
  const { records, repairs } = readCloudTrailRecords(text);
  const plan = await planCloudRecords(ctx, caseId, opts.idPrefix, () =>
    records.map((rec) => cloudRecordIdentity("cloudtrail", rec)),
  );
  recordCloudRecordDebug(plan, opts.debug);
  const dedupNote = cloudRecordNote(plan);
  const parsedRaw = parseCloudTrail(text, {
    ...opts.aws,
    debug: opts.debug,
    sigma,
    records,
    repairs,
    recordGate: plan.gate,
    provenance: plan.provenance,
  });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  recordParsedImport(opts.debug, parsedRaw, parsedRaw.events.length, parsed.events.length);
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return {
      state: await noteEmptyImport(
        ctx,
        caseId,
        opts,
        "AWS CloudTrail",
        parsed.total,
        [dedupNote, describeJsonRepairs(parsed.repairs)].filter(Boolean).join("; ") || undefined,
      ),
      coverage: parsed.coverage,
    };

  // An identity IOC (#2543) links to the row that produced it, through the row's aggKey.
  const eventIdByAggKey = new Map(parsed.events.map((e, i) => [e.aggKey ?? "", `${opts.idPrefix}e${i + 1}`]));
  const raw = {
    findings: [],
    iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
      id: `${opts.idPrefix}i${i + 1}`,
      type: c.type,
      value: c.value,
      ...(c.note ? { note: c.note } : {}),
      ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
    })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["AWS CloudTrail"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `AWS CloudTrail import: ${parsed.events.length} event(s) from ${parsed.total} record(s)` +
      describeFloor(parsedRaw.events.length, parsed.events.length) +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)` +
      sigmaImportNote(sigma, parsedRaw.sigmaRowsMatched) +
      (dedupNote ? `, ${dedupNote}` : "") +
      jsonRepairNote(parsed.repairs),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  const state = await ctx.withStateLock(caseId, async () => {
    abortIfCancelled(opts.signal);
    const s = await mergeAndSaveDelta(ctx, caseId, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    opts.onProgress?.(1, 1);
    return s;
  });
  await settleCloudRecords(ctx, caseId, plan, opts, parsed.events, opts.debug);
  return { state, coverage: parsed.coverage };
}

// Import GCP Cloud Audit Logs + Azure Activity Log. Deterministic (no AI call): each record
// is routed (GCP / Azure) and mapped, severity derived from the action (+ denied bump); the
// caller IP → IOC and the principal email is surfaced for the asset graph.
export async function importCloudActivity(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "g3") so ids never collide
    importedAt: string;
    cloud?: CloudActivityImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    debug?: ImportDebugRecorder;
    onProgress?: (done: number, total: number) => void;
    signal?: AbortSignal; // #2425: the import job's Cancel — checked right before the merge
  },
): Promise<ImportWithCoverage> {
  // One Sigma snapshot for this whole import (#2204); it grades the GCP records only (#2346).
  const sigma = ctx.opts.sigmaGrader?.snapshot();
  const { records, repairs } = readCloudRecords(text);
  const plan = await planCloudRecords(ctx, caseId, opts.idPrefix, () =>
    records.map((rec) => cloudRecordIdentity(cloudActivityRecordProvider(rec), rec)),
  );
  recordCloudRecordDebug(plan, opts.debug);
  const dedupNote = cloudRecordNote(plan);
  const parsedRaw = parseCloudActivity(text, {
    ...opts.cloud,
    debug: opts.debug,
    sigma,
    records,
    repairs,
    recordGate: plan.gate,
    provenance: plan.provenance,
  });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  recordParsedImport(opts.debug, parsedRaw, parsedRaw.events.length, parsed.events.length);
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return {
      state: await noteEmptyImport(
        ctx,
        caseId,
        opts,
        "Cloud activity",
        parsed.total,
        [dedupNote, describeJsonRepairs(parsed.repairs)].filter(Boolean).join("; ") || undefined,
      ),
      coverage: parsed.coverage,
    };

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Cloud Audit"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Cloud activity import (${parsed.format}): ${parsed.events.length} event(s) from ${parsed.total} record(s)` +
      describeFloor(parsedRaw.events.length, parsed.events.length) +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)` +
      // Only an import that carried GCP records was graded by Sigma; Azure Activity never is.
      (parsed.format === "gcp" || parsed.format === "mixed"
        ? sigmaImportNote(sigma, parsedRaw.sigmaRowsMatched)
        : "") +
      (dedupNote ? `, ${dedupNote}` : "") +
      jsonRepairNote(parsed.repairs),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  const state = await ctx.withStateLock(caseId, async () => {
    abortIfCancelled(opts.signal);
    const s = await mergeAndSaveDelta(ctx, caseId, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    opts.onProgress?.(1, 1);
    return s;
  });
  await settleCloudRecords(ctx, caseId, plan, opts, parsed.events, opts.debug);
  return { state, coverage: parsed.coverage };
}
