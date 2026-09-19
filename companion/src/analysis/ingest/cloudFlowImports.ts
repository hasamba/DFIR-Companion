// Cloud data-plane flow-log sources (#931 item 13): AWS VPC Flow Logs (#1113), Azure virtual
// network flow logs and GCP VPC Flow Logs (#1294). Split out of cloudImports.ts when the three
// ingest functions pushed it past the 800-line cap. Each is deterministic (no AI call) and lands
// every kept row as a Low `network/flow` event; the per-provider refusal/gap counts are named in
// the import note so an analyst never reads "zero rows" as "no traffic".

import { parseAwsFlowLog, type AwsFlowLogImportOptions } from "../awsFlowLogImport.js";
import { parseAzureFlowLog, type AzureFlowLogImportOptions } from "../azureFlowLogImport.js";
import { parseGcpFlowLog, type GcpFlowLogImportOptions } from "../gcpFlowLogImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { type InvestigationState, type Severity } from "../stateTypes.js";
import { describeFloor } from "./floorNote.js";
import { noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";

// Import AWS VPC Flow Logs, default (v2) format (#931 item 13). Deterministic (no AI call).
export async function importAwsFlowLog(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    awsFlowLog?: AwsFlowLogImportOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseAwsFlowLog(text, opts.awsFlowLog);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0) {
    // Codex review (P2): an all-SKIPDATA/NODATA upload must not silently lose the coverage
    // disclosure just because it produced zero events — SKIPDATA in particular is a real AWS
    // collection gap, not "nothing to report."
    const gapDetail = [
      parsed.nodata ? `${parsed.nodata} NODATA interval(s)` : "",
      parsed.skipdata ? `${parsed.skipdata} SKIPDATA interval(s) — a collection gap, not "no traffic"` : "",
      parsed.malformed ? `${parsed.malformed} malformed line(s)` : "",
    ]
      .filter(Boolean)
      .join(", ");
    return noteEmptyImport(ctx, caseId, opts, "AWS VPC Flow Logs", parsed.total, gapDetail || undefined);
  }

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["AWS VPC Flow Logs"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    // NODATA/SKIPDATA are disclosed by name (#931 item 13 — Codex review) — not lumped into one
    // generic "dropped": SKIPDATA is a real AWS-side collection gap, NODATA is not.
    timelineNote:
      `AWS VPC Flow Log import (${parsed.format}): ${parsed.events.length} event(s) from ${parsed.total} record(s)` +
      describeFloor(parsedRaw.events.length, parsed.events.length) +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      (parsed.nodata ? `, ${parsed.nodata} NODATA interval(s)` : "") +
      (parsed.skipdata
        ? `, ${parsed.skipdata} SKIPDATA interval(s) — a collection gap, not "no traffic"`
        : "") +
      (parsed.malformed ? `, ${parsed.malformed} malformed line(s)` : "") +
      `, ${parsed.iocs.length} IOC(s)`,
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return ctx.withStateLock(caseId, async () => {
    let state = await ctx.opts.stateStore.load(caseId);
    state = await ctx.mergeWithAliases(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await ctx.opts.stateStore.save(state);
    ctx.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  });
}

// Import Azure virtual network flow logs, flowLogVersion 4 (#931 item 13 second half, #1294).
// Deterministic (no AI call). Refused shapes (the retired NSG format, another version) are named in
// the note, never misparsed; `noTarget` rows keep the tuple but carry no subscription/resource.
export async function importAzureFlowLog(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    azureFlowLog?: AzureFlowLogImportOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseAzureFlowLog(text, opts.azureFlowLog);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  const detail = [
    parsed.legacyNsg ? `${parsed.legacyNsg} retired NSG-format record(s) refused by name (not read)` : "",
    parsed.unsupportedVersion
      ? `${parsed.unsupportedVersion} record(s) of an unsupported flowLogVersion (only 4 is read)`
      : "",
    parsed.malformed ? `${parsed.malformed} malformed tuple(s)` : "",
    parsed.unspecifiedRule ? `${parsed.unspecifiedRule} encryption-denied group(s) (rule unspecified)` : "",
    parsed.noTarget
      ? `${parsed.noTarget} record(s) with no targetResourceID (rows kept, no subscription)`
      : "",
  ]
    .filter(Boolean)
    .join(", ");
  if (parsed.events.length === 0 && parsed.iocs.length === 0) {
    return noteEmptyImport(
      ctx,
      caseId,
      opts,
      "Azure virtual network flow logs",
      parsed.tuples,
      detail || undefined,
    );
  }
  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Azure virtual network flow logs"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Azure virtual network flow log import (${parsed.format}): ${parsed.events.length} event(s) from ${parsed.tuples} tuple(s) in ${parsed.records} record(s)` +
      describeFloor(parsedRaw.events.length, parsed.events.length) +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      (detail ? `, ${detail}` : "") +
      `, ${parsed.iocs.length} IOC(s). Direction is relative to the logged NIC; rule tokens are printed as logged and may be platform rules; no VM is attributed (the record names a NIC by MAC only).`,
    summary: "",
  };
  const delta = deltaSchema.parse(raw);
  return ctx.withStateLock(caseId, async () => {
    let state = await ctx.opts.stateStore.load(caseId);
    state = await ctx.mergeWithAliases(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await ctx.opts.stateStore.save(state);
    ctx.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  });
}

// Import GCP VPC Flow Logs from a Cloud Logging export (#931 item 13 second half, #1294).
// Deterministic (no AI call). Instance/VPC names in a row are Google's own annotations, never a
// join made here; the records are sampled, so absence is never "no traffic".
export async function importGcpFlowLog(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    gcpFlowLog?: GcpFlowLogImportOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseGcpFlowLog(text, opts.gcpFlowLog);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  const detail = [
    parsed.nonFlow ? `${parsed.nonFlow} non-flow log entr(ies) skipped` : "",
    parsed.malformed ? `${parsed.malformed} malformed entr(ies)` : "",
    parsed.droppedRecords ? `${parsed.droppedRecords} DROPPED record(s)` : "",
    parsed.noReporterInstance
      ? `${parsed.noReporterInstance} entr(ies) with no instance annotation on the reporting side`
      : "",
  ]
    .filter(Boolean)
    .join(", ");
  if (parsed.events.length === 0 && parsed.iocs.length === 0) {
    return noteEmptyImport(ctx, caseId, opts, "GCP VPC Flow Logs", parsed.total, detail || undefined);
  }
  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["GCP VPC Flow Logs"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `GCP VPC Flow Log import (${parsed.format}): ${parsed.events.length} event(s) from ${parsed.total} log entr(ies)` +
      describeFloor(parsedRaw.events.length, parsed.events.length) +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      (detail ? `, ${detail}` : "") +
      `, ${parsed.iocs.length} IOC(s). VPC Flow Logs are sampled — a flow that does not appear is not evidence of no traffic; instance and VPC names are Google's own log-time annotations, not a join made here; bytes are user payload only.`,
    summary: "",
  };
  const delta = deltaSchema.parse(raw);
  return ctx.withStateLock(caseId, async () => {
    let state = await ctx.opts.stateStore.load(caseId);
    state = await ctx.mergeWithAliases(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await ctx.opts.stateStore.save(state);
    ctx.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  });
}
