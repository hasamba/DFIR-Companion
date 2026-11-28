// The body of a CrowdStrike Next-Gen SIEM search job (#2666): run the search, keep the returned rows
// as evidence, import them through the CrowdStrike importer and settle them like every import.
//
// Evidence first: the returned rows are stored (one JSON object per line, fields unmodified) and
// custody-logged BEFORE anything reaches the timeline. The import then crosses the one settle seam
// (routes/importSettle.ts): merge -> super-timeline dual-write -> content tagger -> demote, so Info
// rows land in the super-timeline only and only graded rows reach the forensic timeline (CLAUDE.md
// §7). Nothing here reads the super-timeline.
//
// `table([...])` output keeps only the listed fields, so a per-event query's rows can arrive without
// their event name. When the query names exactly one event type and aggregates nothing
// (analysis/siemSearch.ts inferredEventName), rows that carry an event time are given that name in
// the IMPORT text; the stored evidence keeps the rows as Falcon returned them. Rows that are still not
// Falcon events (groupBy totals, an unfinished aggregate) stay in the evidence file only.

import { inferredEventName, siemSearchText, type SiemSearchOutcome } from "../analysis/siemSearch.js";
import { crowdstrikeTime } from "../analysis/crowdstrikeTime.js";
import { eventName } from "../analysis/crowdstrikeFields.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";
import type { NgsiemRow, NgsiemRunResult } from "../integrations/crowdstrike/ngsiemSearch.js";
import type { RouteContext } from "./context.js";
import { beginImportSection } from "./importSection.js";
import { gradeArmOf } from "./importSettle.js";
import { settleImportOrRecoverThenThrow } from "./importRowRecovery.js";
import { routeSettleDeps } from "./routeSettleDeps.js";
import { countsFromSettled, type ImportCounts } from "../analysis/importNotification.js";

export const NGSIEM_SOURCE_LABEL = "CrowdStrike NG-SIEM";
const EVIDENCE_SOURCE = "CrowdStrike Next-Gen SIEM";

export interface SiemSearchSpec {
  caseId: string;
  title: string;
  query: string;
  startMs: number;
  endMs: number;
  repository: string;
  maxRows: number;
  timeoutMs: number;
  actor: string;
}

/** The rows the importer reads: the evidence rows, a missing event name filled in where safe. */
export function importRows(
  rows: readonly NgsiemRow[],
  query: string,
  result: Pick<NgsiemRunResult, "aggregate" | "finished">,
): { text: string; indexes: number[]; events: number } {
  if (result.aggregate && !result.finished) return { text: "", indexes: [], events: 0 }; // provisional
  const name = inferredEventName(query);
  const lines: string[] = [];
  const indexes: number[] = [];
  rows.forEach((row, i) => {
    let r = row;
    if (!eventName(r) && name && crowdstrikeTime(r)) r = { ...r, "#event_simpleName": name };
    if (!eventName(r)) return; // not a Falcon event: evidence file only
    lines.push(JSON.stringify(r));
    indexes.push(i);
  });
  return { text: lines.join("\n"), indexes, events: lines.length };
}

const stamp = (d: Date): string =>
  d
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d+Z$/, "Z");

/** Store the returned rows as evidence and custody-log them; returns the stored name and text. */
async function saveEvidence(ctx: RouteContext, spec: SiemSearchSpec, rows: readonly NgsiemRow[]) {
  const { store } = ctx;
  const seq = await store.nextImportSeq(spec.caseId);
  const storedName = `${String(seq).padStart(4, "0")}_crowdstrike-ngsiem_${stamp(new Date())}.ndjson`;
  const text = rows.map((r) => JSON.stringify(r)).join("\n");
  const importedAt = new Date().toISOString();
  await store.saveImport(spec.caseId, storedName, text, {
    source: EVIDENCE_SOURCE,
    trigger: "siem-search",
    collectedBy: spec.actor,
  });
  await store.appendImport(spec.caseId, {
    caseId: spec.caseId,
    sequenceNumber: seq,
    importedAt,
    filename: storedName,
    originalName: `${spec.repository}: ${spec.title}`.slice(0, 200),
    rows: rows.length,
    bytes: Buffer.byteLength(text, "utf8"),
  });
  return { storedName, text, seq, importedAt };
}

/** Import the event rows inside the case's import section and settle them. Returns what it added (#2978). */
async function importAndSettle(
  ctx: RouteContext,
  spec: SiemSearchSpec,
  saved: Awaited<ReturnType<typeof saveEvidence>>,
  forImport: ReturnType<typeof importRows>,
): Promise<ImportCounts> {
  const { options } = ctx;
  const pipeline = options.pipeline;
  const settle = routeSettleDeps(ctx);
  if (!pipeline || !settle || !options.stateStore) throw new Error("the case cannot import rows right now");
  const section = await beginImportSection(
    ctx.importLock,
    spec.caseId,
    options.stateStore,
    { incomingBytes: Buffer.byteLength(forImport.text, "utf8") },
    gradeArmOf(settle), // #2909
  );
  try {
    const baseline: ImportBaseline | null = section.baseline;
    // No snapshot means no settle: importing anyway would leave raw Info rows in the forensic
    // timeline, untagged and undemoted (CLAUDE.md §7). Refuse before the case changes.
    if (!baseline) throw new Error("the case could not be snapshotted, so nothing was imported");
    await pipeline.importCrowdstrike(spec.caseId, forImport.text, {
      label: saved.storedName,
      idPrefix: `ngsiem${saved.seq}-`,
      importedAt: saved.importedAt,
      crowdstrike: {
        sourceText: saved.text,
        recordIndexes: forImport.indexes,
        extraSource: NGSIEM_SOURCE_LABEL,
      },
    });
    // A settle failure still fails the search, after its rows are settled (#2891).
    const target = { caseId: spec.caseId, storedNames: [saved.storedName], tag: "crowdstrike" };
    const settled = await settleImportOrRecoverThenThrow(settle, target, baseline, saved.storedName);
    const { timelineDiff: diff, iocsDiff } = settled;
    if (options.importMetaStore) {
      await options.importMetaStore.record(spec.caseId, {
        kind: "crowdstrike",
        file: saved.storedName,
        source: `${NGSIEM_SOURCE_LABEL} search (${spec.repository})`,
        diff,
        superTimelineAddedCount: settled.superTimelineAddedCount,
        superTimelineAvailable: settled.superTimelineAvailable, // #3045
        superTimelineEvicted: settled.superTimelineEvicted,
        iocsDiff,
        linesIn: forImport.events,
        path: "deterministic",
      });
      options.onImportMeta?.(spec.caseId);
    }
    const changed =
      diff.added.length || diff.removed.length || iocsDiff.added.length || iocsDiff.removed.length;
    if (changed || settled.principalNamesChanged) {
      await ctx.pushImportCheckpoint(spec.caseId, baseline, `crowdstrike (${saved.storedName})`);
    }
    return countsFromSettled(settled);
  } finally {
    section.release();
  }
}

/**
 * Keep and import what a search returned. Zero rows store no file. The outcome is what the activity
 * log, the job and Watson's case event say.
 */
export async function landSearchResult(
  ctx: RouteContext,
  spec: SiemSearchSpec,
  result: NgsiemRunResult,
  /** Closes the job's Cancel and says whether a cancel already landed — called before the first write. */
  closeCancel: () => boolean = () => false,
): Promise<SiemSearchOutcome & { storedName?: string; counts?: ImportCounts }> {
  const base: SiemSearchOutcome = {
    title: spec.title,
    rows: result.rows.length,
    events: 0,
    added: 0,
    truncated: result.truncated,
    timedOut: result.timedOut,
    timeoutMs: spec.timeoutMs,
    ...(result.error ? { error: result.error } : {}),
  };
  if (!result.rows.length) {
    // A search that stopped before any row is incomplete, never "found nothing".
    if (result.timedOut) {
      return {
        ...base,
        failed: `it timed out after ${Math.round(spec.timeoutMs / 60_000)} minutes before Falcon returned any rows`,
      };
    }
    if (result.aggregate && !result.finished) return { ...base, failed: "the search did not finish" };
    return base;
  }
  // The first write: from here the search cannot be cancelled, and a cancel that already landed
  // stops it with nothing written (the same order as routes/importCommitJob.ts closeCancel).
  if (closeCancel()) throw new DOMException("The search was cancelled", "AbortError");
  const saved = await saveEvidence(ctx, spec, result.rows);
  const forImport = importRows(result.rows, spec.query, result);
  if (!forImport.events) return { ...base, storedName: saved.storedName };
  const counts = await importAndSettle(ctx, spec, saved, forImport);
  if (counts.added > 0) ctx.resynthesizeInBackground(spec.caseId);
  return { ...base, events: forImport.events, added: counts.added, storedName: saved.storedName, counts };
}

/** The activity entry: what ran, where, over which range, what came back, and who pressed Run. */
export function activityDetail(
  spec: SiemSearchSpec,
  outcome: SiemSearchOutcome & { storedName?: string },
  warnings: readonly string[] = [],
): string {
  const range = `${new Date(spec.startMs).toISOString()} to ${new Date(spec.endMs).toISOString()}`;
  const parts = [
    siemSearchText(outcome) + ".",
    `Repository: ${spec.repository}. Time range: ${range}.`,
    `Rows read: ${outcome.rows}; Falcon events imported: ${outcome.events}; new timeline events: ${outcome.added}` +
      (outcome.truncated ? " (truncated)" : "") +
      ".",
    outcome.storedName ? `Evidence file: ${outcome.storedName}.` : "",
    `Run by: ${spec.actor}.`,
    ...warnings,
    `Query: ${spec.query}`,
  ];
  return parts.filter(Boolean).join(" ");
}
