import { parseCloudSnapshot, snapshotEvent, SHAPE_LABEL, type SnapshotEvent } from "../cloudSnapshotParse.js";
import {
  decide,
  identityId,
  stateHash,
  type StoredSnapshotObservation,
  type SnapshotDecision,
} from "../cloudSnapshotModel.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import type { InvestigationState, Severity } from "../stateTypes.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import { describeFloor } from "./floorNote.js";
import { noteEmptyImport, mergeAndSaveDelta } from "./importState.js";
import type { ImportContext } from "./importContext.js";

/**
 * Microsoft-Extractor-Suite configuration snapshots (#2305): inbox rules, transport rules, OAuth
 * grants, MFA methods. Deterministic (no AI call). Each row is an OBSERVATION of state at collection
 * time, compared with the case's earlier observations of the same object (cloudStateStore.ts):
 * a never-seen object adds one observation, a changed one adds one change observation with a short
 * diff, and an unchanged one, a re-import or an older snapshot imported last adds nothing.
 */
export async function importCloudSnapshot(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    minSeverity?: Severity;
    debug?: ImportDebugRecorder;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsed = parseCloudSnapshot(text, opts);
  const shape = parsed.shape;
  if (!shape)
    return noteEmptyImport(ctx, caseId, opts, "Cloud snapshot", parsed.total, "the columns name no snapshot");
  const store = ctx.opts.cloudStateStore;
  const ids = parsed.rows.map((m) => identityId(m.identityKey));
  const history = store ? await store.history(caseId, ids) : new Map<string, StoredSnapshotObservation[]>();

  const counts = { new: 0, changed: 0, unchanged: 0, duplicate: 0, older: 0 };
  const events: SnapshotEvent[] = [];
  const toStore: StoredSnapshotObservation[] = [];
  parsed.rows.forEach((m, i) => {
    const observation = {
      id: ids[i],
      observedAt: parsed.time.observedAt,
      stateHash: stateHash(m.state),
      state: m.state,
    };
    const d: SnapshotDecision = decide(history.get(ids[i]) ?? [], observation.observedAt, m.state);
    counts[d.kind]++;
    if (d.kind !== "duplicate") toStore.push(observation);
    if (d.kind === "new" || d.kind === "changed") events.push(snapshotEvent(m, shape, parsed.time, d));
  });

  const kept = applySeverityFloor(events, opts.minSeverity);
  const note = snapshotNote(parsed, counts, !!store) + describeFloor(events.length, kept.length);
  opts.debug?.counts({ total: parsed.total, kept: kept.length });
  const state = kept.length
    ? await mergeEvents(ctx, caseId, opts, kept, `${SHAPE_LABEL[shape]} import: ${note}`)
    : await noteEmptyImport(ctx, caseId, opts, SHAPE_LABEL[shape], parsed.total, note);
  // After the merge, so a failed merge leaves the store as it was and a retry re-announces.
  if (store && toStore.length) await store.append(caseId, toStore, opts.idPrefix, opts.label);
  return state;
}

function snapshotNote(
  parsed: ReturnType<typeof parseCloudSnapshot>,
  c: Record<SnapshotDecision["kind"], number>,
  stored: boolean,
): string {
  const parts = [
    `${parsed.total} row(s), ${c.new} new observation(s), ${c.changed} changed`,
    `${c.unchanged + c.duplicate} unchanged or already imported`,
    ...(c.older ? [`${c.older} older than a stored observation (no change announced)`] : []),
    ...(parsed.duplicates ? [`${parsed.duplicates} repeated row(s) in the file`] : []),
    ...(parsed.skipped ? [`${parsed.skipped} row(s) without the columns naming the object`] : []),
    `time: ${parsed.time.basis}`,
    ...(stored ? [] : ["no observation store: every row reads as new"]),
  ];
  return parts.join("; ");
}

async function mergeEvents(
  ctx: ImportContext,
  caseId: string,
  opts: { label: string; idPrefix: string; importedAt: string; onProgress?: (d: number, t: number) => void },
  events: SnapshotEvent[],
  timelineNote: string,
): Promise<InvestigationState> {
  const delta = deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicEvents: events.map((e, i) => ({ ...e, id: `${opts.idPrefix}s${i + 1}` })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote,
    summary: "",
  });
  return ctx.withStateLock(caseId, async () => {
    const s = await mergeAndSaveDelta(ctx, caseId, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    opts.onProgress?.(1, 1);
    return s;
  });
}
