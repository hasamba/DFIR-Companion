// Amazon GuardDuty findings, the whole-file path (#2361) — a hand-dropped or uploaded export small
// enough to read as one string. A large or gzipped one streams through cloudStreamImport.ts with the
// `guardduty` stream provider instead; a collected page streams too. Deterministic (no AI call).
// Each finding is identified by account + region + id + update time (cloudRecordIdentity.ts), so an
// identical re-import is dropped as a duplicate and an updated finding lands as a new observation.

import { guardDutyNoteDetail, parseGuardDuty, GUARDDUTY_SOURCE } from "../guardDutyImport.js";
import { readGuardDutyRecords } from "../guardDutyRecord.js";
import { cloudRecordIdentity } from "../cloudRecordIdentity.js";
import { deltaSchema } from "../responseSchema.js";
import { describeJsonRepairs, jsonRepairNote } from "../tolerantJson.js";
import { applySeverityFloor } from "../severityFloor.js";
import type { InvestigationState, Severity } from "../stateTypes.js";
import { describeFloor } from "./floorNote.js";
import { noteEmptyImport, mergeAndSaveDelta } from "./importState.js";
import type { ImportContext } from "./importContext.js";
import { recordParsedImport } from "./parsedDebug.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import {
  cloudRecordNote,
  planCloudRecords,
  recordCloudRecordDebug,
  settleCloudRecords,
} from "./cloudRecordIngest.js";

export async function importGuardDuty(
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
  const { records, repairs } = readGuardDutyRecords(text);
  const plan = await planCloudRecords(ctx, caseId, opts.idPrefix, () =>
    records.map((rec) => cloudRecordIdentity("guardduty", rec)),
  );
  recordCloudRecordDebug(plan, opts.debug);
  const dedupNote = cloudRecordNote(plan);
  const parsedRaw = parseGuardDuty(text, {
    debug: opts.debug,
    records,
    repairs,
    recordGate: plan.gate,
    provenance: plan.provenance,
  });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  recordParsedImport(opts.debug, parsedRaw, parsedRaw.events.length, parsed.events.length);
  const extra = guardDutyNoteDetail(parsedRaw);
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(
      ctx,
      caseId,
      opts,
      GUARDDUTY_SOURCE,
      parsed.total,
      [dedupNote, extra, describeJsonRepairs(parsed.repairs)].filter(Boolean).join("; ") || undefined,
    );

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [GUARDDUTY_SOURCE],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `AWS GuardDuty import: ${parsed.events.length} event(s) from ${parsed.total} finding(s)` +
      describeFloor(parsedRaw.events.length, parsed.events.length) +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)` +
      (extra ? `, ${extra}` : "") +
      (dedupNote ? `, ${dedupNote}` : "") +
      jsonRepairNote(parsed.repairs),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  const state = await ctx.withStateLock(caseId, async () => {
    const s = await mergeAndSaveDelta(ctx, caseId, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    opts.onProgress?.(1, 1);
    return s;
  });
  await settleCloudRecords(ctx, caseId, plan, opts, parsed.events, opts.debug);
  return state;
}
