import {
  CROWDSTRIKE_SOURCE,
  parseCrowdstrikeExport,
  type CrowdstrikeImportOptions,
} from "../crowdstrikeImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { type InvestigationState, type Severity } from "../stateTypes.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import { recordFloor } from "../parseDebugTally.js";
import { describeFloor } from "./floorNote.js";
import { noteEmptyImport, mergeAndSaveDelta } from "./importState.js";
import type { ImportContext } from "./importContext.js";

// Import CrowdStrike Falcon sensor exports (#2592) — Event Search / LogScale / NG-SIEM
// (`#event_simpleName`) or FDR (`event_simpleName`) rows as JSON, NDJSON or CSV. Deterministic (no
// AI call): crowdstrikeImport.ts dates each row by its event time, maps each event family into a
// description + IOCs, and keeps raw telemetry at Info for the route-seam tagger. Same shape as
// importEcar, without ECAR's cross-upload password-spray pass.
export async function importCrowdstrike(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import so ids never collide
    importedAt: string;
    crowdstrike?: CrowdstrikeImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
    debug?: ImportDebugRecorder;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseCrowdstrikeExport(text, { ...opts.crowdstrike, debug: opts.debug });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  opts.debug?.counts({ total: parsed.total, kept: parsed.events.length, dropped: parsed.dropped });
  recordFloor(opts.debug, parsedRaw.events.length, parsed.events.length);
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "CrowdStrike Falcon", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [CROWDSTRIKE_SOURCE],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `CrowdStrike Falcon import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
      describeFloor(parsedRaw.events.length, parsed.events.length) +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return ctx.withStateLock(caseId, async () => {
    const state = await mergeAndSaveDelta(ctx, caseId, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    opts.onProgress?.(1, 1);
    return state;
  });
}
