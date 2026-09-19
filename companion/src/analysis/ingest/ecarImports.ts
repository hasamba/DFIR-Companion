import { ECAR_SOURCE, parseEcarJson, type EcarImportOptions } from "../ecarImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { type InvestigationState, type Severity } from "../stateTypes.js";
import { describeFloor } from "./floorNote.js";
import { noteEmptyImport, crossUploadSprayRows } from "./importState.js";
import type { ImportContext } from "./importContext.js";

/**
 * ECAR (EDR Common Activity Record) ingest.
 *
 * Split out of endpointImports.ts (#1286): that file sits at the 800-line ledger ceiling, and the
 * cross-upload retention disclosure needed two more lines than it had headroom for. Same shape as
 * every other ingest module — a free function taking an ImportContext; pipeline.ts keeps its
 * one-line delegation, so callers are unchanged.
 */

// Import ECAR — EDR Common Activity Record telemetry (NDJSON of (object, action) endpoint events).
// Deterministic (no AI call): maps each record's object/action/properties into a forensic event,
// reads `timestamp_ms`, scrapes PUBLIC IPs as IOCs, and keeps severity conservative (Info evidence,
// bumped only on real tradecraft) so high-volume raw telemetry doesn't flood the timeline. See
// ecarImport.ts for the mapping (and the lsass-access false-positive rationale).
export async function importEcar(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import so ids never collide
    importedAt: string;
    ecar?: EcarImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseEcarJson(text, { ...opts.ecar });
  const { events: crossRows, retentionNote } = await crossUploadSprayRows(
    ctx,
    caseId,
    opts,
    parsedRaw.sprayCandidates,
    {
      source: ECAR_SOURCE,
      importer: "ecar",
      mappingVersion: "ecar-spray-cross-v1",
    },
  );
  const parsed = {
    ...parsedRaw,
    events: applySeverityFloor([...parsedRaw.events, ...crossRows], opts.minSeverity),
  };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "ECAR", parsed.total, retentionNote || undefined);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [ECAR_SOURCE],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `ECAR import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
      describeFloor(parsedRaw.events.length + crossRows.length, parsed.events.length) +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      (parsed.hostname ? ` (host ${parsed.hostname})` : "") +
      (retentionNote ? `; ${retentionNote}` : ""),
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
