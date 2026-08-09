import type { PlasoParseResult } from "../plasoImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import type { InvestigationState, Severity } from "../stateTypes.js";
import type { ImportContext } from "./importContext.js";

/**
 * The two shared tails every deterministic importer ends in (#418).
 *
 * They were methods on AnalysisPipeline and members of ImportContext, which meant the AI-tier file
 * carried a hundred lines of pure ingest bookkeeping and every importer's interface advertised two
 * operations it mostly did not use. As free functions over the same ImportContext they read the
 * same at the call site — `noteEmptyImport(ctx, …)` instead of `ctx.noteEmptyImport(…)` — and the
 * code lives where the callers do.
 */

/**
 * The load → merge → save → announce tail all deterministic imports share.
 *
 * Exported because it was not actually being shared: every wrapper in platformImports.ts had this
 * same block pasted into it, so the one sequence that must stay consistent across importers — take
 * the lock, merge under the import's timestamp, save, announce — existed in a dozen copies free to
 * drift apart (#517).
 *
 * `signal` is checked inside the lock: an import cancelled while queued behind another write to the
 * same case must not merge its delta after the analyst gave up on it.
 */
export async function commitDelta(
  ctx: ImportContext,
  caseId: string,
  delta: ReturnType<typeof deltaSchema.parse>,
  opts: {
    label: string;
    importedAt: string;
    onProgress?: (done: number, total: number) => void | Promise<void>;
    signal?: AbortSignal;
  },
): Promise<InvestigationState> {
  return ctx.withStateLock(caseId, async () => {
    if (opts.signal?.aborted) {
      throw Object.assign(new Error("import processing cancelled; stored evidence retained"), {
        name: "AbortError",
      });
    }
    let state = await ctx.opts.stateStore.load(caseId);
    state = await ctx.mergeWithAliases(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await ctx.opts.stateStore.save(state);
    ctx.opts.onState?.(state);
    await opts.onProgress?.(1, 1);
    return state;
  });
}

// Record an import that parsed cleanly but contributed nothing.
//
// Every deterministic importer guards on "no events (and no IOCs) → return the state unchanged".
// That guard is correct — an empty delta must not be merged — but returning silently meant the
// file was 202-accepted, stored under `imports/`, and left NO trace in the case: the analyst had
// no way to tell "ingested and understood" from "silently dropped". On the northpeak benchmark
// that hid Zeek conn.json contributing zero events out of 75,951 records, the largest artifact in
// the case. A note costs one small timeline row and makes the outcome legible.
//
// `total` is the importer's own parsed-record count, so the note says how much was READ, not just
// that nothing came out — "0 events from 0 records" (wrong format) and "0 events from 75,951
// records" (understood but uninteresting) are very different problems.
export async function noteEmptyImport(
  ctx: ImportContext,
  caseId: string,
  opts: { label: string; importedAt: string; onProgress?: (done: number, total: number) => void },
  kind: string,
  total: number,
): Promise<InvestigationState> {
  const delta = deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicEvents: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: `${kind} import: no events from ${total} record(s) — nothing added to the case`,
    summary: "",
  });
  return commitDelta(ctx, caseId, delta, opts);
}

// Shared tail of both Plaso entry points: apply the severity floor, build the delta and merge it
// into the case state. (Keeping this in one place means the in-memory and streaming importers
// produce identical timeline rows / IOCs / notes.)
export async function persistPlasoParsed(
  ctx: ImportContext,
  caseId: string,
  parsedRaw: PlasoParseResult,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return noteEmptyImport(ctx, caseId, opts, "Plaso", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Plaso"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Plaso import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)`,
    summary: "",
  };

  return commitDelta(ctx, caseId, deltaSchema.parse(raw), opts);
}
