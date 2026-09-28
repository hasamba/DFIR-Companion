/**
 * The Hayabusa importer, and the one seam that sends a Velociraptor-pulled Hayabusa result to it.
 *
 * #1756: the drop folder routes a `*hayabusa*` file with a Hayabusa body to the native importer
 * (#700), but a hunt collect and an external hunt/flow import called the Velociraptor importer
 * directly. One file then gave two event counts, two severity sets and two host names depending on
 * how it arrived. `importVelociraptorArtifact` asks the same question auto-detect asks
 * (looksLikeHayabusaNamedExport) and hands a Hayabusa result to `importHayabusa`, carrying over the
 * options the pull paths set: the hunt-wide event budget, the flow's host, the GUI link, and the
 * partly-read mark. A result over DFIR_MAX_IMPORT_FILE_MB keeps the batched Velociraptor path: the
 * Hayabusa importer is whole-file, and that is the cap the drop folder applies to the same file.
 * Moved out of endpointImports.ts, which had no room under the file-size cap.
 */
import {
  looksLikeHayabusaNamedExport,
  parseHayabusaTimeline,
  type HayabusaImportOptions,
} from "../hayabusaImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { type InvestigationState, type Severity } from "../stateTypes.js";
import type { VelociraptorImportOptions } from "../velociraptorImport.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import { describeFloor } from "./floorNote.js";
import { deltaIocs, hostIdentityDelta, knownHostIdentity, noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";
import { recordParsedImport } from "./parsedDebug.js";
import { importVelociraptor } from "./endpointImports.js";
import { maxImportFileBytes } from "./importFileCap.js";

// Import a Hayabusa (Yamato Security) detection timeline — JSON/JSONL or CSV. Like the
// other deterministic paths there is no AI call: the matched Sigma rule's level drives
// severity, its title leads the description, its tactics/tags become MITRE, and IOCs /
// asset / process-chain come from the rendered detail fields. Tagged Hayabusa as source.
export async function importHayabusa(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "h3") so ids never collide
    importedAt: string;
    hayabusa?: HayabusaImportOptions; // filtering overrides (aggregate, minSeverity, maxEvents…)
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    veloUrl?: string; // the Velociraptor hunt/flow GUI link, when the result was pulled from one (#1756)
    partlyReadArtifact?: string; // the pull read had no source list: stamp every event (#1651)
    onProgress?: (done: number, total: number) => void;
    debug?: ImportDebugRecorder; // this attempt's decision recorder (#1736)
  },
): Promise<InvestigationState> {
  const known = await knownHostIdentity(ctx, caseId); // the case's rename ledger seeds the parse (#1495)
  const parsedRaw = parseHayabusaTimeline(text, { ...known, ...opts.hayabusa, debug: opts.debug });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  recordParsedImport(opts.debug, parsedRaw, parsedRaw.events.length, parsed.events.length);
  if (parsed.events.length === 0 && parsed.iocs.length === 0 && parsed.hostRenames.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "Hayabusa", parsed.total);

  const raw = {
    findings: [],
    iocs: deltaIocs(parsed.iocs, opts.idPrefix),
    mitreTechniques: [],
    ...hostIdentityDelta(parsed),
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Hayabusa"],
      ...(opts.veloUrl ? { veloUrl: opts.veloUrl } : {}),
      ...(opts.partlyReadArtifact ? { partlyReadArtifact: opts.partlyReadArtifact } : {}),
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Hayabusa import (${parsed.format}): ${parsed.events.length} event(s) from ${parsed.total} record(s)` +
      describeFloor(parsedRaw.events.length, parsed.events.length) +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      (parsed.groups > parsed.kept && parsed.dropped > 0
        ? `, ${parsed.dropped} record(s) omitted at the event cap`
        : "") +
      (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
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

// The Velociraptor options that mean the same thing to the Hayabusa parser. Only keys the caller set
// are copied: an explicit `undefined` would overwrite the case's rename ledger inside importHayabusa.
function hayabusaOptionsFrom(v: VelociraptorImportOptions | undefined): HayabusaImportOptions | undefined {
  if (!v) return undefined;
  const out: HayabusaImportOptions = {};
  if (v.aggregate !== undefined) out.aggregate = v.aggregate;
  if (v.minSeverity !== undefined) out.minSeverity = v.minSeverity;
  if (v.maxEvents !== undefined) out.maxEvents = v.maxEvents; // the hunt-wide budget
  if (v.maxIocs !== undefined) out.maxIocs = v.maxIocs;
  if (v.knownRenames !== undefined) out.knownRenames = v.knownRenames;
  if (v.collectorHostnames !== undefined) out.collectorHostnames = v.collectorHostnames;
  if (v.hostFallback !== undefined) out.hostFallback = v.hostFallback;
  if (v.hostFallbackBasis !== undefined) out.hostFallbackBasis = v.hostFallbackBasis;
  return out;
}

// One Velociraptor artifact pulled from the server (hunt collect, external hunt or flow import). A
// Hayabusa result goes to the importer the drop folder would pick; everything else is unchanged. The
// explicit Velociraptor import route does NOT come through here: the analyst chose that importer.
export async function importVelociraptorArtifact(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: Parameters<typeof importVelociraptor>[3],
): Promise<InvestigationState> {
  if (!looksLikeHayabusaNamedExport(opts.label, text)) return importVelociraptor(ctx, caseId, text, opts);
  // The Hayabusa importer holds the file whole. Above the cap the drop folder would refuse to read,
  // keep the batched Velociraptor path so a fleet-sized result cannot exhaust the server.
  if (Buffer.byteLength(text, "utf8") > maxImportFileBytes()) {
    opts.debug?.fallback("hayabusa_over_import_file_cap");
    return importVelociraptor(ctx, caseId, text, opts);
  }
  opts.debug?.detected("hayabusa", { confident: true, decision: "velociraptor_hayabusa_artifact" });
  return importHayabusa(ctx, caseId, text, {
    label: opts.label,
    idPrefix: opts.idPrefix,
    importedAt: opts.importedAt,
    hayabusa: hayabusaOptionsFrom(opts.velociraptor),
    minSeverity: opts.minSeverity,
    veloUrl: opts.veloUrl,
    partlyReadArtifact: opts.velociraptor?.partlyReadArtifact,
    onProgress: opts.onProgress,
    debug: opts.debug,
  });
}
