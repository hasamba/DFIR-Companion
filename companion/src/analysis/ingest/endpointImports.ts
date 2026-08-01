import { parseChainsawReport, type ChainsawImportOptions } from "../chainsawImport.js";
import { parseCybertriage, type CybertriageImportOptions } from "../cybertriageImport.js";
import { ECAR_SOURCE, parseEcarJson, type EcarImportOptions } from "../ecarImport.js";
import { parseHayabusaTimeline, type HayabusaImportOptions } from "../hayabusaImport.js";
import { parseKapeCsv, type KapeImportOptions } from "../kapeImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { resolveExtractedFrom } from "../siemImport.js";
import { type InvestigationState, type Severity } from "../stateTypes.js";
import { parseThorReport, type ThorImportOptions } from "../thorImport.js";
import { parseVelociraptorJsonProgress, type VelociraptorImportOptions } from "../velociraptorImport.js";
import type { ImportContext } from "./importContext.js";

/**
 * Endpoint and host-triage collections: agent output, triage bundles and EDR exports.
 *
 * Moved from AnalysisPipeline (#384). Each of these was a method; each is now a free function
 * taking an ImportContext, which is the small set of collaborators an importer is allowed to use.
 * The pipeline keeps a one-line delegation per importer, so callers are unchanged.
 */

// Import a THOR (Nextron) scanner report in JSON-Lines format. Unlike the CSV/log
// paths this is DETERMINISTIC — THOR's JSON is structured and stable, so each
// finding maps straight to a forensic event + IOCs with NO AI extraction call.
// Scan-lifecycle/info noise (module init, "Info" level) is dropped by default.
// Findings/attacker-path still come from a later synthesize().
export async function importThor(
  ctx: ImportContext,
  caseId: string,
  jsonText: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "t3") so ids never collide
    importedAt: string;
    thor?: ThorImportOptions; // filtering overrides (dropInfo, dropLifecycleModules…)
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseThorReport(jsonText, opts.thor);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return ctx.noteEmptyImport(caseId, opts, "THOR", parsed.total);

  // Assign stable, collision-free ids and validate the delta against the schema
  // (fills defaults like relatedFindingIds). No model call — purely structural.
  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({ ...e, id: `${opts.idPrefix}e${i + 1}` })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `THOR import: ${parsed.kept} finding(s) kept, ${parsed.dropped} info/lifecycle row(s) dropped` +
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

// Import Chainsaw (WithSecure) hunt output or a raw EVTX-as-JSON dump. Like THOR/SIEM
// the mapping is DETERMINISTIC (no AI call): the embedded EVTX events get the same
// per-EID Windows mapping as the SIEM import, and — for Chainsaw — the matched Sigma
// rule's level drives severity while its `attack.tXXXX` tags become MITRE techniques.
// Each event is tagged Chainsaw / EVTX as its source for cross-source correlation.
export async function importChainsaw(
  ctx: ImportContext,
  caseId: string,
  jsonText: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "c3") so ids never collide
    importedAt: string;
    chainsaw?: ChainsawImportOptions; // filtering overrides (aggregate, minSeverity, maxEvents…)
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseChainsawReport(jsonText, opts.chainsaw);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return ctx.noteEmptyImport(caseId, opts, "Chainsaw", parsed.total);

  const fallback = parsed.detections > 0 ? "Chainsaw" : "EVTX";
  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [fallback],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `${parsed.detections > 0 ? "Chainsaw" : "EVTX"} import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.detections > 0 ? `, ${parsed.detections} rule detection(s)` : "") +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
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
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseHayabusaTimeline(text, opts.hayabusa);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return ctx.noteEmptyImport(caseId, opts, "Hayabusa", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Hayabusa"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Hayabusa import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
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

// Import Velociraptor native JSON output (collection results / hunt export). Like the
// other deterministic paths there is no AI call: each row is classified (Sigma / YARA /
// EventLog / generic) and mapped — detection rows are verdict-driven, the rest auto-detect
// the artifact's own time + IOCs. Every event is tagged Velociraptor as its source.
export async function importVelociraptor(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "v3") so ids never collide
    importedAt: string;
    velociraptor?: VelociraptorImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    veloUrl?: string; // the originating hunt/flow's GUI URL (only known for a live hunt/flow import) — stamped onto every event so the forensic timeline's "↗ Velociraptor" link resolves, mirroring the super-only path
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  // Rows often carry no _Source; use the (Velociraptor-named) filename as the fallback artifact
  // label so generic/detection events show their source — e.g. "DetectRaptor.Windows.Detection.NamedPipes".
  const rawArtifact = opts.label.replace(/^\d+_/, "").replace(/\.(json|jsonl|ndjson|csv)$/i, "");
  let artifact = rawArtifact;
  try {
    artifact = decodeURIComponent(rawArtifact);
  } catch {
    /* malformed %xx — keep the raw label */
  }
  // Chunked async parse: reports (rowsDone, rowsTotal) as it goes (→ the import job's progress bar
  // and the "importing X/Y" status) and yields to the event loop between chunks, so a huge MFT/USN
  // import streams live progress instead of freezing the server on one synchronous pass.
  const parsedRaw = await parseVelociraptorJsonProgress(
    text,
    { artifact, ...opts.velociraptor },
    opts.onProgress,
  );
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return ctx.noteEmptyImport(caseId, opts, "Velociraptor", parsed.total);

  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return {
      ...rest,
      id,
      sources: rest.sources?.length ? rest.sources : ["Velociraptor"],
      ...(opts.veloUrl ? { veloUrl: opts.veloUrl } : {}),
    };
  });

  const raw = {
    findings: [],
    iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
      id: `${opts.idPrefix}i${i + 1}`,
      type: c.type,
      value: c.value,
      ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
    })),
    mitreTechniques: [],
    forensicEvents,
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Velociraptor import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
      (parsed.detections > 0 ? `, ${parsed.detections} detection(s)` : "") +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
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
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return ctx.noteEmptyImport(caseId, opts, "ECAR", parsed.total);

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
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
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

// Import a KAPE / Eric Zimmerman Tools CSV (Prefetch, Amcache, ShimCache, LNK, JumpLists,
// UsnJrnl, MFT, SRUM, Recycle Bin, Shellbags). Deterministic (no AI call): the EZ tool is
// detected from the CSV header, then each row maps to a forensic event reading the
// artifact's own time + file/hash/process IOCs. Events are tagged by artifact name.
export async function importKape(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "k3") so ids never collide
    importedAt: string;
    kape?: KapeImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseKapeCsv(text, opts.kape);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0)
    return ctx.noteEmptyImport(caseId, opts, `KAPE/${parsed.artifact}`, parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [parsed.artifact],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `KAPE/${parsed.artifact} import: ${parsed.kept} event(s) from ${parsed.total} row(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : ""),
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

// Import a Cyber Triage timeline export (JSONL / JSON array / CSV). Deterministic (no AI call):
// scored rows map verdict-first (severity from the Bad/Suspicious verdict + reason keywords),
// unscored process/task rows become Info evidence, the bulk File super-timeline is dropped
// (unless `fileTelemetry`), and Active-Connection remote IPs become IOCs. Events tagged
// "Cyber Triage".
export async function importCybertriage(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "ct3") so ids never collide
    importedAt: string;
    cybertriage?: CybertriageImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseCybertriage(text, opts.cybertriage);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return ctx.noteEmptyImport(caseId, opts, "Cyber Triage", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Cyber Triage"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Cyber Triage import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
      (parsed.notable > 0 ? `, ${parsed.notable} scored item(s)` : "") +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)` +
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
