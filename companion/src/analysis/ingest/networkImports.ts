import { parseNetworkLogs, type NetworkImportOptions } from "../networkImport.js";
import { deltaSchema } from "../responseSchema.js";
import { parseSecurityOnion, type SecurityOnionImportOptions } from "../securityOnionImport.js";
import { applySeverityFloor } from "../severityFloor.js";
import { resolveExtractedFrom } from "../siemImport.js";
import { SNORT_SOURCE, parseSnortLog, type SnortImportOptions } from "../snortImport.js";

import { type InvestigationState, type Severity } from "../stateTypes.js";
import { pickImportYear } from "../timeYearClamp.js";
import { noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";

/**
 * Network sensors and captures.
 *
 * Moved from AnalysisPipeline (#384). Each of these was a method; each is now a free function
 * taking an ImportContext, which is the small set of collaborators an importer is allowed to use.
 * The pipeline keeps a one-line delegation per importer, so callers are unchanged.
 */

// Import a Snort / Suricata "fast" alert log — a real IDS verdict feed. Deterministic (no AI):
// severity is the rule's Priority verdict, public src/dst IPs become IOCs, year-less timestamps are
// re-anchored by the mergeDelta year-clamp. See snortImport.ts.
export async function importSnort(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    snort?: SnortImportOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  // Year-less BSD-style timestamps default to the CURRENT calendar year unless the case already has
  // an established dominant year to anchor onto — see pickImportYear (a big year-less import can
  // outweigh clampOutlierYears' post-hoc ≥90% minority-outlier guard).
  const priorState = await ctx.opts.stateStore.load(caseId).catch(() => null);
  const assumeYear = opts.snort?.assumeYear ?? pickImportYear(priorState?.forensicTimeline ?? []);
  const parsedRaw = parseSnortLog(text, {
    ...opts.snort,
    ...(assumeYear !== undefined ? { assumeYear } : {}),
  });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return noteEmptyImport(ctx, caseId, opts, "Snort", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [SNORT_SOURCE],
      // A Snort fast-alert line carries no year, so `assumeYear` above supplied one — mark it a
      // guess so the merge's year-clamp may re-anchor it (#739).
      yearInferred: true,
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Snort import (${parsed.format}): ${parsed.kept} alert(s) from ${parsed.total} line(s)` +
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

// Import network-monitor logs — Suricata `eve.json` and Zeek JSON (Security Onion's
// network side). Deterministic (no AI call): the timeline is built from the detections
// (Suricata alerts + Zeek notices); surrounding telemetry (dns/http/tls/files/conn)
// contributes IOCs only. Events are tagged Suricata / Zeek.
export async function importNetwork(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "n3") so ids never collide
    importedAt: string;
    network?: NetworkImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  // Pass the import filename so per-stream Zeek JSON (conn.json / dns.json / … with no `_path`)
  // routes to the right stream (#197).
  const parsedRaw = parseNetworkLogs(text, {
    ...opts.network,
    filename: opts.network?.filename ?? opts.label,
  });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "Network", parsed.total);

  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return { ...rest, id, sources: rest.sources?.length ? rest.sources : ["Suricata"] };
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
      `Network import (${parsed.format}): ${parsed.kept} detection event(s) from ${parsed.total} record(s)` +
      (parsed.alerts > 0 ? `, ${parsed.alerts} alert/notice(s)` : "") +
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

// Import Security Onion Console (SOC) events — the Alerts / Hunt views the browser extension
// pushes. Deterministic (no AI call), verdict-first per the post-detection principle: the
// event's own `event.severity_label` drives severity, `rule.name` leads the description, ECS
// threat fields become MITRE, and source/destination IPs + app-layer fields become IOCs.
// Events are tagged "Security Onion".
export async function importSecurityOnion(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "so3") so ids never collide
    importedAt: string;
    securityOnion?: SecurityOnionImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseSecurityOnion(text, opts.securityOnion);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "Security Onion", parsed.total);

  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return { ...rest, id, sources: rest.sources?.length ? rest.sources : ["Security Onion"] };
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
      `Security Onion import: ${parsed.kept} event(s) from ${parsed.total} record(s)` +
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
