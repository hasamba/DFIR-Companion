import { parseAuditdLog, type AuditdImportOptions } from "../auditdImport.js";
import { parseShellHistoryFile, userFromHistoryFilename } from "../bashHistoryImport.js";
import { CISCO_ASA_SOURCE, parseCiscoAsaLog, type CiscoAsaImportOptions } from "../ciscoAsaImport.js";
import {
  COMBINED_LOG_SOURCE,
  parseCombinedLog,
  type CombinedLogImportOptions,
} from "../combinedLogImport.js";
import { parseJournald, type JournaldImportOptions } from "../journaldImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { resolveExtractedFrom } from "../siemImport.js";

import { type InvestigationState, type Severity } from "../stateTypes.js";
import { parseSysdig, type SysdigImportOptions } from "../sysdigImport.js";
import { SYSLOG_SOURCE, parseSyslogProgress, type SyslogImportOptions } from "../syslogImport.js";
import { pickImportYear } from "../timeYearClamp.js";
import { noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";

/**
 * Line-oriented host and appliance logs, where each record is one line of text.
 *
 * Moved from AnalysisPipeline (#384). Each of these was a method; each is now a free function
 * taking an ImportContext, which is the small set of collaborators an importer is allowed to use.
 * The pipeline keeps a one-line delegation per importer, so callers are unchanged.
 */

// Import a Linux/Unix shell history file (.bash_history / .zsh_history / …). Deterministic
// host-triage: one forensic event per command at the artifact's own time (bash HISTTIMEFORMAT
// `#<epoch>` / zsh extended history), Info by default with a conservative tradecraft bump. The
// account is derived from the filename and shown in each event.
export async function importBashHistory(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "b3") so ids never collide
    importedAt: string;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const user = userFromHistoryFilename(opts.label);
  const parsedRaw = parseShellHistoryFile(text, { user });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return noteEmptyImport(ctx, caseId, opts, "Shell history", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Shell history"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Shell history import${user ? ` (${user})` : ""}: ${parsed.kept} command(s) from ${parsed.total} line(s)` +
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

// Import an Apache/Nginx/Squid combined access log (web server or forward-proxy). Deterministic
// (no AI): raw web/proxy telemetry, Info by default with a conservative bump only for an
// access-denied response; git smart-HTTP clone/push tagged T1213. See combinedLogImport.ts.
export async function importCombinedLog(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    combinedLog?: CombinedLogImportOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseCombinedLog(text, { ...opts.combinedLog });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "Web/proxy access-log", parsed.total);

  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return { ...rest, id, sources: rest.sources?.length ? rest.sources : [COMBINED_LOG_SOURCE] };
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
      `Web/proxy access-log import (${parsed.format}): ${parsed.kept} request(s) from ${parsed.total} line(s)` +
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

// Import a Cisco ASA firewall syslog export. Deterministic (no AI): Built/Teardown telemetry
// stays Info, an explicit Deny bumps to Low, dynamic-NAT-translation noise is dropped,
// year-less timestamps are re-anchored by the mergeDelta year-clamp. See ciscoAsaImport.ts.
export async function importCiscoAsa(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    ciscoAsa?: CiscoAsaImportOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  // Year-less BSD-style timestamps default to the CURRENT calendar year unless the case already has
  // an established dominant year to anchor onto — see pickImportYear (a big year-less import can
  // outweigh clampOutlierYears' post-hoc ≥90% minority-outlier guard).
  const priorState = await ctx.opts.stateStore.load(caseId).catch(() => null);
  const assumeYear = opts.ciscoAsa?.assumeYear ?? pickImportYear(priorState?.forensicTimeline ?? []);
  const parsedRaw = parseCiscoAsaLog(text, {
    ...opts.ciscoAsa,
    ...(assumeYear !== undefined ? { assumeYear } : {}),
  });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return noteEmptyImport(ctx, caseId, opts, "Cisco ASA", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [CISCO_ASA_SOURCE],
      // An ASA line carries no year, so `assumeYear` above supplied one. Mark it a guess: this is
      // what makes the event eligible for the merge's year-clamp, and what keeps the clamp off
      // every importer that DID read a year out of the record (#739).
      yearInferred: true,
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Cisco ASA import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} line(s)` +
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

// Import a plain Linux/Unix syslog export (RFC 5424 / RFC 3164). Deterministic (no AI): host
// telemetry stays Info, an auth-failure or crit/alert/emerg PRI bumps to Low, the host is carried
// as the event's asset, RFC-3164 year-less timestamps are re-anchored by the mergeDelta year-clamp.
// See syslogImport.ts.
export async function importSyslog(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    syslog?: SyslogImportOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
    onParseProgress?: (done: number, total: number, detail?: string) => void | Promise<void>;
    signal?: AbortSignal;
  },
): Promise<InvestigationState> {
  // Year-less BSD-style timestamps default to the CURRENT calendar year unless the case already has
  // an established dominant year to anchor onto — see pickImportYear (a big year-less import can
  // outweigh clampOutlierYears' post-hoc ≥90% minority-outlier guard).
  const priorState = await ctx.opts.stateStore.load(caseId).catch(() => null);
  const assumeYear = opts.syslog?.assumeYear ?? pickImportYear(priorState?.forensicTimeline ?? []);
  const parsedRaw = await parseSyslogProgress(
    text,
    { ...opts.syslog, ...(assumeYear !== undefined ? { assumeYear } : {}) },
    (done, total) => opts.onParseProgress?.(done, total, "reading syslog lines"),
    opts.signal,
  );
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return noteEmptyImport(ctx, caseId, opts, "Syslog", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [SYSLOG_SOURCE],
      // Per PARSED LINE, carried up from syslogImport: RFC 3164 is year-less and its year came from
      // `assumeYear` above, while RFC 5424 carries a full RFC 3339 stamp and is recorded evidence.
      // One export mixes both framings, so marking the whole file would hand the merge's year-clamp
      // permission to rewrite real timestamps — the #739 defect, in a second place.
      ...(e.yearInferred ? { yearInferred: true } : {}),
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Syslog import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} line(s)` +
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

// Import a Linux auditd log (raw audit.log / `ausearch` record format, or an `aureport` table).
// Deterministic (no AI call): records sharing a serial collapse into one logical event, mapped
// to severity/MITRE by record type (logins, account/group mgmt, sudo, SELinux denials, audit-config
// tampering), bumped on a failed auth or a suspicious command. Read at the audit() epoch. Tagged auditd.
export async function importAuditd(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "ad3") so ids never collide
    importedAt: string;
    auditd?: AuditdImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseAuditdLog(text, opts.auditd);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "auditd", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["auditd"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `auditd import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
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

// Import a systemd-journald structured log (`journalctl -o json` / `-o json-pretty`). Deterministic
// (no AI call): each entry is read at its own time (_SOURCE/__REALTIME µs epoch), severity derived
// from PRIORITY then bumped from the message (sshd auth, sudo, useradd, kernel), with IOCs scraped
// from _EXE/_COMM and the MESSAGE. Tagged journald.
export async function importJournald(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "jd3") so ids never collide
    importedAt: string;
    journald?: JournaldImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseJournald(text, opts.journald);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "journald", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["journald"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `journald import: ${parsed.kept} event(s) from ${parsed.total} entr(y/ies)` +
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

// Import a sysdig / Falco export (Falco alert JSON and/or sysdig `-j` event JSON). Deterministic
// (no AI call): Falco rule hits are the DETECTIONS (verdict-first: priority → severity, tags →
// MITRE) and surface on the timeline; raw sysdig syscall events are telemetry → Info evidence;
// both contribute proc/file/network IOCs. Tagged Falco / sysdig.
export async function importSysdig(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "sd3") so ids never collide
    importedAt: string;
    sysdig?: SysdigImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseSysdig(text, opts.sysdig);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "sysdig/Falco", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["sysdig"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `sysdig/Falco import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.alerts > 0 ? `, ${parsed.alerts} Falco alert(s)` : "") +
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
