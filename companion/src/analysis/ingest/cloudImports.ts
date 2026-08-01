import { parseCloudTrail, type AwsImportOptions } from "../awsImport.js";
import { parseCloudActivity, type CloudActivityImportOptions } from "../cloudActivityImport.js";
import { parseK8sAudit, type K8sAuditImportOptions } from "../k8sAuditImport.js";
import { parseM365Audit, type M365ImportOptions } from "../m365Import.js";
import { parseOsqueryLog, type OsqueryImportOptions } from "../osqueryImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { type InvestigationState, type Severity } from "../stateTypes.js";
import type { ImportContext } from "./importContext.js";

/**
 * Cloud control-plane and fleet-query sources.
 *
 * Moved from AnalysisPipeline (#384). Each of these was a method; each is now a free function
 * taking an ImportContext, which is the small set of collaborators an importer is allowed to use.
 * The pipeline keeps a one-line delegation per importer, so callers are unchanged.
 */

// Import Microsoft 365 Unified Audit Log + Entra ID (sign-in / directory audit) data.
// Deterministic (no AI call): each record is classified (UAL / sign-in / audit) and mapped,
// severity derived from the operation (BEC tradecraft) or Entra's own risk verdict; the
// source IP becomes an IOC and the UPN is surfaced for the asset graph.
export async function importM365(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "m3") so ids never collide
    importedAt: string;
    m365?: M365ImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseM365Audit(text, opts.m365);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return ctx.noteEmptyImport(caseId, opts, "Microsoft 365", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Microsoft 365"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Microsoft 365 import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)`,
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

// Import AWS CloudTrail logs. Deterministic (no AI call): each API-call record is mapped,
// severity derived from the action (IAM persistence, logging/detection tampering, S3
// exposure, secrets access) + denied/root/console-failure bumps; the caller IP → IOC.
export async function importAws(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "a3") so ids never collide
    importedAt: string;
    aws?: AwsImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseCloudTrail(text, opts.aws);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return ctx.noteEmptyImport(caseId, opts, "AWS CloudTrail", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["AWS CloudTrail"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `AWS CloudTrail import: ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)`,
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

// Import GCP Cloud Audit Logs + Azure Activity Log. Deterministic (no AI call): each record
// is routed (GCP / Azure) and mapped, severity derived from the action (+ denied bump); the
// caller IP → IOC and the principal email is surfaced for the asset graph.
export async function importCloudActivity(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "g3") so ids never collide
    importedAt: string;
    cloud?: CloudActivityImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseCloudActivity(text, opts.cloud);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return ctx.noteEmptyImport(caseId, opts, "Cloud activity", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Cloud Audit"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Cloud activity import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)`,
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

// Import Kubernetes API-server audit logs (audit.k8s.io). Deterministic (no AI call): each audit
// Event → a forensic event whose severity is derived from the (verb, resource, subresource) tuple
// (pod exec/attach, secret access, RBAC change, privileged-pod create, anonymous access), Info by
// default. Source IP → IOC. Tagged Kubernetes Audit.
export async function importK8sAudit(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "k3") so ids never collide
    importedAt: string;
    k8s?: K8sAuditImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseK8sAudit(text, opts.k8s);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return ctx.noteEmptyImport(caseId, opts, "Kubernetes audit", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Kubernetes Audit"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Kubernetes audit import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)`,
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

// Import osquery scheduled-query result logs (differential `columns` rows + `snapshot` sets).
// Deterministic (no AI call): Info-by-default endpoint telemetry, with a conservative tradecraft
// bump on a command-line column; columns → IOCs (path/hash/ip/process). Tagged osquery.
export async function importOsquery(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "o3") so ids never collide
    importedAt: string;
    osquery?: OsqueryImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseOsqueryLog(text, opts.osquery);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return ctx.noteEmptyImport(caseId, opts, "osquery", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["osquery"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `osquery import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)`,
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
