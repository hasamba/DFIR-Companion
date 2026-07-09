import type { AnalysisDelta } from "./responseSchema.js";
import type { InvestigationState, Finding, IOC, Technique, ForensicEvent } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import { isAnalystWorkLog } from "./workLogFilter.js";
import { correlateEvents } from "./correlate.js";
import { clampOutlierYears } from "./timeYearClamp.js";
import { linkEmailDelivery } from "./initialAccess.js";
import { linkArchiveToExfil } from "./exfilCorrelate.js";
import { toUtcIso } from "./timeUtc.js";
import { matchIocToExclude } from "./iocExclude.js";

export interface WindowContext {
  windowSequence: number;
  timestamp: string;
  sourceScreenshots: string[];
}

function uniq(values: string[]): string[] {
  return Array.from(new Set(values));
}

function padIocId(n: number): string {
  return `i${String(n).padStart(3, "0")}`;
}

// Highest existing IOC sequence in the canonical i### form; ids in other formats
// (legacy "i1", model-supplied junk) are ignored so we never collide with them.
function nextIocSeq(iocs: IOC[]): number {
  let max = 0;
  for (const i of iocs) {
    const m = /^i(\d+)$/.exec(i.id);
    if (m) max = Math.max(max, parseInt(m[1], 10));
  }
  return max + 1;
}

export function mergeDelta(
  state: InvestigationState,
  delta: AnalysisDelta,
  ctx: WindowContext,
): InvestigationState {
  // IOCs first — we need the id remap before processing findings so their
  // relatedIocs cross-references (e.g. the model's "i1") can be rewritten to
  // our canonical ids ("i001", "i002", ...).
  const iocs: IOC[] = state.iocs.map((i) => ({ ...i }));
  const iocIdRemap = new Map<string, string>();
  let nextSeq = nextIocSeq(iocs);
  for (const incoming of delta.iocs) {
    // Permanently excluded (per-case IOC Exclude List — e.g. ".lan"-style client hostname noise):
    // never create it, so it can never be enriched either (enrichIocs only ever sees state.iocs).
    // The id is deliberately never added to iocIdRemap; a finding's relatedIocs reference falls
    // back to the raw id via remapIocRefs's `?? id`, a harmless dangling reference.
    if (matchIocToExclude({ type: incoming.type, value: incoming.value }, state.iocExcludeRules)) continue;
    // Case-insensitive: the same indicator (a hostname/domain especially) routinely arrives with
    // different casing across importers/rows (e.g. "DESKTOP-X" vs "desktop-x"), and an exact-match
    // comparison let those through as separate rows instead of collapsing into one (matches
    // applyDeobfuscation.ts's dedup, which was already case-insensitive).
    const incomingLower = incoming.value.toLowerCase();
    const dup = iocs.find((i) => i.value.toLowerCase() === incomingLower);
    const canonical = dup ? dup.id : padIocId(nextSeq++);
    if (!dup) {
      iocs.push({ id: canonical, type: incoming.type, value: incoming.value, firstSeen: ctx.timestamp });
    }
    // First occurrence wins: when the model reuses an id (e.g. "i2") across
    // multiple distinct IOCs, a finding's `relatedIocs: ["i2"]` should refer to
    // the first one it emitted, not whichever happened to be last.
    if (!iocIdRemap.has(incoming.id)) iocIdRemap.set(incoming.id, canonical);
  }
  const remapIocRefs = (ids: string[]): string[] =>
    uniq(ids.map((id) => iocIdRemap.get(id) ?? id));

  const findings: Finding[] = state.findings.map((f) => ({ ...f }));

  for (const incoming of delta.findings) {
    const existing = findings.find((f) => f.id === incoming.id);
    if (existing) {
      existing.severity = incoming.severity;
      if (incoming.confidence !== undefined) existing.confidence = Math.round(incoming.confidence);
      if (incoming.confidenceReason !== undefined) existing.confidenceReason = incoming.confidenceReason;
      existing.title = incoming.title;
      existing.description = incoming.description;
      existing.status = incoming.status;
      existing.relatedIocs = uniq([...existing.relatedIocs, ...remapIocRefs(incoming.relatedIocs)]);
      existing.mitreTechniques = uniq([...existing.mitreTechniques, ...incoming.mitreTechniques]);
      if (incoming.relatedEventIds !== undefined) {
        existing.relatedEventIds = uniq([...(existing.relatedEventIds ?? []), ...incoming.relatedEventIds]);
      }
      existing.sourceScreenshots = uniq([...existing.sourceScreenshots, ...ctx.sourceScreenshots]);
      existing.lastUpdated = ctx.timestamp;
    } else {
      findings.push({
        id: incoming.id,
        severity: incoming.severity,
        ...(incoming.confidence !== undefined ? { confidence: Math.round(incoming.confidence) } : {}),
        ...(incoming.confidenceReason !== undefined ? { confidenceReason: incoming.confidenceReason } : {}),
        title: incoming.title,
        description: incoming.description,
        relatedIocs: remapIocRefs(incoming.relatedIocs),
        mitreTechniques: uniq(incoming.mitreTechniques),
        ...(incoming.relatedEventIds !== undefined ? { relatedEventIds: uniq(incoming.relatedEventIds) } : {}),
        sourceScreenshots: uniq(ctx.sourceScreenshots),
        firstSeen: ctx.timestamp,
        lastUpdated: ctx.timestamp,
        status: incoming.status,
      });
    }
  }

  const mitreTechniques: Technique[] = state.mitreTechniques.map((t) => ({ ...t, findingIds: [...t.findingIds] }));
  for (const incoming of delta.mitreTechniques) {
    const existing = mitreTechniques.find((t) => t.id === incoming.id);
    const findingIds = delta.findings.filter((f) => f.mitreTechniques.includes(incoming.id)).map((f) => f.id);
    if (existing) {
      existing.findingIds = uniq([...existing.findingIds, ...findingIds]);
    } else {
      mitreTechniques.push({ id: incoming.id, name: incoming.name, findingIds: uniq(findingIds) });
    }
  }

  const openThreads = state.openThreads.map((t) => ({ ...t }));
  for (const t of delta.threadsOpened) {
    if (!openThreads.some((x) => x.id === t.id)) {
      openThreads.push({ id: t.id, description: t.description, status: "open", openedAt: ctx.timestamp, closedAt: null });
    }
  }
  for (const closedId of delta.threadsClosed) {
    const t = openThreads.find((x) => x.id === closedId);
    if (t && t.status === "open") {
      t.status = "closed";
      t.closedAt = ctx.timestamp;
    }
  }

  const timeline = [...state.timeline];
  if (delta.timelineNote.trim().length > 0) {
    timeline.push({
      timestamp: ctx.timestamp,
      windowSequence: ctx.windowSequence,
      description: delta.timelineNote,
      sourceScreenshots: uniq(ctx.sourceScreenshots),
    });
  }

  // Forensic timeline: dedupe by id, accumulate evidence, keep sorted by real time.
  const forensicTimeline: ForensicEvent[] = state.forensicTimeline.map((e) => ({
    ...e,
    mitreTechniques: [...e.mitreTechniques],
    relatedFindingIds: [...e.relatedFindingIds],
    sourceScreenshots: [...e.sourceScreenshots],
  }));
  for (const incoming of delta.forensicEvents ?? []) {
    // Hard guard: a weak model may narrate the analyst operating the tool
    // ("Velociraptor Response and Monitoring session continued") as an event.
    // Never let tool-usage narration into the forensic timeline.
    if (isAnalystWorkLog(incoming.description)) continue;
    // Normalize the artifact's own time to UTC (converts an explicit offset like +02:00 to "…Z";
    // leaves already-UTC / naive times untouched) so the whole timeline is one timezone.
    const ts = toUtcIso(incoming.timestamp);
    const endTs = incoming.endTimestamp !== undefined ? toUtcIso(incoming.endTimestamp) : undefined;
    const existing = forensicTimeline.find((e) => e.id === incoming.id);
    if (existing) {
      existing.timestamp = ts || existing.timestamp;
      existing.description = incoming.description;
      existing.severity = incoming.severity;
      existing.mitreTechniques = uniq([...existing.mitreTechniques, ...incoming.mitreTechniques]);
      existing.relatedFindingIds = uniq([...existing.relatedFindingIds, ...incoming.relatedFindingIds]);
      existing.sourceScreenshots = uniq([...existing.sourceScreenshots, ...ctx.sourceScreenshots]);
      if (incoming.count !== undefined) existing.count = incoming.count;
      if (endTs !== undefined) existing.endTimestamp = endTs;
      if (incoming.sha256) existing.sha256 = incoming.sha256;
      if (incoming.md5) existing.md5 = incoming.md5;
      if (incoming.path) existing.path = incoming.path;
      if (incoming.asset) existing.asset = incoming.asset;
      if (incoming.sources?.length) existing.sources = uniq([...(existing.sources ?? []), ...incoming.sources]);
      if (incoming.artifactName) existing.artifactName = incoming.artifactName;
      if (incoming.message) existing.message = incoming.message;
      if (incoming.veloUrl) existing.veloUrl = incoming.veloUrl;
      if (incoming.processName) existing.processName = incoming.processName;
      if (incoming.parentName) existing.parentName = incoming.parentName;
      if (incoming.pid !== undefined) existing.pid = incoming.pid;
      if (incoming.action) existing.action = incoming.action;
      if (incoming.srcIp) existing.srcIp = incoming.srcIp;
      if (incoming.dstIp) existing.dstIp = incoming.dstIp;
      if (incoming.port !== undefined) existing.port = incoming.port;
    } else {
      forensicTimeline.push({
        id: incoming.id,
        timestamp: ts,
        description: incoming.description,
        severity: incoming.severity,
        mitreTechniques: uniq(incoming.mitreTechniques),
        relatedFindingIds: uniq(incoming.relatedFindingIds),
        sourceScreenshots: uniq(ctx.sourceScreenshots),
        ...(incoming.count !== undefined ? { count: incoming.count } : {}),
        ...(endTs !== undefined ? { endTimestamp: endTs } : {}),
        ...(incoming.sha256 ? { sha256: incoming.sha256 } : {}),
        ...(incoming.md5 ? { md5: incoming.md5 } : {}),
        ...(incoming.path ? { path: incoming.path } : {}),
        ...(incoming.asset ? { asset: incoming.asset } : {}),
        ...(incoming.sources?.length ? { sources: uniq(incoming.sources) } : {}),
        ...(incoming.artifactName ? { artifactName: incoming.artifactName } : {}),
        ...(incoming.message ? { message: incoming.message } : {}),
        ...(incoming.veloUrl ? { veloUrl: incoming.veloUrl } : {}),
        ...(incoming.processName ? { processName: incoming.processName } : {}),
        ...(incoming.parentName ? { parentName: incoming.parentName } : {}),
        ...(incoming.pid !== undefined ? { pid: incoming.pid } : {}),
        ...(incoming.action ? { action: incoming.action } : {}),
        ...(incoming.srcIp ? { srcIp: incoming.srcIp } : {}),
        ...(incoming.dstIp ? { dstIp: incoming.dstIp } : {}),
        ...(incoming.port !== undefined ? { port: incoming.port } : {}),
      });
    }
  }
  // Re-anchor mis-dated stray events (a year-less syslog/CSV line the AI import guessed into the wrong
  // year) onto the timeline's dominant year BEFORE correlation, so they sort/correlate in the right
  // place instead of corrupting the chronology. Conservative + idempotent (no-op unless one year clearly
  // dominates). See timeYearClamp.ts.
  const dated = clampOutlierYears(forensicTimeline);
  // Stitch a phishing email to the host activity it caused: when a host later contacts a domain a
  // phishing email linked to, tag the contact as initial access (T1566.002 → T1204.002). Runs
  // before correlation so the tagged event still dedups normally. Conservative + idempotent (#201).
  const withInitialAccess = linkEmailDelivery(dated);
  // Stitch archive STAGING (T1560.001) to a subsequent UPLOAD (T1041) on the same host: the
  // SEQUENCE is the exfil signal (a lone upload to routine SaaS/cloud infra is not), so a matched
  // upload is raised to High and tagged — a deterministic, destination-agnostic "Data Exfiltration"
  // signal instead of relying on the synthesis model to notice the pairing. Conservative + idempotent.
  const withExfil = linkArchiveToExfil(withInitialAccess);
  // Collapse duplicates / cross-source matches immediately (so re-importing the same
  // report, or two tools flagging one artifact, never doubles the timeline) — not only
  // during synthesis. Idempotent.
  const correlated = correlateEvents(withExfil).sort(byEventTime);

  // Key questions are a holistic reassessment — replace wholesale when synthesis
  // provides them; otherwise keep the existing set (per-window deltas omit them).
  const keyQuestions = delta.keyQuestions !== undefined
    ? delta.keyQuestions.map((q) => ({
        id: q.id, question: q.question, status: q.status, answer: q.answer, pointer: q.pointer,
        ...(q.relatedFindingIds?.length ? { relatedFindingIds: q.relatedFindingIds } : {}),
      }))
    : state.keyQuestions;

  // Next steps are likewise a holistic recommendation — replaced wholesale by
  // synthesis, preserved when a per-window delta omits them.
  const nextSteps = delta.nextSteps !== undefined
    ? delta.nextSteps.map((s) => ({ id: s.id, priority: s.priority, action: s.action, rationale: s.rationale, pointer: s.pointer }))
    : state.nextSteps;

  return {
    caseId: state.caseId,
    findings,
    iocs,
    openThreads,
    timeline,
    forensicTimeline: correlated,
    mitreTechniques,
    keyQuestions,
    nextSteps,
    lastSummary: delta.summary.trim().length > 0 ? delta.summary : state.lastSummary,
    attackerPath: (delta.attackerPath ?? "").trim().length > 0 ? (delta.attackerPath as string) : state.attackerPath,
    narrativeTimeline: (delta.narrativeTimeline ?? "").trim().length > 0 ? (delta.narrativeTimeline as string) : state.narrativeTimeline,
    iocExcludeRules: state.iocExcludeRules,
    updatedAt: ctx.timestamp,
  };
}
