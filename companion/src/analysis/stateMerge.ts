import type { AnalysisDelta } from "./responseSchema.js";
import type { InvestigationState, Finding, IOC, Technique, ForensicEvent } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import { isAnalystWorkLog } from "./workLogFilter.js";
import { correlateEvents } from "./correlate.js";
import { toUtcIso } from "./timeUtc.js";

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
    const dup = iocs.find((i) => i.value === incoming.value);
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
      existing.title = incoming.title;
      existing.description = incoming.description;
      existing.status = incoming.status;
      existing.relatedIocs = uniq([...existing.relatedIocs, ...remapIocRefs(incoming.relatedIocs)]);
      existing.mitreTechniques = uniq([...existing.mitreTechniques, ...incoming.mitreTechniques]);
      existing.sourceScreenshots = uniq([...existing.sourceScreenshots, ...ctx.sourceScreenshots]);
      existing.lastUpdated = ctx.timestamp;
    } else {
      findings.push({
        id: incoming.id,
        severity: incoming.severity,
        title: incoming.title,
        description: incoming.description,
        relatedIocs: remapIocRefs(incoming.relatedIocs),
        mitreTechniques: uniq(incoming.mitreTechniques),
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
      if (incoming.processName) existing.processName = incoming.processName;
      if (incoming.parentName) existing.parentName = incoming.parentName;
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
        ...(incoming.processName ? { processName: incoming.processName } : {}),
        ...(incoming.parentName ? { parentName: incoming.parentName } : {}),
      });
    }
  }
  // Collapse duplicates / cross-source matches immediately (so re-importing the same
  // report, or two tools flagging one artifact, never doubles the timeline) — not only
  // during synthesis. Idempotent.
  const correlated = correlateEvents(forensicTimeline).sort(byEventTime);

  // Key questions are a holistic reassessment — replace wholesale when synthesis
  // provides them; otherwise keep the existing set (per-window deltas omit them).
  const keyQuestions = delta.keyQuestions !== undefined
    ? delta.keyQuestions.map((q) => ({ id: q.id, question: q.question, status: q.status, answer: q.answer, pointer: q.pointer }))
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
    updatedAt: ctx.timestamp,
  };
}
