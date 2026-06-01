import type { AnalysisDelta } from "./responseSchema.js";
import type { InvestigationState, Finding, IOC, Technique, ForensicEvent } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import { isAnalystWorkLog } from "./workLogFilter.js";

export interface WindowContext {
  windowSequence: number;
  timestamp: string;
  sourceScreenshots: string[];
}

function uniq(values: string[]): string[] {
  return Array.from(new Set(values));
}

export function mergeDelta(
  state: InvestigationState,
  delta: AnalysisDelta,
  ctx: WindowContext,
): InvestigationState {
  const findings: Finding[] = state.findings.map((f) => ({ ...f }));

  for (const incoming of delta.findings) {
    const existing = findings.find((f) => f.id === incoming.id);
    if (existing) {
      existing.severity = incoming.severity;
      existing.title = incoming.title;
      existing.description = incoming.description;
      existing.status = incoming.status;
      existing.relatedIocs = uniq([...existing.relatedIocs, ...incoming.relatedIocs]);
      existing.mitreTechniques = uniq([...existing.mitreTechniques, ...incoming.mitreTechniques]);
      existing.sourceScreenshots = uniq([...existing.sourceScreenshots, ...ctx.sourceScreenshots]);
      existing.lastUpdated = ctx.timestamp;
    } else {
      findings.push({
        id: incoming.id,
        severity: incoming.severity,
        title: incoming.title,
        description: incoming.description,
        relatedIocs: uniq(incoming.relatedIocs),
        mitreTechniques: uniq(incoming.mitreTechniques),
        sourceScreenshots: uniq(ctx.sourceScreenshots),
        firstSeen: ctx.timestamp,
        lastUpdated: ctx.timestamp,
        status: incoming.status,
      });
    }
  }

  const iocs: IOC[] = state.iocs.map((i) => ({ ...i }));
  for (const incoming of delta.iocs) {
    if (!iocs.some((i) => i.value === incoming.value)) {
      iocs.push({ id: incoming.id, type: incoming.type, value: incoming.value, firstSeen: ctx.timestamp });
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
    const existing = forensicTimeline.find((e) => e.id === incoming.id);
    if (existing) {
      existing.timestamp = incoming.timestamp || existing.timestamp;
      existing.description = incoming.description;
      existing.severity = incoming.severity;
      existing.mitreTechniques = uniq([...existing.mitreTechniques, ...incoming.mitreTechniques]);
      existing.relatedFindingIds = uniq([...existing.relatedFindingIds, ...incoming.relatedFindingIds]);
      existing.sourceScreenshots = uniq([...existing.sourceScreenshots, ...ctx.sourceScreenshots]);
    } else {
      forensicTimeline.push({
        id: incoming.id,
        timestamp: incoming.timestamp,
        description: incoming.description,
        severity: incoming.severity,
        mitreTechniques: uniq(incoming.mitreTechniques),
        relatedFindingIds: uniq(incoming.relatedFindingIds),
        sourceScreenshots: uniq(ctx.sourceScreenshots),
      });
    }
  }
  forensicTimeline.sort(byEventTime);

  return {
    caseId: state.caseId,
    findings,
    iocs,
    openThreads,
    timeline,
    forensicTimeline,
    mitreTechniques,
    lastSummary: delta.summary.trim().length > 0 ? delta.summary : state.lastSummary,
    attackerPath: (delta.attackerPath ?? "").trim().length > 0 ? (delta.attackerPath as string) : state.attackerPath,
    updatedAt: ctx.timestamp,
  };
}
