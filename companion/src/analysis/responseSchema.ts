import { z } from "zod";

// Enums use .catch(fallback) so ONE unexpected value (e.g. an IOC type of "malware")
// maps to the fallback instead of rejecting the ENTIRE synthesis response.
const severity = z.enum(["Critical", "High", "Medium", "Low", "Info"]);
const iocType = z.enum(["ip", "domain", "hash", "file", "process", "url", "other"]);

export const deltaSchema = z.object({
  findings: z.array(z.object({
    id: z.string().min(1),
    severity: severity.catch("Medium"),
    title: z.string().min(1),
    description: z.string(),
    relatedIocs: z.array(z.string()),
    mitreTechniques: z.array(z.string()),
    status: z.enum(["open", "confirmed", "dismissed"]).catch("open"),
    // Synthesis only: the forensic-event ids this finding is based on. Used to
    // back-link events to the correct findings (extraction can't know finding ids).
    relatedEventIds: z.array(z.string()).optional(),
  })),
  iocs: z.array(z.object({
    id: z.string().min(1),
    type: iocType.catch("other"),
    value: z.string().min(1),
  })),
  mitreTechniques: z.array(z.object({
    id: z.string().min(1),
    name: z.string(),
  })),
  threadsOpened: z.array(z.object({ id: z.string().min(1), description: z.string() })),
  threadsClosed: z.array(z.string()), // thread ids
  timelineNote: z.string(),
  summary: z.string(),
  // Real incident events with their actual timestamps, extracted from the evidence.
  forensicEvents: z.array(z.object({
    id: z.string().min(1),
    timestamp: z.string(),                                    // event's real time as shown in the artifact
    description: z.string().min(1),
    severity: severity.default("Info").catch("Info"),
    mitreTechniques: z.array(z.string()).default([]),
    relatedFindingIds: z.array(z.string()).default([]),
  })).optional(),
  // Narrative reconstruction of the attacker's path (kill-chain story).
  attackerPath: z.string().optional(),
  // Standard DFIR questions with current answers + where to find them.
  keyQuestions: z.array(z.object({
    id: z.string().min(1),
    question: z.string().min(1),
    status: z.enum(["answered", "partial", "unknown"]).default("unknown").catch("unknown"),
    answer: z.string().default(""),
    pointer: z.string().default(""),
  })).optional(),
  // Prioritized recommendations for the most valuable next investigative actions.
  nextSteps: z.array(z.object({
    id: z.string().min(1),
    priority: z.enum(["critical", "high", "medium", "low"]).default("medium").catch("medium"),
    action: z.string().min(1),
    rationale: z.string().default(""),
    pointer: z.string().default(""),
  })).optional(),
});

export type AnalysisDelta = z.infer<typeof deltaSchema>;
