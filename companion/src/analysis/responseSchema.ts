import { z } from "zod";

export const deltaSchema = z.object({
  findings: z.array(z.object({
    id: z.string().min(1),
    severity: z.enum(["Critical", "High", "Medium", "Low", "Info"]),
    title: z.string().min(1),
    description: z.string(),
    relatedIocs: z.array(z.string()),
    mitreTechniques: z.array(z.string()),
    status: z.enum(["open", "confirmed", "dismissed"]),
  })),
  iocs: z.array(z.object({
    id: z.string().min(1),
    type: z.enum(["ip", "domain", "hash", "file", "process", "url", "other"]),
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
    severity: z.enum(["Critical", "High", "Medium", "Low", "Info"]).default("Info"),
    mitreTechniques: z.array(z.string()).default([]),
    relatedFindingIds: z.array(z.string()).default([]),
  })).optional(),
  // Narrative reconstruction of the attacker's path (kill-chain story).
  attackerPath: z.string().optional(),
  // Standard DFIR questions with current answers + where to find them.
  keyQuestions: z.array(z.object({
    id: z.string().min(1),
    question: z.string().min(1),
    status: z.enum(["answered", "partial", "unknown"]).default("unknown"),
    answer: z.string().default(""),
    pointer: z.string().default(""),
  })).optional(),
});

export type AnalysisDelta = z.infer<typeof deltaSchema>;
