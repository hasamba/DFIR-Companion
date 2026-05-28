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
});

export type AnalysisDelta = z.infer<typeof deltaSchema>;
