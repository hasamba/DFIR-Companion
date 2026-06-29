import { z } from "zod";

// Enums use .catch(fallback) so ONE unexpected value (e.g. an IOC type of "malware")
// maps to the fallback instead of rejecting the ENTIRE synthesis response.
const severity = z.enum(["Critical", "High", "Medium", "Low", "Info"]);
const iocType = z.enum(["ip", "domain", "hash", "file", "process", "url", "other"]);

export const deltaSchema = z.object({
  findings: z.array(z.object({
    id: z.string().min(1),
    severity: severity.catch("Medium"),
    confidence: z.number().min(0).max(100).optional().catch(undefined),
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
    // Aggregation: when one event represents many collapsed occurrences (e.g. "20
    // failed logins"), count is the number of occurrences and endTimestamp the time
    // of the last one. Absent/1 means a single discrete event.
    count: z.number().int().positive().optional(),
    endTimestamp: z.string().optional(),
    // Correlation identifiers (let the model tie an event to a concrete file/hash).
    sha256: z.string().optional(),
    md5: z.string().optional(),
    path: z.string().optional(),
    asset: z.string().optional(),                             // host/computer/FQDN the event pertains to
    sources: z.array(z.string()).optional(),
    processName: z.string().optional(),
    parentName: z.string().optional(),
    // Phase 2 evidence-chain fields.
    action: z.enum(["write", "execute", "network_send", "network_receive"]).optional(),
    srcIp: z.string().optional(),
    dstIp: z.string().optional(),
    port: z.number().int().positive().optional(),
  })).optional(),
  // Narrative reconstruction of the attacker's path (kill-chain story).
  attackerPath: z.string().optional(),
  // Prose narrative of the incident for management/stakeholders.
  narrativeTimeline: z.string().optional(),
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
  // Candidate explanations for the observed activity (issue #140 — hypothesis-driven mode). Title is
  // NOT .min(1) so a blank one doesn't reject the whole array — sanitizeHypotheses drops it. These are
  // merged into the per-case HypothesisStore (refresh-pristine / freeze-touched), not InvestigationState.
  hypotheses: z.array(z.object({
    title: z.string().default(""),
    description: z.string().default("").catch(""),
    expectedOutcome: z.string().default("").catch(""),
    status: z.enum(["open", "supported", "refuted", "unknown"]).default("open").catch("open"),
    relatedTechniques: z.array(z.string()).default([]).catch([]),
    relatedEventIds: z.array(z.string()).default([]).catch([]),
    relatedIocIds: z.array(z.string()).default([]).catch([]),
  })).optional(),
});

export type AnalysisDelta = z.infer<typeof deltaSchema>;

// Answer to an analyst's free-form question about the case ("was data exfiltrated?").
// Lenient (.catch) like the delta so a slightly-off model response still parses.
export const askSchema = z.object({
  answer: z.string().catch(""),
  status: z.enum(["answered", "partial", "unknown"]).catch("unknown"),
  pointer: z.string().catch(""),                 // where/which artifact to look for or collect next
  relatedEventIds: z.array(z.string()).catch([]),
});

export type AskAnswer = z.infer<typeof askSchema>;

// Management-facing executive summary of the whole case (plain-language, no T-codes/hashes).
// Lenient like the others so a slightly-off model response still parses.
export const execSummarySchema = z.object({
  summary: z.string().catch(""),
});

export type ExecSummary = z.infer<typeof execSummarySchema>;

// Incident-specific remediation plan (#178) — a concrete, prioritized action list the IR team can
// execute, grounded in the case findings + ATT&CK mitigations. Markdown in a single string. Lenient.
export const remediationPlanSchema = z.object({
  plan: z.string().catch(""),
});

export type RemediationPlan = z.infer<typeof remediationPlanSchema>;

// AI explanation of a single forensic event in the context of the investigation (issue #141).
// Lenient (.catch) so a slightly-off model response still parses.
export const explainEventSchema = z.object({
  summary: z.string().catch(""),
  whyItMatters: z.string().catch(""),
  normalContext: z.string().catch(""),
  suspiciousIndicators: z.string().catch(""),
  attackMapping: z.string().catch(""),
  pivotQueries: z.array(z.object({
    platform: z.string().catch(""),
    query: z.string().catch(""),
    rationale: z.string().catch(""),
  })).catch([]),
  evidenceFor: z.string().catch(""),
  evidenceAgainst: z.string().catch(""),
  relatedEventIds: z.array(z.string()).catch([]),
});

export type ExplainEventResult = z.infer<typeof explainEventSchema>;
