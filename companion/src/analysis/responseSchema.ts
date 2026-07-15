import { z } from "zod";

// Enums use .catch(fallback) so ONE unexpected value (e.g. an IOC type of "malware")
// maps to the fallback instead of rejecting the ENTIRE synthesis response.
const severity = z.enum(["Critical", "High", "Medium", "Low", "Info"]);
const iocType = z.enum(["ip", "domain", "hash", "file", "process", "url", "sid", "other"]);

// A structured collection directive (investigation-guidance #8) — where/what to collect. Every field is
// optional + lenient so a partial model reply still parses; sanitized/validated (host vs known
// endpoints) at the consumer, not here.
const collectDirective = z.object({
  host: z.string().optional().catch(undefined),
  artifact: z.string().optional().catch(undefined),
  logSource: z.string().optional().catch(undefined),
  expectedOutcome: z.string().optional().catch(undefined),
}).optional();

export const deltaSchema = z.object({
  findings: z.array(z.object({
    id: z.string().min(1),
    severity: severity.catch("Medium"),
    confidence: z.number().min(0).max(100).optional().catch(undefined),
    confidenceReason: z.string().max(500).optional().catch(undefined),
    title: z.string().min(1),
    description: z.string(),
    relatedIocs: z.array(z.string()),
    mitreTechniques: z.array(z.string()),
    status: z.enum(["open", "confirmed", "dismissed"]).catch("open"),
    // Synthesis only: the forensic-event ids this finding is based on. Used to
    // back-link events to the correct findings (extraction can't know finding ids).
    relatedEventIds: z.array(z.string()).optional(),
    // Rabbit-hole detection (investigation-guidance #13): the model's relevance verdict for genuine-
    // but-possibly-unrelated activity. 'unrelated-but-real' = real, but NOT part of THIS incident's
    // attack path (a separate issue to park); 'undetermined' = unsure. The deterministic connectedness
    // pass is authoritative for 'connected'/'disconnected'; this only refines a disconnected finding.
    relevance: z.enum(["connected", "unrelated-but-real", "undetermined"]).optional().catch(undefined),
  })),
  iocs: z.array(z.object({
    id: z.string().min(1),
    type: iocType.catch("other"),
    value: z.string().min(1),
    // Authoritative source-event links (set by the deterministic importers via pipeline.ts, never
    // by AI synthesis). Optional — absent for every existing caller.
    extractedFrom: z.array(z.string()).optional(),
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
    artifactName: z.string().optional(),
    message: z.string().optional(),
    veloUrl: z.string().optional(),
    processName: z.string().optional(),
    parentName: z.string().optional(),
    pid: z.number().int().positive().optional(),              // subject pid on process-creation events (cross-tool correlation)
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
    // Finding ids this answer is based on — lets a later false-positive mark force a re-answer.
    relatedFindingIds: z.array(z.string()).default([]).catch([]),
    // Structured collection directive for an unknown/partial question (#8): where/what to collect.
    collect: collectDirective,
  })).optional(),
  // Prioritized recommendations for the most valuable next investigative actions.
  nextSteps: z.array(z.object({
    id: z.string().min(1),
    priority: z.enum(["critical", "high", "medium", "low"]).default("medium").catch("medium"),
    action: z.string().min(1),
    rationale: z.string().default(""),
    pointer: z.string().default(""),
    // Structured collection directive (#8) for a collection-type step + the findings it advances.
    collect: collectDirective,
    relatedFindingIds: z.array(z.string()).default([]).catch([]),
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
    // ACH-style analysis (investigation-guidance #14): events INCONSISTENT with this explanation, and
    // the single artifact (host + artifact) that would best separate it from the leading alternative.
    contradictingEventIds: z.array(z.string()).default([]).catch([]),
    discriminator: z.string().default("").catch(""),
  })).optional(),
  // Second-look loop (investigation-guidance #11): data the model knows it was NOT shown (only a
  // sample of the timeline is included in the prompt). Each request is resolved AFTER synthesis against
  // the complete raw record (super-timeline + omitted scoped events); matches are promoted for one
  // bounded re-synthesis, and a request that matches nothing becomes a collection lead. Lenient/optional
  // so a model that omits it (or fills it partially) still parses. Consumed in pipeline.ts, not merged.
  evidenceRequests: z.array(z.object({
    host: z.string().optional().catch(undefined),
    timeWindow: z.object({
      from: z.string().optional().catch(undefined),
      to: z.string().optional().catch(undefined),
    }).optional().catch(undefined),
    keywords: z.array(z.string()).default([]).catch([]),
    reason: z.string().default("").catch(""),
  })).optional(),
});

export type AnalysisDelta = z.infer<typeof deltaSchema>;

// AI synthesis/extraction responses must never carry extractedFrom — that field asserts an
// authoritative, stored source-event link, which only the deterministic importers (pipeline.ts)
// are allowed to set. Without this, a model response (or prompt-injected content it read from
// evidence) could fabricate the field and have it rendered as "linked" in the IOC provenance
// panel — a false trust claim. Strip it defensively after schema validation, at every AI
// extraction/synthesis call site (never at the deterministic-importer call sites, which build
// their delta objects field-by-field and set extractedFrom themselves via resolveExtractedFrom).
export function stripAiExtractedFrom(delta: AnalysisDelta): AnalysisDelta {
  return { ...delta, iocs: delta.iocs.map(({ extractedFrom, ...rest }) => rest) };
}

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

// Which OTHER case items (by id) likely share the same false-positive pattern as the anchor the
// analyst just marked (#227). Lenient: an id list, defaulting to empty on a malformed response.
export const fpSimilaritySchema = z.object({
  candidateIds: z.array(z.string()).catch([]),
});

export type FpSimilarityResult = z.infer<typeof fpSimilaritySchema>;

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

// On-demand hypothesis falsification review (issue #71): for each OPEN hypothesis, the plain-English
// evidence for and against it plus an ADVISORY recommended status. Lenient (.catch everywhere) so a
// partial/slightly-off model reply still parses; sanitizeHypothesisReviews then drops invented targets,
// coerces the status, and filters event ids. The recommendation is advisory — never auto-applied.
export const hypothesisReviewSchema = z.object({
  reviews: z.array(z.object({
    hypothesisId: z.string().catch(""),
    title: z.string().catch(""),
    supportingEvidence: z.array(z.string()).catch([]),
    refutingEvidence: z.array(z.string()).catch([]),
    recommendedStatus: z.enum(["open", "supported", "refuted", "unknown"]).catch("unknown"),
    rationale: z.string().catch(""),
    relatedEventIds: z.array(z.string()).catch([]),
  })).catch([]),
});

export type HypothesisReviewResponse = z.infer<typeof hypothesisReviewSchema>;
