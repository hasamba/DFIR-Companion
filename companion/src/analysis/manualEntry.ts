// Analyst-authored manual entries: a forensic event or an IOC the AI didn't catch. Pure +
// validated (zod), with injectable now()/id() so the builders are deterministic in tests. The
// server appends the result to the case state; because synthesis PRESERVES the forensic timeline
// and IOCs, manual entries survive re-synthesis (and a high-severity manual event still earns a
// finding via the backfill).

import { z } from "zod";
import { randomUUID } from "node:crypto";
import type { ForensicEvent, IOC, Severity } from "./stateTypes.js";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;
const IOC_TYPES = ["ip", "domain", "hash", "file", "process", "url", "other"] as const;

// Accept MITRE techniques as an array OR a comma/space-separated string; normalize to T-id list.
const techniques = z.preprocess(
  (v) => (typeof v === "string" ? v.split(/[\s,]+/) : v),
  z.array(z.string()).catch([]),
).transform((arr) => arr.map((t) => t.trim().toUpperCase()).filter((t) => /^T\d{4}(\.\d{3})?$/.test(t)));

export const manualEventSchema = z.object({
  timestamp: z.string().min(1, "timestamp is required"),
  description: z.string().min(1, "description is required"),
  severity: z.enum(SEVERITIES).catch("Medium"),
  asset: z.string().trim().optional(),
  mitreTechniques: techniques.optional().default([]),
  sha256: z.string().trim().optional(),
  md5: z.string().trim().optional(),
  path: z.string().trim().optional(),
});

export const manualIocSchema = z.object({
  type: z.enum(IOC_TYPES),
  value: z.string().trim().min(1, "value is required"),
});

export interface BuildDeps {
  now?: () => string;        // injected ISO clock (default real)
  id?: () => string;         // injected id generator (default randomUUID)
}

// Parse a date as forgivingly as the UI sends it (ISO, or a datetime-local value); fall back to
// the raw string when it isn't parseable so the event still carries the analyst's intent.
function normalizeTimestamp(input: string): string {
  const d = new Date(input);
  return Number.isNaN(d.getTime()) ? input : d.toISOString();
}

// Build a ForensicEvent from validated input. Tagged `sources: ["manual"]` for provenance.
export function buildManualEvent(input: unknown, deps: BuildDeps = {}): ForensicEvent {
  const p = manualEventSchema.parse(input);
  const id = deps.id ?? randomUUID;
  return {
    id: `manual-${id()}`,
    timestamp: normalizeTimestamp(p.timestamp),
    description: p.description.trim(),
    severity: p.severity as Severity,
    mitreTechniques: p.mitreTechniques,
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["manual"],
    ...(p.asset ? { asset: p.asset } : {}),
    ...(p.sha256 ? { sha256: p.sha256 } : {}),
    ...(p.md5 ? { md5: p.md5 } : {}),
    ...(p.path ? { path: p.path } : {}),
  };
}

// Build an IOC from validated input.
export function buildManualIoc(input: unknown, deps: BuildDeps = {}): IOC {
  const p = manualIocSchema.parse(input);
  const now = deps.now ?? (() => new Date().toISOString());
  const id = deps.id ?? randomUUID;
  return {
    id: `manual-${id()}`,
    type: p.type,
    value: p.value,
    firstSeen: now(),
  };
}
