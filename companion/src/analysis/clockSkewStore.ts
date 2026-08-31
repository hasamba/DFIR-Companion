import { readFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import {
  DEFAULT_MAX_AUTO_ALIGN_MS,
  hostKey,
  type ClockSkewResult,
  type ClockSkewReport,
  type HostTimeGap,
  type SkewConfidence,
} from "./clockSkew.js";

// Per-case clock-skew state (#228), in state/clock-skew.json. A stateless wrapper over CaseStore
// (mirrors SourceTrustStore). Holds the alignment toggle, the last detection, and the analyst's
// per-host offset overrides. Returns sensible defaults when absent / unreadable.
export interface ClockSkewRecord {
  alignEnabled: boolean;
  results: ClockSkewResult[];
  // Analyst-set offsets keyed by normalized short hostname. Always win over a detected offset; an
  // explicit 0 means "this clock is right, leave it alone".
  overrides: Record<string, number>;
  // Large timestamp splits found on single hosts (#740). Advisory only — nothing aligns on these,
  // and unlike `results` they are REPLACED on every detection rather than accumulated, because they
  // describe the whole current timeline rather than accumulating independent anchor evidence.
  timeGaps: HostTimeGap[];
  detectedAt: string; // when `results` were measured ("" if never)
  anchorGroups: number; // anchors behind `results`, kept so a weaker re-run can be recognised
  referenceHost: string; // the clock `results` are expressed against (see detectClockSkew)
  updatedAt: string;
}

const EMPTY: ClockSkewRecord = {
  alignEnabled: false,
  results: [],
  overrides: {},
  timeGaps: [],
  detectedAt: "",
  anchorGroups: 0,
  referenceHost: "",
  updatedAt: "",
};

const CONFIDENCES: SkewConfidence[] = ["high", "medium", "low"];

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

// Rebuild a result from JSON that a hand-edit (or an older build) may have malformed. Anything
// unrecognisable is dropped rather than trusted — a bad offset here would shift a real timeline.
function cleanResult(raw: unknown): ClockSkewResult | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const r = raw as Record<string, unknown>;
  const host = typeof r.host === "string" ? r.host : "";
  const key = typeof r.hostKey === "string" && r.hostKey ? hostKey(r.hostKey) : hostKey(host);
  if (!key) return undefined;
  const confidence = CONFIDENCES.includes(r.confidence as SkewConfidence)
    ? (r.confidence as SkewConfidence)
    : "low";
  const offsetMs = num(r.offsetMs);
  const qualified = r.qualified === true;
  return {
    host: host || key,
    hostKey: key,
    offsetMs,
    anchorCount: num(r.anchorCount),
    dispersionMs: num(r.dispersionMs),
    confidence,
    qualified,
    // Derived, not defaulted, when the field is absent: a record written before `alignable` existed
    // has to keep aligning the hosts it was already aligning, and a bare `=== true` would silently
    // switch every one of them off on the next read.
    alignable:
      typeof r.alignable === "boolean"
        ? r.alignable
        : qualified && Math.abs(offsetMs) <= DEFAULT_MAX_AUTO_ALIGN_MS,
    skewed: r.skewed === true,
    sources: Array.isArray(r.sources) ? r.sources.filter((s): s is string => typeof s === "string") : [],
  };
}

// Same defensive rebuild as cleanResult, for an advisory gap. A malformed entry is dropped rather
// than shown — a warning nobody can read is worse than no warning.
function cleanGap(raw: unknown): HostTimeGap | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const g = raw as Record<string, unknown>;
  const host = typeof g.host === "string" ? g.host : "";
  const key = typeof g.hostKey === "string" && g.hostKey ? hostKey(g.hostKey) : hostKey(host);
  if (!key) return undefined;
  const iso = (v: unknown): string => (typeof v === "string" ? v : "");
  return {
    host: host || key,
    hostKey: key,
    gapMs: num(g.gapMs),
    minorityCount: num(g.minorityCount),
    totalCount: num(g.totalCount),
    minorityStart: iso(g.minorityStart),
    minorityEnd: iso(g.minorityEnd),
    majorityStart: iso(g.majorityStart),
    majorityEnd: iso(g.majorityEnd),
    minoritySide: g.minoritySide === "after" ? "after" : "before",
    sources: Array.isArray(g.sources) ? g.sources.filter((sc): sc is string => typeof sc === "string") : [],
  };
}

function cleanOverrides(raw: unknown): Record<string, number> {
  if (!raw || typeof raw !== "object") return {};
  const out: Record<string, number> = {};
  for (const [host, value] of Object.entries(raw as Record<string, unknown>)) {
    const key = hostKey(host);
    if (key && typeof value === "number" && Number.isFinite(value)) out[key] = value;
  }
  return out;
}

export class ClockSkewStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "clock-skew.json");
  }

  async load(caseId: string): Promise<ClockSkewRecord> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8"));
      return {
        alignEnabled: parsed.alignEnabled === true,
        results: Array.isArray(parsed.results)
          ? (parsed.results as unknown[])
              .map(cleanResult)
              .filter((r): r is ClockSkewResult => r !== undefined)
          : [],
        overrides: cleanOverrides(parsed.overrides),
        timeGaps: Array.isArray(parsed.timeGaps)
          ? (parsed.timeGaps as unknown[]).map(cleanGap).filter((g): g is HostTimeGap => g !== undefined)
          : [],
        detectedAt: typeof parsed.detectedAt === "string" ? parsed.detectedAt : "",
        anchorGroups: num(parsed.anchorGroups),
        referenceHost: typeof parsed.referenceHost === "string" ? parsed.referenceHost : "",
        updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : "",
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  async save(caseId: string, record: ClockSkewRecord): Promise<ClockSkewRecord> {
    await mkdir(this.cases.stateDir(caseId), { recursive: true });
    const clean: ClockSkewRecord = {
      alignEnabled: record.alignEnabled === true,
      results: (Array.isArray(record.results) ? record.results : [])
        .map(cleanResult)
        .filter((r): r is ClockSkewResult => r !== undefined),
      overrides: cleanOverrides(record.overrides),
      timeGaps: (Array.isArray(record.timeGaps) ? record.timeGaps : [])
        .map(cleanGap)
        .filter((g): g is HostTimeGap => g !== undefined),
      detectedAt: typeof record.detectedAt === "string" ? record.detectedAt : "",
      anchorGroups: num(record.anchorGroups),
      referenceHost: typeof record.referenceHost === "string" ? record.referenceHost : "",
      updatedAt: new Date().toISOString(),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(clean, null, 2));
    return clean;
  }

  /**
   * Store a fresh detection.
   *
   * Detection reads anchors from the PRE-merge timeline, and correlateEvents collapses those anchors
   * the first time it runs (see clockSkew.ts). So a later re-run legitimately sees less evidence
   * than the first one did, and must not overwrite a well-anchored measurement with a thinner one.
   * Per host the better-anchored result wins; `replace` forces the fresh one in wholesale, which is
   * what an explicit analyst-triggered recompute wants after new evidence lands.
   */
  async recordDetection(
    caseId: string,
    report: ClockSkewReport,
    opts: { replace?: boolean } = {},
  ): Promise<ClockSkewRecord> {
    const current = await this.load(caseId);
    let results = report.results;
    if (!opts.replace) {
      const merged = new Map(current.results.map((r) => [r.hostKey, r]));
      for (const fresh of report.results) {
        const prev = merged.get(fresh.hostKey);
        if (!prev || fresh.anchorCount >= prev.anchorCount) merged.set(fresh.hostKey, fresh);
      }
      results = [...merged.values()].sort((a, b) => a.hostKey.localeCompare(b.hostKey));
    }
    return this.save(caseId, {
      ...current,
      results,
      // Replaced, not merged: see the field comment. A report that measured no gaps (the caller did
      // not compute them) leaves the stored ones alone rather than silently clearing a warning.
      timeGaps: report.timeGaps ?? current.timeGaps,
      detectedAt: new Date().toISOString(),
      anchorGroups: opts.replace ? report.anchorGroups : Math.max(current.anchorGroups, report.anchorGroups),
      referenceHost: report.referenceHost || current.referenceHost,
    });
  }

  async setAlign(caseId: string, alignEnabled: boolean): Promise<ClockSkewRecord> {
    const current = await this.load(caseId);
    return this.save(caseId, { ...current, alignEnabled });
  }

  /** Set (number) or clear (null) one host's manual offset. */
  async setOverride(caseId: string, host: string, offsetMs: number | null): Promise<ClockSkewRecord> {
    const current = await this.load(caseId);
    const key = hostKey(host);
    const overrides = { ...current.overrides };
    if (offsetMs === null) delete overrides[key];
    else overrides[key] = offsetMs;
    return this.save(caseId, { ...current, overrides });
  }
}
