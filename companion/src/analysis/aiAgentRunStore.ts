// AI Agent Forensics (#2690): the per-case record of runs (`state/ai-agent-runs.json`) — what was
// launched on which endpoints, with which rule version and options, and the results-only report and
// upload manifest once fetched. The hunt itself is tracked by VeloHuntStore like any bundle hunt; this
// file holds what only this feature needs. A sweep case (outside-a-case run) holds exactly one run.

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import type { AiAgentReport } from "./aiAgentReport.js";

const MAX_RUNS_PER_CASE = 20;

/** One file a run uploaded to Velociraptor, as the manifest records it — never its content. */
export interface UploadManifestEntry {
  clientId: string;
  flowId: string;
  path: string;
  size: number;
  sha256: string;
}
const MANIFEST_MAX = 2000;
const lock = new StateLock();

export interface AiAgentRun {
  runId: string;
  huntId: string;
  guiUrl?: string;
  launchedAt: string;
  serverSetId?: string;
  endpoints: { clientId: string; hostname: string }[];
  failedEndpoints: { clientId: string; error: string }[];
  skippedEndpoints: { clientId: string; hostname: string; reason: string }[];
  scopes: string[];
  uploadMaxBytes: number;
  ruleSetVersion: string;
  artifacts: string[];
  preserved: boolean;
  warnings: string[];
  /** Always true: preservation may have copied credential files into Velociraptor (§14.3). */
  sensitive: true;
  report?: AiAgentReport;
  /** The run's raw result rows (capped) — what "Add to case" files. Carries the unredacted snippet:
   *  never served to the dashboard and never AI input (routes strip it). */
  rows?: Record<string, unknown>[];
  reportError?: string;
  manifest?: { fetchedAt: string; total: number; totalBytes: number; files: UploadManifestEntry[] };
  /** Cases this sweep's hits were filed into with "Add to case". */
  addedTo?: { caseId: string; at: string; events: number }[];
}

export function newAiAgentRunId(): string {
  return `aar-${randomUUID()}`;
}

export class AiAgentRunStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "ai-agent-runs.json");
  }

  async list(caseId: string): Promise<AiAgentRun[]> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8")) as unknown;
      return Array.isArray(parsed) ? (parsed as AiAgentRun[]) : [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async get(caseId: string, runId: string): Promise<AiAgentRun | null> {
    return (await this.list(caseId)).find((r) => r.runId === runId) ?? null;
  }

  /** Add a run (newest first, capped) or replace it in place. */
  upsert(caseId: string, run: AiAgentRun): Promise<AiAgentRun> {
    return lock.runExclusive(caseId, async () => {
      const runs = await this.list(caseId);
      const idx = runs.findIndex((r) => r.runId === run.runId);
      const next =
        idx >= 0 ? runs.map((r, i) => (i === idx ? run : r)) : [run, ...runs].slice(0, MAX_RUNS_PER_CASE);
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return run;
    });
  }

  /** Read-modify-write one run under the case lock; null when it no longer exists. */
  update(caseId: string, runId: string, fn: (run: AiAgentRun) => AiAgentRun): Promise<AiAgentRun | null> {
    return lock.runExclusive(caseId, async () => {
      const runs = await this.list(caseId);
      const idx = runs.findIndex((r) => r.runId === runId);
      if (idx < 0) return null;
      const written = { ...fn(runs[idx]), runId };
      await atomicWrite(
        this.path(caseId),
        JSON.stringify(
          runs.map((r, i) => (i === idx ? written : r)),
          null,
          2,
        ),
      );
      return written;
    });
  }
}

/** The manifest as stored: totals over everything, the file list capped. */
export function capManifest(
  entries: readonly UploadManifestEntry[],
  now = new Date(),
): AiAgentRun["manifest"] {
  return {
    fetchedAt: now.toISOString(),
    total: entries.length,
    totalBytes: entries.reduce((n, e) => n + (e.size || 0), 0),
    files: entries.slice(0, MANIFEST_MAX),
  };
}
