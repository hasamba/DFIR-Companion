// AI Agent Forensics (#2721, #2740): the report-safe fields of one stored run — the allowlist both the
// case report section and the filed-run copy (aiAgentFiledRuns.ts) use. Never the raw rows, which hold
// the unredacted matched text, and never the manifest's file list.

import type { AiAgentRunView } from "../analysis/aiAgentReportTypes.js";

type Obj = Record<string, unknown>;

export const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
export const str = (v: unknown): v is string => typeof v === "string";
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter(str) : []);
export const objs = (v: unknown): Obj[] => (Array.isArray(v) ? v.filter(isObj) : []);
const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);

/** A stored report is kept only when its lists are lists; its nested cells are escaped at render. */
function reportOf(v: unknown): AiAgentRunView["report"] {
  if (!isObj(v) || !Array.isArray(v.endpoints) || !Array.isArray(v.hits) || !Array.isArray(v.notRun))
    return undefined;
  return v as unknown as AiAgentRunView["report"];
}

/** The report-safe fields of one stored run; null when it lacks the fields every run has. */
export function projectAiAgentRun(raw: unknown): AiAgentRunView | null {
  if (!isObj(raw) || !str(raw.runId) || !str(raw.huntId) || !str(raw.launchedAt)) return null;
  const report = reportOf(raw.report);
  const manifest = isObj(raw.manifest) ? raw.manifest : null;
  const incomplete = objs(raw.readIncomplete).map((x) => ({
    artifact: String(x.artifact ?? ""),
    rowsRead: num(x.rowsRead),
  }));
  return {
    runId: raw.runId,
    huntId: raw.huntId,
    ...(str(raw.guiUrl) ? { guiUrl: raw.guiUrl } : {}),
    launchedAt: raw.launchedAt,
    scopes: strs(raw.scopes),
    ruleSetVersion: str(raw.ruleSetVersion) ? raw.ruleSetVersion : "",
    preserved: raw.preserved === true,
    warnings: strs(raw.warnings),
    failedEndpoints: objs(raw.failedEndpoints).map((e) => ({
      clientId: String(e.clientId ?? ""),
      error: String(e.error ?? ""),
    })),
    skippedEndpoints: objs(raw.skippedEndpoints).map((e) => ({
      clientId: String(e.clientId ?? ""),
      hostname: String(e.hostname ?? ""),
      reason: String(e.reason ?? ""),
    })),
    ...(incomplete.length ? { readIncomplete: incomplete } : {}),
    ...(str(raw.reportError) ? { reportError: raw.reportError } : {}),
    ...(manifest ? { manifest: { total: num(manifest.total), totalBytes: num(manifest.totalBytes) } } : {}),
    ...(report ? { report } : {}),
  };
}
