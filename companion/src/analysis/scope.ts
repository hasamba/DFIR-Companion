import { readFile } from "node:fs/promises";
import { atomicWrite } from "../storage/atomicWrite.js";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { ForensicEvent } from "./stateTypes.js";

// An optional investigation time window. Events outside it (and the findings/IOCs
// derived from them) are excluded — useful when the evidence includes earlier,
// unrelated activity. Null bounds mean "unbounded on that side".
export interface ScopeWindow {
  start: string | null;   // ISO-8601, inclusive lower bound
  end: string | null;     // ISO-8601, inclusive upper bound
}

export const NO_SCOPE: ScopeWindow = { start: null, end: null };

export function hasScope(scope: ScopeWindow): boolean {
  return Boolean(scope.start) || Boolean(scope.end);
}

// An undated (unparseable) timestamp can't be proven out of scope, so it is kept.
export function inScope(timestamp: string, scope: ScopeWindow): boolean {
  if (!hasScope(scope)) return true;
  const t = Date.parse(timestamp);
  if (Number.isNaN(t)) return true;
  if (scope.start) { const s = Date.parse(scope.start); if (!Number.isNaN(s) && t < s) return false; }
  if (scope.end) { const e = Date.parse(scope.end); if (!Number.isNaN(e) && t > e) return false; }
  return true;
}

export function filterEventsByScope(events: ForensicEvent[], scope: ScopeWindow): ForensicEvent[] {
  if (!hasScope(scope)) return events;
  return events.filter((e) => inScope(e.timestamp, scope));
}

export class ScopeStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "scope.json");
  }

  async load(caseId: string): Promise<ScopeWindow> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<ScopeWindow>;
      return { start: raw.start ?? null, end: raw.end ?? null };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...NO_SCOPE };
      throw err;
    }
  }

  async save(caseId: string, scope: ScopeWindow): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(scope, null, 2));
  }
}
