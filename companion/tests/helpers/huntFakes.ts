import type { ForensicRow } from "../../src/analysis/forensicRows.js";
import type { HuntSettleStateStore } from "../../src/analysis/huntSettle.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";

/** An in-memory forensic timeline with the row API hunt grading uses (#2670). */
export function memoryHuntStore(rows: ForensicEvent[] = [], overview: Partial<InvestigationState> = {}) {
  let next = 1;
  const table = new Map<number, ForensicRow>();
  const put = (e: ForensicEvent) => {
    const rowId = next++;
    table.set(rowId, { rowId, version: 1, event: e });
  };
  rows.forEach(put);
  const store: HuntSettleStateStore & { events(): ForensicEvent[] } = {
    async loadOverview(caseId) {
      return { ...emptyState(caseId), ...overview };
    },
    async appendForensicEvents(_c, events) {
      events.forEach(put);
      return events.length;
    },
    async forensicRowsById(_c, ids) {
      const want = new Set(ids);
      return [...table.values()].filter((r) => want.has(r.event.id));
    },
    async updateForensicRows(_c, update) {
      for (const r of update) table.set(r.rowId, { ...r, version: r.version + 1 });
      return { written: update.length };
    },
    async deleteForensicRows(_c, rowIds) {
      for (const id of rowIds) table.delete(id);
      return rowIds.length;
    },
    events: () => [...table.values()].map((r) => r.event),
  };
  return store;
}

export const reachedJob = (n: number, p: Partial<VeloHuntJob> = {}): VeloHuntJob => ({
  bundleId: "threat-hunt-starter",
  bundleName: "Threat Hunt Starter",
  artifacts: [],
  huntId: "H.1",
  launchedAt: "2026-01-01T00:00:00Z",
  waitMinutes: 15,
  collectAt: "2026-01-01T00:15:00Z",
  status: "imported",
  clientCounts: { scheduled: n, completed: n, errors: 0 },
  reachedClients: Array.from({ length: n }, (_, i) => ({
    clientId: `C.${i}`,
    hostname: `WS-${String(i).padStart(3, "0")}`,
    fqdn: "",
    os: "windows",
  })),
  ...p,
});

/** A Velociraptor prefetch row for `program` at `dir` on host index `i`. */
export const prefetchRow = (id: string, i: number, program: string, dir = "C:\\Tools"): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: `Velociraptor [Windows.Forensics.Prefetch]: Executed (prefetch): ${program.toUpperCase()} (${dir}\\${program}) - @ WS-${String(i).padStart(3, "0")}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: `WS-${String(i).padStart(3, "0")}`,
  path: `${dir}\\${program}`,
  processName: program,
  artifactName: "Windows.Forensics.Prefetch",
});
