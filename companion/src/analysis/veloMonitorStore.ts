import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { Severity } from "./stateTypes.js";

// Per-case record of live Velociraptor CLIENT_EVENT monitors (#84). Each monitor watches one client
// monitoring artifact (e.g. Windows.Events.ProcessCreation) on one endpoint; the server polls it on an
// interval and feeds new rows into the push/import pipeline. The `cursor` (last-seen event epoch) is
// persisted here so a server restart (the project's #1 gotcha) resumes WITHOUT re-ingesting old events.
// MULTIPLE monitors per case are supported (a list keyed by id). NOT part of InvestigationState, and
// excluded from the snapshot allowlist (machine/transient, like velo-hunt).

export type VeloMonitorStatus = "active" | "stopped" | "error";

export interface VeloMonitor {
  id: string;                 // stable id = clientId__artifact, so re-adding the same pair refreshes it
  clientId: string;           // Velociraptor client id (C....)
  hostname?: string;          // display name resolved from the inventory (optional)
  artifact: string;           // CLIENT_EVENT artifact name (Windows.Events.ProcessCreation, …)
  pollSeconds: number;        // poll interval (clamped at the route)
  cursor: number;             // last-seen event time, epoch SECONDS (0 = start from first poll's window)
  status: VeloMonitorStatus;
  minSeverity?: Severity;     // optional import floor (keeps low-value telemetry out)
  createdAt: string;          // ISO
  lastPolledAt?: string;      // ISO of the last poll attempt
  lastEventAt?: string;       // ISO of the last poll that actually ingested rows
  addedEvents?: number;       // cumulative forensic events ingested by this monitor
  polls?: number;             // cumulative poll count
  lastError?: string;         // last poll error (cleared on the next success)
}

// Cap retained monitors per case so the side file stays small.
const MAX_MONITORS = 24;

// Build the stable id for a (client, artifact) pair — re-adding the same pair updates in place rather
// than spawning a duplicate poller.
export function monitorId(clientId: string, artifact: string): string {
  return `${clientId}__${artifact}`;
}

export class VeloMonitorStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "velo-monitor.json");
  }

  // All monitors for the case (insertion order). [] when the file is missing/malformed (never throws).
  async list(caseId: string): Promise<VeloMonitor[]> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8")) as unknown;
      if (Array.isArray(parsed)) return parsed.filter((m): m is VeloMonitor => !!m && typeof (m as VeloMonitor).id === "string");
      return [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async get(caseId: string, id: string): Promise<VeloMonitor | null> {
    return (await this.list(caseId)).find((m) => m.id === id) ?? null;
  }

  // Add a new monitor (appended) or update an existing one in place (matched by id), capping history.
  async upsert(caseId: string, monitor: VeloMonitor): Promise<VeloMonitor> {
    const monitors = await this.list(caseId);
    const idx = monitors.findIndex((m) => m.id === monitor.id);
    const next = idx >= 0 ? monitors.map((m, i) => (i === idx ? monitor : m)) : [...monitors, monitor].slice(-MAX_MONITORS);
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return monitor;
  }

  async remove(caseId: string, id: string): Promise<void> {
    const monitors = await this.list(caseId);
    const next = monitors.filter((m) => m.id !== id);
    if (next.length !== monitors.length) {
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    }
  }
}
