/**
 * Live Velociraptor CLIENT_EVENT monitors (#84): per-case pollers that stream a client monitoring
 * artifact's new rows into the import pipeline. Lifted out of createApp by #416; the timer
 * behaviour is pinned by tests/server/timerLifecycle.test.ts.
 *
 * setTimeout PER MONITOR, NOT setInterval. A poll that runs long must not overlap itself — the
 * cursor is advanced by the poll, so two in flight would read the same window twice. Each tick
 * schedules the next one at the end, which also means a monitor that is stopped or deleted mid-poll
 * simply never re-arms.
 *
 * TIMERS ARE LOST ON RESTART, BY DESIGN. The monitors themselves are persisted, cursor and all, so
 * `resumeMonitors()` re-arms them at startup and streaming picks up exactly where it left off
 * without re-ingesting. Every timer is .unref()'d so a pending poll never blocks process exit.
 */
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import { monitorId, type VeloMonitor } from "../analysis/veloMonitorStore.js";
import {
  pollMonitorOnce,
  monitorArtifactMap,
  type PollDeps,
} from "../integrations/velociraptor/monitorPoller.js";
import {
  ensureClientMonitoring,
  isClientMonitoringEnabled,
  releaseClientMonitoring,
} from "../integrations/velociraptor/clientMonitoringTable.js";
import type { Severity } from "../analysis/stateTypes.js";
import { logLine } from "../logging/serverLogger.js";

export interface VeloMonitorsDeps {
  store: CaseStore;
  options: AppOptions;
  ingestStreamed: (
    caseId: string,
    kind: string,
    text: string,
    originalName: string,
    minSeverity?: Severity,
  ) => Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }>;
}

export interface VeloMonitors {
  /** Snapshot the enrolled fleet into the persisted client inventory (#70). Returns the count. */
  refreshVeloClients(): Promise<number>;
  createVeloMonitor(
    caseId: string,
    spec: {
      clientId: string;
      artifact: string;
      pollSeconds: number;
      hostname?: string;
      minSeverity?: Severity;
      allClients?: boolean;
      /** true = the artifact was just read from Velociraptor's monitoring table; skip the enable step. */
      alreadyEnabled?: boolean;
    },
  ): Promise<VeloMonitor>;
  scheduleVeloMonitor(caseId: string, monitor: VeloMonitor): void;
  pollVeloMonitor(caseId: string, id: string): Promise<void>;
  stopVeloMonitorTimer(caseId: string, id: string): void;
  /**
   * Re-verify that the monitor's artifact is still in Velociraptor's Client Monitoring table (#1409).
   * Returns the monitor unchanged when it is; otherwise persists + returns it as errored with a
   * plain-language lastError so the dashboard stops showing a green light over a silent stream.
   */
  verifyVeloMonitorEnabled(caseId: string, monitor: VeloMonitor): Promise<VeloMonitor>;
  /**
   * Remove a monitor and, when the companion enabled its artifact and no other monitor in any case
   * still uses it, take the artifact back out of Velociraptor's Client Monitoring table (#1409).
   */
  deleteVeloMonitor(caseId: string, id: string): Promise<void>;
  /** Re-arm every non-stopped monitor across all cases (called once at startup). */
  resumeVeloMonitors(): Promise<void>;
}

export function createVeloMonitors({ store, options, ingestStreamed }: VeloMonitorsDeps): VeloMonitors {
  // Per-monitor self-rescheduling timers, keyed `caseId<NUL>monitorId`.
  //
  // The separator is a literal NUL, written as an escape rather than pasted as a raw byte: a raw
  // 0x00 anywhere in a source file makes grep/ripgrep treat the WHOLE file as binary and silently
  // report no matches in it — which is exactly what it did to server.ts before this move. NUL is
  // still the right separator (it is the one character a caseId or artifact name can never contain,
  // so no pair of ids can collide), it just has to be spelled, not embedded.
  const timers = new Map<string, NodeJS.Timeout>();
  const monitorKey = (caseId: string, id: string): string => `${caseId}\u0000${id}`;

  async function refreshVeloClients(): Promise<number> {
    const client = options.velociraptorClient;
    const clientStore = options.velociraptorClientStore;
    if (!client || !clientStore) return 0;
    const clients = await client.listClients();
    await clientStore.save(clients, new Date().toISOString());
    logLine(`[velociraptor] client inventory refreshed — ${clients.length} enrolled client(s)`);
    return clients.length;
  }

  // The ingest step a poll hands its rows to: wrap them as a Velociraptor artifact-map and run the
  // shared streamed-ingest path; return how many forensic events it added (for the running stat).
  async function ingestMonitorRows(caseId: string, monitor: VeloMonitor, rows: unknown[]): Promise<number> {
    const json = monitorArtifactMap(monitor.artifact, rows);
    const shortHost = (monitor.hostname || monitor.clientId)
      .split(".")[0]
      .replace(/[^\w.\-]+/g, "_")
      .slice(0, 40);
    const filename = `velo-monitor_${monitor.artifact}_${shortHost}.json`;
    const r = await ingestStreamed(caseId, "velociraptor", json, filename, monitor.minSeverity);
    return r.addedEvents;
  }

  // One poll cycle for a monitor: load it, poll (pure pollMonitorOnce), persist the updated monitor,
  // broadcast, and reschedule the next tick (unless it was removed/stopped). Never throws.
  async function pollVeloMonitor(caseId: string, id: string): Promise<void> {
    const monStore = options.veloMonitorStore;
    const client = options.velociraptorClient;
    if (!monStore || !client) {
      timers.delete(monitorKey(caseId, id));
      return;
    }
    let monitor: VeloMonitor | null = null;
    try {
      monitor = await monStore.get(caseId, id);
    } catch {
      /* treat as gone */
    }
    if (!monitor || monitor.status === "stopped") {
      timers.delete(monitorKey(caseId, id));
      return;
    }

    const deps: PollDeps = {
      read: async (clientId, artifact, start, end) =>
        (await client.monitorResults(clientId, artifact, start, end)).rows,
      ingest: (m, rows) => ingestMonitorRows(caseId, m, rows),
      now: () => Math.floor(Date.now() / 1000),
      defaultLookbackSeconds: monitor.pollSeconds,
      log: logLine,
    };
    const updated = await pollMonitorOnce(monitor, deps);
    try {
      await monStore.upsert(caseId, updated);
    } catch {
      /* best-effort */
    }
    options.onVeloMonitor?.(caseId);
    // Reschedule only if it's still meant to run (a concurrent stop/delete clears the timer below).
    if (timers.has(monitorKey(caseId, id))) scheduleVeloMonitor(caseId, updated);
  }

  // Arm (or re-arm) a monitor's timer for one poll interval out. Clears any existing timer first so
  // start is idempotent. Clamped 5s..1h so a bad value can't busy-loop or stall forever.
  function scheduleVeloMonitor(caseId: string, monitor: VeloMonitor): void {
    const key = monitorKey(caseId, monitor.id);
    const existing = timers.get(key);
    if (existing) clearTimeout(existing);
    const seconds = Math.min(3600, Math.max(5, Math.floor(monitor.pollSeconds) || 30));
    const timer = setTimeout(() => {
      void pollVeloMonitor(caseId, monitor.id);
    }, seconds * 1000);
    timer.unref?.();
    timers.set(key, timer);
  }

  function stopVeloMonitorTimer(caseId: string, id: string): void {
    const key = monitorKey(caseId, id);
    const timer = timers.get(key);
    if (timer) clearTimeout(timer);
    timers.delete(key);
  }

  // Re-arm timers for every active monitor across all cases (called once at startup so monitoring
  // survives the #1-gotcha restart). Best-effort — a single bad case must not abort the sweep.
  async function resumeVeloMonitors(): Promise<void> {
    const monStore = options.veloMonitorStore;
    if (!monStore || !options.velociraptorClient) return;
    let cases: { caseId: string }[] = [];
    try {
      cases = await store.listCases();
    } catch {
      return;
    }
    let resumed = 0;
    for (const c of cases) {
      try {
        for (const m of await monStore.list(c.caseId)) {
          if (m.status !== "stopped") {
            scheduleVeloMonitor(c.caseId, m);
            resumed++;
          }
        }
      } catch {
        /* skip this case */
      }
    }
    if (resumed > 0)
      logLine(`[velo-monitor] resumed ${resumed} live monitor(s) across ${cases.length} case(s)`);
  }

  // Build + persist + schedule one monitor (shared by the manual start route and the auto-monitor
  // route). `clientId` is a real client (`C....`) or the ALL_CLIENTS sentinel (`*`) for every endpoint.
  // Idempotent per (clientId, artifact): re-arming keeps the existing cursor so events aren't re-ingested;
  // a brand-new monitor starts at "now" (no history backfill). Returns the persisted monitor.
  async function createVeloMonitor(
    caseId: string,
    spec: {
      clientId: string;
      artifact: string;
      pollSeconds: number;
      hostname?: string;
      minSeverity?: Severity;
      allClients?: boolean;
      alreadyEnabled?: boolean;
    },
  ): Promise<VeloMonitor> {
    const monStore = options.veloMonitorStore!;
    const nowEpoch = Math.floor(Date.now() / 1000);
    const id = monitorId(spec.clientId, spec.artifact);
    const existing = await monStore.get(caseId, id);
    // Put the artifact in Velociraptor's Client Monitoring table first (#1409): a monitor for an
    // artifact no client collects polls an empty stream forever while looking healthy. Throws (so the
    // route answers 502 and nothing is persisted) when the table does not take it. A re-armed monitor
    // keeps its "added" mark so the delete path still knows the companion owns the entry.
    const ensured = spec.alreadyEnabled
      ? "present"
      : await ensureClientMonitoring(options.velociraptorClient!, spec.artifact);
    // "present" because ANOTHER companion monitor put it there → this one inherits the "added" mark, so
    // the entry is still released once the last monitor for the artifact is deleted.
    const veloTableEntry =
      ensured === "present" &&
      (await someMonitor((m) => m.artifact === spec.artifact && m.veloTableEntry === "added"))
        ? "added"
        : ensured;
    const monitor: VeloMonitor = {
      id,
      clientId: spec.clientId,
      artifact: spec.artifact,
      pollSeconds: spec.pollSeconds,
      allClients: spec.allClients || undefined,
      hostname: spec.allClients ? spec.hostname || "all clients" : spec.hostname,
      cursor: existing?.cursor && existing.cursor > 0 ? existing.cursor : nowEpoch,
      status: "active",
      minSeverity: spec.minSeverity,
      createdAt: existing?.createdAt ?? new Date().toISOString(),
      addedEvents: existing?.addedEvents ?? 0,
      polls: existing?.polls ?? 0,
      veloTableEntry: existing?.veloTableEntry === "added" ? "added" : veloTableEntry,
    };
    await monStore.upsert(caseId, monitor);
    scheduleVeloMonitor(caseId, monitor);
    options.onVeloMonitor?.(caseId);
    logLine(
      `[velo-monitor] started ${spec.artifact} on ${monitor.hostname || spec.clientId} (every ${spec.pollSeconds}s) for case ${caseId}` +
        (veloTableEntry === "added" ? " — enabled it in Velociraptor's Client Monitoring table" : ""),
    );
    return monitor;
  }

  async function verifyVeloMonitorEnabled(caseId: string, monitor: VeloMonitor): Promise<VeloMonitor> {
    const client = options.velociraptorClient;
    const monStore = options.veloMonitorStore;
    if (!client || !monStore) return monitor;
    if (await isClientMonitoringEnabled(client, monitor.artifact)) return monitor;
    const flagged: VeloMonitor = {
      ...monitor,
      status: "error",
      lastError: `${monitor.artifact} is no longer enabled in Velociraptor → Client Monitoring — no client is collecting it. Start the monitor again to re-enable it.`,
    };
    await monStore.upsert(caseId, flagged);
    options.onVeloMonitor?.(caseId);
    return flagged;
  }

  // True when any persisted monitor, in any case, matches — the cross-case view the table needs,
  // since one Velociraptor entry serves every case.
  async function someMonitor(match: (m: VeloMonitor) => boolean): Promise<boolean> {
    const monStore = options.veloMonitorStore!;
    for (const c of await store.listCases()) {
      for (const m of await monStore.list(c.caseId)) if (match(m)) return true;
    }
    return false;
  }

  async function deleteVeloMonitor(caseId: string, id: string): Promise<void> {
    const monStore = options.veloMonitorStore!;
    const monitor = await monStore.get(caseId, id);
    stopVeloMonitorTimer(caseId, id);
    await monStore.remove(caseId, id);
    options.onVeloMonitor?.(caseId);
    if (!monitor || monitor.veloTableEntry !== "added" || !options.velociraptorClient) return;
    // Another monitor (any case; this one is already removed) still watches the artifact → its entry stays.
    if (await someMonitor((m) => m.artifact === monitor.artifact)) return;
    // Best-effort: the monitor is gone either way; a failed release is logged, not surfaced as a 5xx.
    try {
      await releaseClientMonitoring(options.velociraptorClient, monitor.artifact);
      logLine(`[velo-monitor] removed ${monitor.artifact} from Velociraptor's Client Monitoring table`);
    } catch (err) {
      logLine(
        `[velo-monitor] could not remove ${monitor.artifact} from Client Monitoring: ${(err as Error).message}`,
      );
    }
  }

  return {
    refreshVeloClients,
    createVeloMonitor,
    scheduleVeloMonitor,
    pollVeloMonitor,
    stopVeloMonitorTimer,
    verifyVeloMonitorEnabled,
    deleteVeloMonitor,
    resumeVeloMonitors,
  };
}
