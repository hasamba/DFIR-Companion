import type { VeloMonitor } from "../../analysis/veloMonitorStore.js";

// Pure core of the Velociraptor CLIENT_EVENT poller (#84). The server schedules a timer per active
// monitor; each tick calls pollMonitorOnce, which reads the [cursor, now] window from the client's
// monitoring result set, hands any new rows to the injected ingest fn (which routes them through the
// push/import pipeline), and returns the UPDATED monitor (advanced cursor + stats). Reading + ingesting
// are injected, so this whole loop is unit-tested with no Velociraptor binary and no network.

// Read a monitoring artifact's rows for one client in a half-open-ish time window [start, end] (epoch
// seconds). Returns just the rows (the server's VelociraptorClient.monitorResults adapts to this).
export type MonitorReader = (clientId: string, artifact: string, startEpoch: number, endEpoch: number) => Promise<unknown[]>;

// Ingest the new rows for a monitor; resolves to the number of forensic events actually added (for the
// running "+N events" stat). Throwing is fine — pollMonitorOnce catches it into the monitor's lastError.
export type MonitorIngestor = (monitor: VeloMonitor, rows: unknown[]) => Promise<number>;

export interface PollDeps {
  read: MonitorReader;
  ingest: MonitorIngestor;
  now: () => number;                 // epoch SECONDS (injected → testable / resume-safe)
  defaultLookbackSeconds?: number;    // window start when a monitor has no cursor yet (default = pollSeconds)
  log?: (msg: string) => void;
}

// Common timestamp fields on a Velociraptor monitoring row, in preference order. `_ts` is the
// server-side ingestion time Velociraptor stamps on every monitoring event (epoch seconds) — the most
// reliable cursor. The rest cover artifacts that surface their own event time.
const TIME_FIELDS = ["_ts", "Timestamp", "timestamp", "EventTime", "event_time", "Time", "time"];

function num(v: unknown): number | null {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
}

// Normalize a value to epoch SECONDS. Accepts epoch seconds, epoch millis (auto-detected by magnitude),
// or a parseable date string. Returns null when it can't be read.
export function toEpochSeconds(v: unknown): number | null {
  const n = num(v);
  if (n !== null) {
    // > ~ year 2001 in ms (1e12) but a plausible seconds value never reaches 1e12 until year 33658 →
    // a value that large is milliseconds.
    return n >= 1e12 ? Math.floor(n / 1000) : Math.floor(n);
  }
  if (typeof v === "string") {
    const parsed = Date.parse(v);
    if (Number.isFinite(parsed)) return Math.floor(parsed / 1000);
  }
  return null;
}

// Best event time on a monitoring row, or null when none of the known fields is usable.
export function extractRowTime(row: unknown): number | null {
  if (typeof row !== "object" || row === null) return null;
  const r = row as Record<string, unknown>;
  for (const f of TIME_FIELDS) {
    if (r[f] != null) {
      const t = toEpochSeconds(r[f]);
      if (t !== null) return t;
    }
  }
  return null;
}

// The query window for the next poll. start = the monitor's cursor (last poll's end), or now−lookback
// the first time (no cursor). end = now. Guarded so end ≥ start even if the clock went backwards.
export function computeWindow(monitor: VeloMonitor, nowEpoch: number, defaultLookbackSeconds: number): { start: number; end: number } {
  const start = monitor.cursor && monitor.cursor > 0 ? monitor.cursor : Math.max(0, nowEpoch - defaultLookbackSeconds);
  return { start, end: Math.max(start, nowEpoch) };
}

// The cursor for the next poll: the window end we just queried up to, never going backwards. Boundary
// events re-read on the next window are deduped by the importer (exact time+description), so advancing
// to the window end can't drop events while keeping the window from growing unbounded.
export function nextCursor(prevCursor: number, windowEnd: number): number {
  return Math.max(prevCursor || 0, windowEnd);
}

// Wrap an artifact's rows as the `{ "<Artifact.Name>": [rows] }` artifact-map that detectImportKind →
// importVelociraptor consume — the same shape a bundle-hunt collection produces.
export function monitorArtifactMap(artifact: string, rows: unknown[]): string {
  return JSON.stringify({ [artifact]: rows });
}

// One poll cycle. NEVER throws: a read/ingest failure is captured into the returned monitor's
// lastError + status:"error", and the cursor is NOT advanced (the window retries next tick). On
// success the cursor advances, lastError clears, and the stats update. A stopped monitor is returned
// untouched (the caller shouldn't have scheduled it, but this keeps the loop safe).
export async function pollMonitorOnce(monitor: VeloMonitor, deps: PollDeps): Promise<VeloMonitor> {
  if (monitor.status === "stopped") return monitor;
  const nowEpoch = Math.floor(deps.now());
  const nowIso = new Date(nowEpoch * 1000).toISOString();
  const lookback = deps.defaultLookbackSeconds ?? monitor.pollSeconds;
  const { start, end } = computeWindow(monitor, nowEpoch, lookback);

  try {
    const rows = await deps.read(monitor.clientId, monitor.artifact, start, end);
    let added = 0;
    if (rows.length > 0) {
      added = await deps.ingest(monitor, rows);
    }
    return {
      ...monitor,
      status: "active",
      cursor: nextCursor(monitor.cursor, end),
      lastPolledAt: nowIso,
      ...(added > 0 ? { lastEventAt: nowIso } : {}),
      addedEvents: (monitor.addedEvents ?? 0) + added,
      polls: (monitor.polls ?? 0) + 1,
      lastError: undefined,
    };
  } catch (err) {
    deps.log?.(`[velo-monitor] poll failed (${monitor.clientId} / ${monitor.artifact}): ${(err as Error).message}`);
    return {
      ...monitor,
      status: "error",
      lastPolledAt: nowIso,
      polls: (monitor.polls ?? 0) + 1,
      lastError: (err as Error).message,
      // cursor intentionally NOT advanced — retry the same window next tick
    };
  }
}
