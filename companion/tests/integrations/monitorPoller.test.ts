import { describe, it, expect } from "vitest";
import {
  toEpochSeconds, extractRowTime, computeWindow, nextCursor, monitorArtifactMap, pollMonitorOnce,
  type PollDeps,
} from "../../src/integrations/velociraptor/monitorPoller.js";
import type { VeloMonitor } from "../../src/analysis/veloMonitorStore.js";

function mon(over: Partial<VeloMonitor> = {}): VeloMonitor {
  return {
    id: "C.1__Windows.Events.ProcessCreation",
    clientId: "C.1",
    artifact: "Windows.Events.ProcessCreation",
    pollSeconds: 30,
    cursor: 1000,
    status: "active",
    createdAt: "2026-06-13T00:00:00.000Z",
    ...over,
  };
}

describe("monitorPoller pure helpers", () => {
  it("toEpochSeconds normalizes seconds, millis, and ISO strings", () => {
    expect(toEpochSeconds(1_700_000_000)).toBe(1_700_000_000);
    expect(toEpochSeconds(1_700_000_000_000)).toBe(1_700_000_000);   // millis → seconds
    expect(toEpochSeconds("2021-11-14T22:13:20.000Z")).toBe(1_636_928_000);
    expect(toEpochSeconds("not a date")).toBeNull();
    expect(toEpochSeconds(null)).toBeNull();
  });

  it("extractRowTime reads common Velociraptor time fields (prefers _ts)", () => {
    expect(extractRowTime({ _ts: 1500, Timestamp: 9999 })).toBe(1500);
    expect(extractRowTime({ Timestamp: "2021-11-14T22:13:20Z" })).toBe(1_636_928_000);
    expect(extractRowTime({ nope: 1 })).toBeNull();
    expect(extractRowTime("scalar")).toBeNull();
  });

  it("computeWindow uses the cursor as start, now as end", () => {
    expect(computeWindow(mon({ cursor: 1000 }), 2000, 30)).toEqual({ start: 1000, end: 2000 });
  });

  it("computeWindow falls back to now−lookback when there is no cursor", () => {
    expect(computeWindow(mon({ cursor: 0 }), 2000, 30)).toEqual({ start: 1970, end: 2000 });
  });

  it("computeWindow never inverts the window", () => {
    expect(computeWindow(mon({ cursor: 5000 }), 2000, 30)).toEqual({ start: 5000, end: 5000 });
  });

  it("nextCursor never goes backwards", () => {
    expect(nextCursor(1000, 2000)).toBe(2000);
    expect(nextCursor(3000, 2000)).toBe(3000);
  });

  it("monitorArtifactMap wraps rows as an artifact-map", () => {
    expect(JSON.parse(monitorArtifactMap("A.B", [{ x: 1 }]))).toEqual({ "A.B": [{ x: 1 }] });
  });
});

describe("pollMonitorOnce", () => {
  const baseDeps = (over: Partial<PollDeps> = {}): PollDeps => ({
    read: async () => [],
    ingest: async () => 0,
    now: () => 2000,
    ...over,
  });

  it("advances the cursor + records stats on a successful poll with rows", async () => {
    let ingested: unknown[] = [];
    const deps = baseDeps({
      read: async (_c, _a, start, end) => { expect(start).toBe(1000); expect(end).toBe(2000); return [{ _ts: 1500 }, { _ts: 1900 }]; },
      ingest: async (_m, rows) => { ingested = rows; return rows.length; },
    });
    const out = await pollMonitorOnce(mon({ cursor: 1000, addedEvents: 3, polls: 2 }), deps);
    expect(ingested).toHaveLength(2);
    expect(out.status).toBe("active");
    expect(out.cursor).toBe(2000);          // advanced to window end
    expect(out.addedEvents).toBe(5);        // 3 + 2
    expect(out.polls).toBe(3);
    expect(out.lastEventAt).toBe(new Date(2000 * 1000).toISOString());
    expect(out.lastError).toBeUndefined();
  });

  it("does NOT call ingest when there are no rows, but still advances the cursor", async () => {
    let ingestCalls = 0;
    const out = await pollMonitorOnce(mon({ cursor: 1000 }), baseDeps({ ingest: async () => { ingestCalls++; return 0; } }));
    expect(ingestCalls).toBe(0);
    expect(out.cursor).toBe(2000);
    expect(out.lastEventAt).toBeUndefined();
    expect(out.polls).toBe(1);
  });

  it("captures a read error WITHOUT advancing the cursor (retries next tick)", async () => {
    const out = await pollMonitorOnce(mon({ cursor: 1000 }), baseDeps({ read: async () => { throw new Error("velo down"); } }));
    expect(out.status).toBe("error");
    expect(out.lastError).toBe("velo down");
    expect(out.cursor).toBe(1000);          // unchanged
  });

  it("captures an ingest error WITHOUT advancing the cursor", async () => {
    const out = await pollMonitorOnce(mon({ cursor: 1000 }), baseDeps({
      read: async () => [{ _ts: 1500 }],
      ingest: async () => { throw new Error("import failed"); },
    }));
    expect(out.status).toBe("error");
    expect(out.lastError).toBe("import failed");
    expect(out.cursor).toBe(1000);
  });

  it("leaves a stopped monitor untouched", async () => {
    const m = mon({ status: "stopped" });
    expect(await pollMonitorOnce(m, baseDeps())).toEqual(m);
  });
});
