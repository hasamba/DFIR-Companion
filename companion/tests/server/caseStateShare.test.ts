// #2120: concurrent GET /cases/:id/state requests for the same case and page share one read.
//
// Each request used to run its own overview read plus a page of up to 10k rows, deserialised and
// upgraded on the main thread. They now share one read while it is QUEUED (routes/caseStateRead.ts),
// never one that started before a write a later caller already saw finish, and a queued read whose
// every caller has left is dropped before it starts.
import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import type { AddressInfo } from "node:net";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ClockSkewStore } from "../../src/analysis/clockSkewStore.js";
import { HEAVY_READ_CONCURRENCY } from "../../src/composition/heavyReadGate.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { pollFor, pollBudget } from "../helpers/poll.js";

const CASE = "c1";

const ev = (id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp,
  description: `event ${id}`,
  severity: "Low",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...extra,
});

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    deepFreeze((value as Record<PropertyKey, unknown>)[key], seen);
  }
  return Object.freeze(value);
}

/** A promise the test opens by hand. */
function latch(): { wait: Promise<void>; open: () => void } {
  let open = (): void => undefined;
  const wait = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { wait, open };
}

const servers: http.Server[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(() => r(undefined)))));
});

async function harness(state: Partial<InvestigationState> = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-2120-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const clockSkewStore = new ClockSkewStore(store);
  const app = createApp(store, { aiConfigured: false, stateStore, clockSkewStore });
  await request(app).post("/cases").send({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  await stateStore.save({
    ...emptyState(CASE),
    forensicTimeline: [ev("e1", "2026-06-10T12:00:00Z"), ev("e2", "2026-06-10T12:01:00Z")],
    ...state,
  });
  // Every overview read is held, after it has read the case, until the test opens the latch.
  const hold = latch();
  const realOverview = stateStore.loadOverview.bind(stateStore);
  let held = 0;
  const overviewSpy = vi.spyOn(stateStore, "loadOverview").mockImplementation(async (id: string) => {
    const read = await realOverview(id);
    held++;
    await hold.wait;
    return read;
  });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise((r) => server.once("listening", r));
  const port = (server.address() as AddressInfo).port;
  // Waits until `n` distinct reads have read the case and are parked at the latch (#2172): an
  // observable state, so no fixed sleep has to guess how long that takes on a loaded runner.
  const untilHeld = (n: number): Promise<true> =>
    pollFor(
      () => `${n} overview read(s) held at the latch (saw ${held})`,
      async () => (held >= n ? true : undefined),
      { timeoutMs: pollBudget(5_000) },
    );
  return { app, stateStore, clockSkewStore, overviewSpy, hold, port, realOverview, untilHeld };
}

interface OpenRequest {
  done: Promise<{ status: number; body: Record<string, unknown> } | "aborted">;
  abort: () => void;
}

/** A raw GET on its own socket, so the test can make its client leave mid-request. */
function get(port: number, path: string): OpenRequest {
  const req = http.get({ host: "127.0.0.1", port, path, agent: false });
  const done = new Promise<{ status: number; body: Record<string, unknown> } | "aborted">((resolve) => {
    req.on("response", (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => (text += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: JSON.parse(text) }));
      res.on("error", () => resolve("aborted"));
    });
    req.on("error", () => resolve("aborted"));
  });
  return { done, abort: () => req.destroy() };
}

/**
 * Lets in-flight handlers reach their shared read (case lookup, gate, middleware). Kept only where
 * the server exposes nothing to poll: a co-request joining a queued read, or an abort being
 * processed. A read reaching the latch is polled with `untilHeld` instead (#2172).
 */
const settleIo = (): Promise<void> => new Promise((r) => setTimeout(r, 150));

const statePath = (query = ""): string => `/cases/${CASE}/state${query}`;

describe("GET /cases/:id/state shares concurrent reads (#2120)", () => {
  it("serves a burst for one case and page from at most two reads, with identical bodies", async () => {
    const { overviewSpy, hold, port, untilHeld } = await harness();
    const burst = Array.from({ length: HEAVY_READ_CONCURRENCY }, () => get(port, statePath()));
    await untilHeld(1);
    await settleIo(); // the rest of the burst joins the shared read
    hold.open();
    const results = await Promise.all(burst.map((r) => r.done));
    expect(overviewSpy.mock.calls.length).toBeLessThanOrEqual(2);
    for (const r of results) {
      if (r === "aborted") throw new Error("request aborted");
      expect(r.status).toBe(200);
      expect(r.body).toEqual((results[0] as { body: unknown }).body);
    }
  });

  it("never shares a read between different pages or searches", async () => {
    const { overviewSpy, hold, port, untilHeld } = await harness();
    const queries = [
      "?timelineLimit=1",
      "?timelineLimit=2",
      "?timelineCursor=1",
      // Free analyst text: a delimiter-joined key could make these collide; the JSON key cannot.
      `?q=${encodeURIComponent("a|b")}`,
      `?q=${encodeURIComponent('a","b')}`,
    ];
    const reqs = queries.map((q) => get(port, statePath(q)));
    await untilHeld(Math.min(queries.length, HEAVY_READ_CONCURRENCY));
    hold.open();
    const results = await Promise.all(reqs.map((r) => r.done));
    expect(results.every((r) => r !== "aborted" && r.status === 200)).toBe(true);
    expect(overviewSpy).toHaveBeenCalledTimes(queries.length);
    const limited = results[0] as { body: Record<string, unknown> };
    expect(limited.body.forensicTimeline as unknown[]).toHaveLength(1);
  });

  it("never answers a request made after a write with a read that started before it", async () => {
    const { stateStore, hold, port, realOverview, untilHeld } = await harness();
    const first = get(port, statePath());
    await untilHeld(1); // the first read has read the case and is held
    const current = await realOverview(CASE);
    await stateStore.save({
      ...current,
      forensicTimeline: (await stateStore.queryForensicTimeline(CASE)).entities,
      lastSummary: "written after the first read started",
    });
    const second = get(port, statePath());
    await settleIo();
    hold.open();
    const [a, b] = await Promise.all([first.done, second.done]);
    if (a === "aborted" || b === "aborted") throw new Error("request aborted");
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(b.body.lastSummary).toBe("written after the first read started");
  });

  it("drops a queued read whose every caller has left before it starts", async () => {
    const { overviewSpy, hold, port, untilHeld } = await harness();
    const first = get(port, statePath());
    await untilHeld(1);
    const leavers = [get(port, statePath()), get(port, statePath())];
    await settleIo();
    for (const r of leavers) r.abort();
    await settleIo();
    hold.open();
    const done = await first.done;
    expect(done !== "aborted" && done.status).toBe(200);
    await settleIo();
    expect(overviewSpy).toHaveBeenCalledTimes(1);
  });

  it("keeps a shared queued read for the caller that stayed when another leaves", async () => {
    const { overviewSpy, hold, port, untilHeld } = await harness();
    const first = get(port, statePath());
    await untilHeld(1);
    const leaver = get(port, statePath());
    const stayer = get(port, statePath());
    await settleIo();
    leaver.abort();
    await settleIo();
    hold.open();
    const [a, b] = await Promise.all([first.done, stayer.done]);
    if (a === "aborted" || b === "aborted") throw new Error("request aborted");
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect((b.body.forensicTimeline as unknown[]).length).toBe(2);
    expect(overviewSpy).toHaveBeenCalledTimes(2);
  });

  it("never modifies the shared read while building each caller's view", async () => {
    const at = (min: number): string => `2026-06-10T12:0${min}:00Z`;
    const { stateStore, clockSkewStore, overviewSpy, realOverview, port } = await harness({
      forensicTimeline: [
        ev("e1", at(0), { asset: "WS-01", mitreTechniques: ["T1059", "T1490"] }),
        ev("e2", at(1), { asset: "WS-01", mitreTechniques: ["T1490"] }),
      ],
      mitreTechniques: [
        { id: "T1490", name: "Inhibit System Recovery" },
      ] as InvestigationState["mitreTechniques"],
      rejectedTechniques: ["T1059"],
      eventAliases: { old1: "e1" },
    });
    await clockSkewStore.setOverride(CASE, "WS-01", 60_000);
    await clockSkewStore.setAlign(CASE, true);
    const realPage = stateStore.queryForensicTimeline.bind(stateStore);
    vi.spyOn(stateStore, "queryForensicTimeline").mockImplementation(async (...args) =>
      deepFreeze(await realPage(...args)),
    );
    overviewSpy.mockImplementation(async (id: string) => deepFreeze(await realOverview(id)));
    const reqs = [get(port, statePath()), get(port, statePath())];
    const results = await Promise.all(reqs.map((r) => r.done));
    for (const r of results) {
      if (r === "aborted") throw new Error("request aborted");
      expect(r.status).toBe(200);
      const events = r.body.forensicTimeline as ForensicEvent[];
      expect(events.flatMap((e) => e.mitreTechniques)).not.toContain("T1059");
      expect(events.some((e) => e.originalTimestamp)).toBe(true);
      expect(r.body.eventAliases).toBeUndefined();
    }
  });
});
