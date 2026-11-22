import { describe, it, expect, afterEach } from "vitest";
import express, { type Express, type Request, type Response } from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { HeavyReadGate, mountHeavyReadGate } from "../../src/composition/heavyReadGate.js";
import { getServerLogger, setServerLogger } from "../../src/logging/serverLogger.js";
import type { Logger } from "../../src/logging/logger.js";
import {
  HEAVY_READ_BUDGET_RECHECK_MS,
  type HeavyReadBudget,
} from "../../src/composition/heavyReadMemoryBudget.js";

// #2846: the heavy-read gate with a memory budget. The budget is stubbed: each case's cost comes from
// `costs`, and `room` is what fits beside the reads already running. No real memory is measured.

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

const servers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

interface StubBudget extends HeavyReadBudget {
  room: number;
}

function stubBudget(costs: Record<string, number>, room: number): StubBudget {
  const b: StubBudget = {
    room,
    estimate: async (caseId) => {
      const cost = costs[caseId];
      if (cost === undefined) throw new Error("unknown case");
      return cost;
    },
    fits: (need, reserved) => need + reserved <= b.room,
  };
  return b;
}

/** /cases/:id/state holds until released; `order` records which case started, in order. */
function harness(gate: HeavyReadGate) {
  const app: Express = express();
  mountHeavyReadGate(app, gate);
  const order: string[] = [];
  const holds = new Map<string, ReturnType<typeof deferred>>();
  app.get("/cases/:id/state", async (req: Request, res: Response) => {
    const id = req.params.id;
    order.push(id);
    const hold = deferred();
    holds.set(id, hold);
    await hold.promise;
    res.status(200).json({ id });
  });
  return { app, order, holds };
}

async function listen(app: Express): Promise<number> {
  const server = http.createServer(app);
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return (server.address() as AddressInfo).port;
}

function get(port: number, path: string) {
  let req!: http.ClientRequest;
  const reply = new Promise<number>((resolve, reject) => {
    req = http.request({ host: "127.0.0.1", port, path, agent: false }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end();
  });
  reply.catch(() => undefined);
  return { reply, drop: () => req.destroy() };
}

async function until(check: () => boolean, ms = 3000): Promise<void> {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error("condition not reached");
    await new Promise((r) => setTimeout(r, 5));
  }
}

const limits = { concurrency: 4, queueLimit: 10, retryAfterSeconds: 2 };

describe("heavy read gate with a memory budget (#2846)", () => {
  it("a read that does not fit beside the running one waits, and starts when that one finishes", async () => {
    const gate = new HeavyReadGate(limits, stubBudget({ a: 6, b: 6 }, 10));
    const h = harness(gate);
    const port = await listen(h.app);
    const a = get(port, "/cases/a/state");
    await until(() => h.order.length === 1);
    const b = get(port, "/cases/b/state");
    await until(() => gate.waiting === 1);
    expect(h.order).toEqual(["a"]);
    expect(gate.reservedBytes).toBe(6);
    h.holds.get("a")!.resolve();
    expect(await a.reply).toBe(200);
    await until(() => h.order.length === 2);
    expect(h.order).toEqual(["a", "b"]);
    h.holds.get("b")!.resolve();
    expect(await b.reply).toBe(200);
    await until(() => gate.active === 0);
    expect(gate.reservedBytes).toBe(0);
  });

  it("reads that fit run side by side, up to the count cap", async () => {
    const gate = new HeavyReadGate({ ...limits, concurrency: 2 }, stubBudget({ a: 1, b: 1, c: 1 }, 100));
    const h = harness(gate);
    const port = await listen(h.app);
    const replies = ["a", "b", "c"].map((id) => get(port, `/cases/${id}/state`));
    await until(() => h.order.length === 2 && gate.waiting === 1);
    for (const id of ["a", "b"]) h.holds.get(id)!.resolve();
    await until(() => h.order.length === 3);
    h.holds.get("c")!.resolve();
    expect(await Promise.all(replies.map((r) => r.reply))).toEqual([200, 200, 200]);
  });

  it("with nothing running, a read that does not fit waits for memory to come back", async () => {
    const budget = stubBudget({ big: 8 }, 4);
    const gate = new HeavyReadGate({ ...limits, idleHoldMs: 60_000 }, budget);
    const h = harness(gate);
    const port = await listen(h.app);
    const r = get(port, "/cases/big/state");
    await until(() => gate.waiting === 1);
    await new Promise((res) => setTimeout(res, HEAVY_READ_BUDGET_RECHECK_MS * 1.5));
    expect(h.order).toEqual([]);
    budget.room = 10; // idle isolates handed their heaps back
    await until(() => h.order.length === 1, HEAVY_READ_BUDGET_RECHECK_MS * 3);
    h.holds.get("big")!.resolve();
    expect(await r.reply).toBe(200);
  });

  it("with nothing running, a read larger than the budget starts after the idle hold: slow, never stuck", async () => {
    const gate = new HeavyReadGate({ ...limits, idleHoldMs: 200 }, stubBudget({ big: 50, big2: 50 }, 10));
    const h = harness(gate);
    const port = await listen(h.app);
    const first = get(port, "/cases/big/state");
    const second = get(port, "/cases/big2/state");
    await until(() => h.order.length === 1 && gate.waiting === 1);
    h.holds.get("big")!.resolve();
    await until(() => h.order.length === 2);
    h.holds.get("big2")!.resolve();
    expect([await first.reply, await second.reply]).toEqual([200, 200]);
  });

  it("a read that waited behind others still gets the full idle hold once nothing is running", async () => {
    const hold = 1_500;
    const gate = new HeavyReadGate({ ...limits, idleHoldMs: hold }, stubBudget({ a: 1, big: 50 }, 10));
    const h = harness(gate);
    const port = await listen(h.app);
    const a = get(port, "/cases/a/state");
    await until(() => h.order.length === 1);
    const big = get(port, "/cases/big/state");
    await until(() => gate.waiting === 1);
    await new Promise((r) => setTimeout(r, hold + 300)); // longer than the hold, behind a running read
    h.holds.get("a")!.resolve();
    expect(await a.reply).toBe(200);
    const released = Date.now();
    await new Promise((r) => setTimeout(r, hold / 3));
    expect(h.order).toEqual(["a"]); // its queue time does not count: memory gets the full hold
    await until(() => h.order.length === 2, hold * 3);
    expect(Date.now() - released).toBeGreaterThanOrEqual(hold - 50);
    h.holds.get("big")!.resolve();
    expect(await big.reply).toBe(200);
  });

  it("keeps arrival order: a small read never jumps a large one held back by the budget", async () => {
    const gate = new HeavyReadGate(limits, stubBudget({ a: 5, large: 8, small: 1 }, 10));
    const h = harness(gate);
    const port = await listen(h.app);
    const a = get(port, "/cases/a/state");
    await until(() => h.order.length === 1);
    const large = get(port, "/cases/large/state");
    await until(() => gate.waiting === 1);
    const small = get(port, "/cases/small/state");
    await until(() => gate.waiting === 2);
    expect(h.order).toEqual(["a"]); // small would fit (5 + 1 <= 10), but large is ahead of it
    h.holds.get("a")!.resolve();
    await until(() => h.order.length === 3);
    expect(h.order).toEqual(["a", "large", "small"]); // large alone, then small beside it (8 + 1)
    h.holds.get("large")!.resolve();
    h.holds.get("small")!.resolve();
    expect([await a.reply, await large.reply, await small.reply]).toEqual([200, 200, 200]);
  });

  it("looks again while a read waits only for memory, and admits it once memory frees", async () => {
    const budget = stubBudget({ a: 6, b: 6 }, 10);
    const gate = new HeavyReadGate(limits, budget);
    const h = harness(gate);
    const port = await listen(h.app);
    const a = get(port, "/cases/a/state");
    await until(() => h.order.length === 1);
    const b = get(port, "/cases/b/state");
    await until(() => gate.waiting === 1);
    budget.room = 20; // garbage collected, another program exited — no read finished
    await until(() => h.order.length === 2, HEAVY_READ_BUDGET_RECHECK_MS * 3);
    expect(gate.reservedBytes).toBe(12);
    h.holds.get("a")!.resolve();
    h.holds.get("b")!.resolve();
    expect([await a.reply, await b.reply]).toEqual([200, 200]);
  });

  it("a case whose size is unknown runs alone, and nothing starts beside it", async () => {
    const gate = new HeavyReadGate(limits, stubBudget({ a: 1, b: 1 }, 100));
    const h = harness(gate);
    const port = await listen(h.app);
    const unknown = get(port, "/cases/nocount/state"); // the stub's estimate rejects
    await until(() => h.order.length === 1);
    const a = get(port, "/cases/a/state");
    await until(() => gate.waiting === 1);
    expect(h.order).toEqual(["nocount"]);
    h.holds.get("nocount")!.resolve();
    await until(() => h.order.length === 2);
    h.holds.get("a")!.resolve();
    expect([await unknown.reply, await a.reply]).toEqual([200, 200]);
    expect(gate.reservedBytes).toBe(0);
  });

  it("a queued read whose client left drops out and never runs; its reservation is never taken", async () => {
    const gate = new HeavyReadGate(limits, stubBudget({ a: 6, b: 6, c: 1 }, 10));
    const h = harness(gate);
    const port = await listen(h.app);
    const a = get(port, "/cases/a/state");
    await until(() => h.order.length === 1);
    const b = get(port, "/cases/b/state");
    await until(() => gate.waiting === 1);
    b.drop();
    await until(() => gate.waiting === 0);
    const c = get(port, "/cases/c/state");
    await until(() => h.order.length === 2);
    expect(h.order).toEqual(["a", "c"]);
    h.holds.get("a")!.resolve();
    h.holds.get("c")!.resolve();
    expect([await a.reply, await c.reply]).toEqual([200, 200]);
  });

  it("a full queue still answers 503 at once", async () => {
    const gate = new HeavyReadGate({ ...limits, queueLimit: 1 }, stubBudget({ a: 6, b: 6, c: 6 }, 10));
    const h = harness(gate);
    const port = await listen(h.app);
    const a = get(port, "/cases/a/state");
    await until(() => h.order.length === 1);
    const b = get(port, "/cases/b/state");
    await until(() => gate.waiting === 1);
    expect(await get(port, "/cases/c/state").reply).toBe(503);
    h.holds.get("a")!.resolve();
    await until(() => h.order.length === 2);
    h.holds.get("b")!.resolve();
    expect([await a.reply, await b.reply]).toEqual([200, 200]);
  });

  it("logs once when reads go one at a time for memory, and once when the wait is over", async () => {
    const lines: string[] = [];
    const real = getServerLogger();
    const capture: Logger = { ...real, info: (m: string) => lines.push(m) };
    setServerLogger(capture);
    try {
      const gate = new HeavyReadGate(limits, stubBudget({ a: 6, b: 6, c: 6 }, 10));
      const h = harness(gate);
      const port = await listen(h.app);
      const replies = ["a", "b", "c"].map((id) => get(port, `/cases/${id}/state`));
      await until(() => h.order.length === 1 && gate.waiting === 2);
      for (const id of ["a", "b", "c"]) {
        await until(() => h.holds.has(id));
        h.holds.get(id)!.resolve();
      }
      expect(await Promise.all(replies.map((r) => r.reply))).toEqual([200, 200, 200]);
      await until(() => gate.active === 0);
      const memory = lines.filter((l) => l.startsWith("[heavy-read]"));
      expect(memory).toHaveLength(2);
      expect(memory[0]).toMatch(/short of memory: case reads wait for memory/);
      expect(memory[1]).toMatch(/memory wait over after \d+s/);
    } finally {
      setServerLogger(real);
    }
  });

  it("logs two lines for a whole memory wait even when two reads fit side by side", async () => {
    const lines: string[] = [];
    const real = getServerLogger();
    setServerLogger({ ...real, info: (m: string) => lines.push(m) });
    try {
      const gate = new HeavyReadGate(limits, stubBudget({ a: 6, b: 6, c: 6, d: 6, e: 6 }, 13));
      const h = harness(gate);
      const port = await listen(h.app);
      const ids = ["a", "b", "c", "d", "e"];
      const replies = ids.map((id) => get(port, `/cases/${id}/state`));
      await until(() => h.order.length === 2 && gate.waiting === 3);
      for (const id of ids) {
        await until(() => h.holds.has(id));
        h.holds.get(id)!.resolve();
      }
      expect(await Promise.all(replies.map((r) => r.reply))).toEqual(ids.map(() => 200));
      await until(() => gate.active === 0);
      const memory = lines.filter((l) => l.startsWith("[heavy-read]"));
      expect(memory).toHaveLength(2);
      expect(memory[0]).toMatch(/2 running/);
    } finally {
      setServerLogger(real);
    }
  });
});
