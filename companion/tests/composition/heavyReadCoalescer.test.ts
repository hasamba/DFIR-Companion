import { describe, it, expect, afterEach } from "vitest";
import express, { type Express, type Request, type Response } from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { HEAVY_READ_PATHS, HeavyReadGate, mountHeavyReadGate } from "../../src/composition/heavyReadGate.js";
import {
  COALESCED_PATHS,
  COALESCE_MAX_HELD_BYTES,
  HeavyReadCoalescer,
} from "../../src/composition/heavyReadCoalescer.js";

// #2846: identical heavy reads share one answer while the first one is still queued. Handlers are
// held until released so the overlap is exact, not timed.

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

const servers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

interface Reply {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

/** Larger than any socket buffer, so a paused client keeps its response from finishing. */
const MID_BODY_BYTES = 32 * 1024 * 1024;

function harness(opts: { concurrency?: number } = {}) {
  const gate = new HeavyReadGate({
    concurrency: opts.concurrency ?? 1,
    queueLimit: 10,
    retryAfterSeconds: 2,
  });
  const coalescer = new HeavyReadCoalescer();
  const app: Express = express();
  // A follower's own middleware header, set before the gate (like securityHeaders / originGuard).
  app.use((req, res, next) => {
    res.setHeader("X-Own", String(req.headers["x-tag"] ?? "none"));
    next();
  });
  mountHeavyReadGate(app, gate, coalescer);
  let runs = 0;
  const holds: ReturnType<typeof deferred>[] = [];
  const handler = async (req: Request, res: Response) => {
    const n = ++runs;
    const hold = deferred();
    holds.push(hold);
    await hold.promise;
    if (req.query.fail) return res.destroy(); // the handler gives up without an answer
    if (req.query.mid) {
      res.setHeader("Content-Type", "application/octet-stream");
      return res.end(Buffer.alloc(MID_BODY_BYTES));
    }
    if (req.query.big) {
      res.setHeader("Content-Type", "application/octet-stream");
      return res.end(Buffer.alloc(COALESCE_MAX_HELD_BYTES + 1));
    }
    res.setHeader("X-Own", "handler"); // a representation-independent header the first answer set
    res.setHeader("ETag", `"v${n}"`);
    res.setHeader("Set-Cookie", "session=leader");
    res.status(200).json({ n, q: req.query });
  };
  app.get("/cases/:id/geo-map", handler);
  app.get("/cases/:id/report.docx", handler); // heavy, but a download: never shared
  app.post("/cases/:id/hypotheses", (_req, res) => res.status(200).json({ ok: true }));
  return { app, gate, coalescer, runs: () => runs, holds };
}

async function listen(app: Express): Promise<number> {
  const server = http.createServer(app);
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return (server.address() as AddressInfo).port;
}

function send(
  port: number,
  path: string,
  opts: { method?: string; headers?: http.OutgoingHttpHeaders } = {},
) {
  let req!: http.ClientRequest;
  const reply = new Promise<Reply>((resolve, reject) => {
    req = http.request(
      { host: "127.0.0.1", port, path, method: opts.method ?? "GET", headers: opts.headers, agent: false },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          }),
        );
      },
    );
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

describe("identical heavy reads share one answer (#2846)", () => {
  it("shares only case-open panel reads that the gate covers", () => {
    for (const p of COALESCED_PATHS) expect(HEAVY_READ_PATHS.has(p), p).toBe(true);
    for (const p of ["/report.docx", "/export/stix", "/timeline.jsonl", "/login-graph", "/sigma/regrade"])
      expect(COALESCED_PATHS.has(p), p).toBe(false);
  });

  it("a read identical to a QUEUED one joins it: one handler run, the same answer, no queue place", async () => {
    const h = harness();
    const port = await listen(h.app);
    const other = send(port, "/cases/c1/geo-map?x=other"); // holds the only slot
    await until(() => h.runs() === 1);
    const first = send(port, "/cases/c1/geo-map?x=1");
    await until(() => h.gate.waiting === 1);
    const second = send(port, "/cases/c1/geo-map?x=1", { headers: { "x-tag": "second" } });
    await until(() => h.coalescer.following === 1);
    expect(h.gate.waiting).toBe(1); // the follower took no queue place
    h.holds[0].resolve();
    await until(() => h.runs() === 2);
    h.holds[1].resolve();
    const [, a, b] = [await other.reply, await first.reply, await second.reply];
    expect(h.runs()).toBe(2);
    expect(b.status).toBe(200);
    expect(b.body).toBe(a.body);
    expect(b.headers.etag).toBe(a.headers.etag); // representation headers come from the answer
    expect(b.headers["content-type"]).toBe(a.headers["content-type"]);
    expect(b.headers["x-own"]).toBe("second"); // its own middleware's header is kept
    expect(b.headers["set-cookie"]).toBeUndefined(); // never another caller's cookie
    expect(h.coalescer.heldBytes).toBe(0);
    expect(h.coalescer.following).toBe(0);
  });

  it("a read identical to a RUNNING one does not join it: it reads for itself, after any write before it", async () => {
    const h = harness({ concurrency: 2 });
    const port = await listen(h.app);
    const first = send(port, "/cases/c1/geo-map");
    await until(() => h.runs() === 1);
    const second = send(port, "/cases/c1/geo-map");
    await until(() => h.runs() === 2);
    expect(h.coalescer.following).toBe(0);
    h.holds[0].resolve();
    h.holds[1].resolve();
    const [a, b] = [await first.reply, await second.reply];
    expect(a.body).not.toBe(b.body);
  });

  it("does not share across a different query, caller header, origin, path or case", async () => {
    const h = harness();
    const port = await listen(h.app);
    const blocker = send(port, "/cases/blk/geo-map");
    await until(() => h.runs() === 1);
    const replies = [
      send(port, "/cases/c1/geo-map?x=1"),
      send(port, "/cases/c1/geo-map?x=2"),
      send(port, "/cases/c1/geo-map?x=1", { headers: { "accept-encoding": "gzip" } }),
      send(port, "/cases/c1/geo-map?x=1", { headers: { origin: "http://127.0.0.1:9" } }),
      send(port, "/cases/c1/geo-map?x=1", { headers: { "if-none-match": '"v1"' } }),
      send(port, "/cases/c2/geo-map?x=1"),
    ];
    await until(() => h.gate.waiting === 6);
    expect(h.coalescer.following).toBe(0);
    for (let n = 0; n <= 6; n++) {
      await until(() => h.holds.length > n);
      h.holds[n].resolve();
    }
    await Promise.all([blocker, ...replies].map((r) => r.reply));
    expect(h.runs()).toBe(7);
  });

  it("never shares a download, nor a HEAD", async () => {
    const h = harness();
    const port = await listen(h.app);
    const blocker = send(port, "/cases/blk/geo-map");
    await until(() => h.runs() === 1);
    const replies = [
      send(port, "/cases/c1/report.docx"),
      send(port, "/cases/c1/report.docx"),
      send(port, "/cases/c1/geo-map", { method: "HEAD" }),
      send(port, "/cases/c1/geo-map", { method: "HEAD" }),
    ];
    await until(() => h.gate.waiting === 4);
    expect(h.coalescer.following).toBe(0);
    for (let n = 0; n <= 4; n++) {
      await until(() => h.holds.length > n);
      h.holds[n].resolve();
    }
    await Promise.all([blocker, ...replies].map((r) => r.reply));
  });

  it("when the first read never answers, its follower runs on its own", async () => {
    const h = harness();
    const port = await listen(h.app);
    const blocker = send(port, "/cases/blk/geo-map");
    await until(() => h.runs() === 1);
    const first = send(port, "/cases/c1/geo-map?fail=1");
    await until(() => h.gate.waiting === 1);
    const second = send(port, "/cases/c1/geo-map?fail=1");
    await until(() => h.coalescer.following === 1);
    h.holds[0].resolve();
    await until(() => h.runs() === 2);
    h.holds[1].resolve(); // the first one's handler destroys its response
    await first.reply.catch(() => undefined);
    await until(() => h.runs() === 3); // the follower runs for itself
    expect(h.coalescer.following).toBe(0);
    second.drop();
    h.holds[2].resolve();
    await blocker.reply;
  });

  it("when the first read's client leaves while queued, its follower takes the lead", async () => {
    const h = harness();
    const port = await listen(h.app);
    const blocker = send(port, "/cases/blk/geo-map");
    await until(() => h.runs() === 1);
    const first = send(port, "/cases/c1/geo-map");
    await until(() => h.gate.waiting === 1);
    const second = send(port, "/cases/c1/geo-map");
    await until(() => h.coalescer.following === 1);
    first.drop(); // its queued request never runs
    await until(() => h.coalescer.following === 0 && h.gate.waiting === 1);
    h.holds[0].resolve();
    await until(() => h.runs() === 2);
    h.holds[1].resolve();
    expect((await second.reply).status).toBe(200);
    expect(h.runs()).toBe(2);
    await blocker.reply;
  });

  it("a follower that leaves does not disturb the first read", async () => {
    const h = harness();
    const port = await listen(h.app);
    const blocker = send(port, "/cases/blk/geo-map");
    await until(() => h.runs() === 1);
    const first = send(port, "/cases/c1/geo-map");
    await until(() => h.gate.waiting === 1);
    const second = send(port, "/cases/c1/geo-map");
    await until(() => h.coalescer.following === 1);
    second.drop();
    await until(() => h.coalescer.following === 0);
    h.holds[0].resolve();
    await until(() => h.runs() === 2);
    h.holds[1].resolve();
    expect((await first.reply).status).toBe(200);
    expect(h.runs()).toBe(2);
    await blocker.reply;
  });

  it("an answer too large to keep is not kept: its follower runs on its own", async () => {
    const h = harness();
    const port = await listen(h.app);
    const blocker = send(port, "/cases/blk/geo-map");
    await until(() => h.runs() === 1);
    const first = send(port, "/cases/c1/geo-map?big=1");
    await until(() => h.gate.waiting === 1);
    const second = send(port, "/cases/c1/geo-map?big=1");
    await until(() => h.coalescer.following === 1);
    h.holds[0].resolve();
    await until(() => h.runs() === 2);
    h.holds[1].resolve();
    expect((await first.reply).body.length).toBe(COALESCE_MAX_HELD_BYTES + 1);
    await until(() => h.runs() === 3);
    expect(h.coalescer.heldBytes).toBe(0);
    h.holds[2].resolve();
    expect((await second.reply).body.length).toBe(COALESCE_MAX_HELD_BYTES + 1);
    await blocker.reply;
  }, 30_000);

  it("a replayed answer stays counted until its follower has been sent it", async () => {
    const h = harness();
    const port = await listen(h.app);
    const blocker = send(port, "/cases/blk/geo-map");
    await until(() => h.runs() === 1);
    const first = send(port, "/cases/c1/geo-map?mid=1");
    await until(() => h.gate.waiting === 1);
    // A follower whose client reads nothing: its socket keeps the body until it is drained.
    let slowRes: http.IncomingMessage | undefined;
    const slow = http.request({ host: "127.0.0.1", port, path: "/cases/c1/geo-map?mid=1", agent: false });
    slow.on("response", (r) => {
      slowRes = r;
      r.pause();
    });
    slow.on("error", () => undefined);
    slow.end();
    await until(() => h.coalescer.following === 1);
    h.holds[0].resolve();
    await until(() => h.runs() === 2);
    h.holds[1].resolve();
    await first.reply;
    await until(() => slowRes !== undefined);
    expect(h.coalescer.heldBytes).toBe(MID_BODY_BYTES); // still being sent to the slow client
    slowRes!.resume();
    await new Promise((r) => slowRes!.on("end", r));
    await until(() => h.coalescer.heldBytes === 0);
    await blocker.reply;
  });

  it("keeps nothing once the first read answered with no one waiting", async () => {
    const h = harness();
    const port = await listen(h.app);
    const first = send(port, "/cases/c1/geo-map");
    await until(() => h.runs() === 1);
    h.holds[0].resolve();
    await first.reply;
    expect(h.coalescer.heldBytes).toBe(0);
    expect(h.coalescer.following).toBe(0);
  });
});
