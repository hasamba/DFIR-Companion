import { describe, it, expect, afterEach, vi } from "vitest";
import express, { type Express, type Request, type Response } from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import {
  HEAVY_READ_CONCURRENCY,
  HEAVY_READ_PATHS,
  HEAVY_READ_QUEUE_LIMIT,
  HEAVY_READ_RETRY_AFTER_SECONDS,
  HeavyReadGate,
  SERVER_BUSY_HEADER,
  mountHeavyReadGate,
} from "../../src/composition/heavyReadGate.js";
import { clientGone, requestAbortSignal } from "../../src/http/requestAbort.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ScopeStore } from "../../src/analysis/scope.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { HostScopeStore } from "../../src/analysis/hostScopeStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { trackedWork } from "../../src/analysis/pendingWork.js";
import { wholeCaseLoads } from "../../src/analysis/wholeCaseLoadLimit.js";

// #1915 (reopened): a burst of whole-case reads must not build an unbounded backlog of main-thread
// work. The heavy whole-case GETs are admitted a few at a time; a bounded queue holds the rest; a full
// queue answers 503 + Retry-After at once; a queued request whose client went away never runs; and
// /health, which the gate never covers, keeps answering.

function deferred<T = void>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

const servers: http.Server[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

/** A small app: the gate, then /health and a gated /state whose every call waits on its own gate. */
function harness(gate: HeavyReadGate) {
  const app: Express = express();
  mountHeavyReadGate(app, gate);
  const started: number[] = [];
  const holds: ReturnType<typeof deferred<void>>[] = [];
  let calls = 0;
  app.get("/health", (_req: Request, res: Response) => res.status(200).json({ ok: true }));
  app.get("/cases/:id/state", (req: Request, _res: Response, next) => {
    if (req.query.throw) throw new Error("boom"); // Express answers 500 for a synchronous throw
    next();
  });
  app.get("/cases/:id/state", async (req: Request, res: Response) => {
    const n = calls++;
    started.push(n);
    const hold = deferred();
    holds.push(hold);
    // ?tracked=1: the wait is uncancellable work (like a whole-case load) the gate must wait out.
    await (req.query.tracked ? trackedWork(() => hold.promise) : hold.promise);
    if (clientGone(res)) return;
    res.status(200).json({ n });
  });
  app.post("/cases/:id/state", (_req, res) => res.status(200).json({ post: true }));
  app.get("/cases/:id/findings", (_req, res) => res.status(200).json({ light: true }));
  return { app, started, holds };
}

async function listen(app: Express): Promise<number> {
  const server = http.createServer(app);
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return (server.address() as AddressInfo).port;
}

interface Reply {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  ms: number;
}

/** A GET whose client can be dropped mid-flight; `reply` settles when the answer arrives. */
function get(port: number, path: string, method = "GET") {
  const at = Date.now();
  let req!: http.ClientRequest;
  const reply = new Promise<Reply>((resolve, reject) => {
    req = http.request({ host: "127.0.0.1", port, path, method, agent: false }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body, ms: Date.now() - at }),
      );
    });
    req.on("error", reject);
    req.end();
  });
  return { reply, drop: () => req.destroy() };
}

async function until(check: () => boolean, ms = 2000): Promise<void> {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error("condition not reached");
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe("heavy read gate (#1915)", () => {
  it("(a) a queued request whose client disconnected never runs its handler", async () => {
    const gate = new HeavyReadGate({ concurrency: 1, queueLimit: 4, retryAfterSeconds: 2 });
    const h = harness(gate);
    const port = await listen(h.app);
    const first = get(port, "/cases/c1/state");
    await until(() => h.started.length === 1);
    const queued = get(port, "/cases/c1/state");
    queued.reply.catch(() => undefined);
    await until(() => gate.waiting === 1);
    queued.drop();
    await until(() => gate.waiting === 0);
    h.holds[0].resolve();
    expect((await first.reply).status).toBe(200);
    await until(() => gate.active === 0);
    expect(h.started).toEqual([0]); // the dropped request never reached the handler
  });

  it("(b) a full queue answers 503 with Retry-After at once", async () => {
    const gate = new HeavyReadGate({ concurrency: 1, queueLimit: 1, retryAfterSeconds: 2 });
    const h = harness(gate);
    const port = await listen(h.app);
    const running = get(port, "/cases/c1/state");
    await until(() => h.started.length === 1);
    const waiting = get(port, "/cases/c1/state");
    await until(() => gate.waiting === 1);
    const refused = await get(port, "/cases/c1/state").reply;
    expect(refused.status).toBe(503);
    expect(refused.headers["retry-after"]).toBe("2");
    expect(refused.headers[SERVER_BUSY_HEADER.toLowerCase()]).toBe("1");
    expect(JSON.parse(refused.body).error).toMatch(/busy/i);
    expect(refused.ms).toBeLessThan(500);
    h.holds[0].resolve();
    await until(() => h.holds.length === 2);
    h.holds[1].resolve();
    expect((await running.reply).status).toBe(200);
    expect((await waiting.reply).status).toBe(200);
  });

  it("(c) /health answers fast while the gate is saturated", async () => {
    const gate = new HeavyReadGate({ concurrency: 1, queueLimit: 1, retryAfterSeconds: 2 });
    const h = harness(gate);
    const port = await listen(h.app);
    const running = get(port, "/cases/c1/state");
    const waiting = get(port, "/cases/c1/state");
    await until(() => gate.active === 1 && gate.waiting === 1);
    const health = await get(port, "/health").reply;
    expect(health.status).toBe(200);
    expect(health.ms).toBeLessThan(200);
    // Ungated routes and writes pass straight through a saturated gate.
    expect((await get(port, "/cases/c1/findings").reply).status).toBe(200);
    expect((await get(port, "/cases/c1/state", "POST").reply).status).toBe(200);
    h.holds[0].resolve();
    await until(() => h.holds.length === 2);
    h.holds[1].resolve();
    await Promise.all([running.reply, waiting.reply]);
  });

  it("(d) a slot is released when the handler throws", async () => {
    const gate = new HeavyReadGate({ concurrency: 1, queueLimit: 1, retryAfterSeconds: 2 });
    const h = harness(gate);
    const port = await listen(h.app);
    expect((await get(port, "/cases/c1/state?throw=1").reply).status).toBe(500);
    await until(() => gate.active === 0);
    const next = get(port, "/cases/c1/state");
    await until(() => h.holds.length === 1);
    h.holds[0].resolve();
    expect((await next.reply).status).toBe(200);
  });

  it("(d) a disconnected request with no uncancellable work pending passes its slot on at once", async () => {
    const gate = new HeavyReadGate({ concurrency: 1, queueLimit: 1, retryAfterSeconds: 2 });
    const h = harness(gate);
    const port = await listen(h.app);
    const gone = get(port, "/cases/c1/state");
    gone.reply.catch(() => undefined);
    await until(() => h.started.length === 1);
    const next = get(port, "/cases/c1/state");
    await until(() => gate.waiting === 1);
    gone.drop();
    await until(() => h.started.length === 2); // the slot passed on without waiting for the handler
    h.holds[1].resolve();
    expect((await next.reply).status).toBe(200);
    h.holds[0].resolve(); // the abandoned handler wakes, sees its client gone, writes nothing
    await until(() => gate.active === 0);
  });

  it("(e) an abandoned request keeps its slot until its uncancellable work settles", async () => {
    const gate = new HeavyReadGate({ concurrency: 1, queueLimit: 1, retryAfterSeconds: 2 });
    const h = harness(gate);
    const port = await listen(h.app);
    const gone = get(port, "/cases/c1/state?tracked=1");
    gone.reply.catch(() => undefined);
    await until(() => h.started.length === 1);
    const next = get(port, "/cases/c1/state");
    await until(() => gate.waiting === 1);
    gone.drop();
    await new Promise((r) => setTimeout(r, 50));
    expect(h.started).toEqual([0]); // the abandoned load still runs: its slot is not handed on
    expect(gate.active).toBe(1);
    h.holds[0].resolve();
    await until(() => h.started.length === 2);
    h.holds[1].resolve();
    expect((await next.reply).status).toBe(200);
    await until(() => gate.active === 0 && gate.waiting === 0);
  });

  it("(e) a slot held for abandoned work is released after the safety-net hold even if it never settles", async () => {
    const gate = new HeavyReadGate({
      concurrency: 1,
      queueLimit: 1,
      retryAfterSeconds: 2,
      abandonedMaxHoldMs: 60,
    });
    const h = harness(gate);
    const port = await listen(h.app);
    const gone = get(port, "/cases/c1/state?tracked=1");
    gone.reply.catch(() => undefined);
    await until(() => h.started.length === 1);
    const next = get(port, "/cases/c1/state");
    await until(() => gate.waiting === 1);
    gone.drop();
    await until(() => h.started.length === 2); // never settled, but the slot did not leak
    h.holds[1].resolve();
    expect((await next.reply).status).toBe(200);
    h.holds[0].resolve();
    await until(() => gate.active === 0);
  });

  it("the request's abort signal fires when its client disconnects", async () => {
    const app = express();
    const aborted = deferred<boolean>();
    app.get("/slow", (_req, res) => {
      const signal = requestAbortSignal(res);
      signal.addEventListener("abort", () => aborted.resolve(clientGone(res)));
    });
    const port = await listen(app);
    const r = get(port, "/slow");
    r.reply.catch(() => undefined);
    await new Promise((x) => setTimeout(x, 30));
    r.drop();
    expect(await aborted.promise).toBe(true);
  });

  it("normal use: one dashboard's whole fan-out of heavy reads is never refused", async () => {
    // One case open fires 33 heavy reads. 17 since #2119: /state, plus the panel loaders asset-graph,
    // evidence-graph, lateral-paths, phases, timeline-gaps, beacon-candidates, anomalies,
    // adversary-hints, host-ranking, d3fend-countermeasures, attack-mitigations, geo-map, swimlane,
    // ioc-sources, ioc-provenance and ioc-provenance-chain. 16 more since #2121, the panel loaders
    // with their own whole-case load: ioc-risk, customer-exposure, cockpit, sessions,
    // campaign-scope, served-exposure, kerberoast-chain, tls-graph, sensitive-access,
    // playbook-match, hypotheses, host-scope, host-duplicates, second-look/preview, known-unknowns
    // and login-graph. compliance, handoff and intel-retirement moved to the overview load (#2127)
    // and are no longer gated. Two such fan-outs together must still fit, so an analyst never sees
    // "server busy".
    const DASHBOARD_FANOUT = 33;
    expect(HEAVY_READ_CONCURRENCY + HEAVY_READ_QUEUE_LIMIT).toBeGreaterThanOrEqual(2 * DASHBOARD_FANOUT);
    const gate = new HeavyReadGate();
    const app = express();
    mountHeavyReadGate(app, gate);
    let peak = 0;
    let running = 0;
    const paths = [...HEAVY_READ_PATHS];
    app.get(
      paths.map((p) => `/cases/:id${p}`),
      async (_req, res) => {
        running++;
        peak = Math.max(peak, running);
        await new Promise((r) => setTimeout(r, 20));
        running--;
        res.status(200).json({ ok: true });
      },
    );
    const port = await listen(app);
    const replies = await Promise.all(
      Array.from(
        { length: 2 * DASHBOARD_FANOUT },
        (_, i) => get(port, `/cases/c1${paths[i % paths.length]}`).reply,
      ),
    );
    expect(replies.map((r) => r.status)).toEqual(replies.map(() => 200));
    expect(peak).toBeLessThanOrEqual(HEAVY_READ_CONCURRENCY);
    expect(HEAVY_READ_RETRY_AFTER_SECONDS).toBeGreaterThan(0);
  });

  it("matches the path the way Express routes it: any case, trailing slash, HEAD", async () => {
    const gate = new HeavyReadGate({ concurrency: 1, queueLimit: 1, retryAfterSeconds: 2 });
    const h = harness(gate);
    const port = await listen(h.app);
    const running = get(port, "/cases/c1/state");
    const waiting = get(port, "/cases/c2/STATE/");
    await until(() => gate.active === 1 && gate.waiting === 1);
    expect((await get(port, "/cases/c3/state", "HEAD").reply).status).toBe(503);
    h.holds[0].resolve();
    await until(() => h.holds.length === 2);
    h.holds[1].resolve();
    await Promise.all([running.reply, waiting.reply]);
  });
});

describe("heavy read gate in the real app (#1915 over #2057)", () => {
  it("is mounted above every route it covers (a gate only covers what is registered after it)", () => {
    const inventory = JSON.parse(
      readFileSync(new URL("../architecture/route-inventory.json", import.meta.url), "utf8"),
    ) as { stack: string[] };
    const gateAt = inventory.stack.findIndex((l) => l.endsWith(" heavyReadGate/3"));
    expect(gateAt).toBeGreaterThan(-1);
    for (const path of HEAVY_READ_PATHS) {
      const routeAt = inventory.stack.findIndex((l) => l === `ROUTE GET /cases/:id${path}`);
      expect(routeAt, path).toBeGreaterThan(gateAt);
    }
  });

  it("covers every whole-case report read the dashboard and exports fire (#2119)", () => {
    const covered = [
      ...["/state", "/swimlane", "/ioc-sources", "/timeline-gaps", "/export/ioc-blocklist", "/export/stix"],
      ...["/report/interactive", "/asset-graph", "/evidence-graph", "/lateral-paths", "/phases"],
      ...["/beacon-candidates", "/anomalies", "/host-ranking", "/d3fend-countermeasures"],
      ...["/attack-mitigations", "/geo-map", "/geo-map.csv", "/attack-layer.json", "/adversary-hints"],
      ...["/mobile-summary", "/presentation", "/present/export", "/incident-timeline.csv"],
      ...["/timeline.jsonl", "/report.docx", "/timesketch-omitted", "/ioc-provenance"],
      "/ioc-provenance-chain",
      // #2121: the case-open panel loaders that call stateStore.load() (or scan the super-timeline).
      ...["/ioc-risk", "/customer-exposure", "/cockpit", "/sessions"],
      ...["/campaign-scope", "/served-exposure", "/kerberoast-chain", "/tls-graph"],
      ...["/sensitive-access", "/playbook-match", "/hypotheses", "/host-scope", "/host-duplicates"],
      ...["/second-look/preview", "/known-unknowns", "/login-graph"],
    ];
    for (const path of covered) expect(HEAVY_READ_PATHS, path).toContain(path);
    // A pre-generated report file is a disk read, and the super-timeline is a paged, interactive
    // query with its own count ceiling (#2069): neither waits behind the case-open fan-out.
    for (const path of ["/report/report.md", "/report/report.html", "/super-timeline"])
      expect(HEAVY_READ_PATHS.has(path), path).toBe(false);
    // The overview load, no forensic rows (#2127): a findings-only panel does not queue behind the
    // case-open fan-out. Re-adding one here is a deliberate change, not drift.
    for (const path of ["/compliance", "/handoff", "/intel-retirement"])
      expect(HEAVY_READ_PATHS.has(path), path).toBe(false);
  });

  it("a report file and the super-timeline still answer while the gate is saturated", async () => {
    const gate = new HeavyReadGate({ concurrency: 1, queueLimit: 0, retryAfterSeconds: 2 });
    const h = harness(gate);
    h.app.get("/cases/:id/report/:file", (_req, res) => res.status(200).send("md"));
    h.app.get("/cases/:id/super-timeline", (_req, res) => res.status(200).json({ rows: [] }));
    const port = await listen(h.app);
    const running = get(port, "/cases/c1/state");
    await until(() => gate.active === 1);
    expect((await get(port, "/cases/c1/anomalies").reply).status).toBe(503);
    expect((await get(port, "/cases/c1/report/report.md").reply).status).toBe(200);
    expect((await get(port, "/cases/c1/super-timeline").reply).status).toBe(200);
    h.holds[0].resolve();
    await running.reply;
  });

  it("a gated report read whose client left skips serialising its answer and passes its slot on", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-heavy-gone-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore, {
      scope: new ScopeStore(store),
      falsePositives: new FalsePositiveStore(store),
    });
    const hold = deferred<unknown>();
    const signals: (AbortSignal | undefined)[] = [];
    const anomalies = vi.spyOn(reportWriter, "anomalies").mockImplementation(async (_id, signal) => {
      signals.push(signal);
      return (await hold.promise) as Awaited<ReturnType<ReportWriter["anomalies"]>>;
    });
    const gate = new HeavyReadGate({ concurrency: 1, queueLimit: 4, retryAfterSeconds: 2 });
    const app = express();
    mountHeavyReadGate(app, gate);
    const inner = createApp(store, { stateStore, reportWriter });
    await request(inner)
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    app.use(inner);
    const port = await listen(app);
    const gone = get(port, "/cases/c1/anomalies");
    gone.reply.catch(() => undefined);
    await until(() => anomalies.mock.calls.length === 1);
    const next = get(port, "/cases/c1/anomalies");
    await until(() => gate.waiting === 1);
    gone.drop();
    await until(() => anomalies.mock.calls.length === 2); // the slot passed on
    expect(signals[0]?.aborted).toBe(true); // the shared load wait ends for the caller who left
    const serialise = vi.fn(() => ({ spikes: [] }));
    hold.resolve({ toJSON: serialise });
    expect((await next.reply).status).toBe(200);
    expect(serialise).toHaveBeenCalledTimes(1); // only the caller still connected got an answer
  });

  it("repeated disconnects on the covered report paths keep pending work bounded by the gate (#1915)", async () => {
    // These handlers run whole-case loads that ignore the request's abort signal (geo-map, its CSV,
    // lateral paths, the ATT&CK layer, the presentation). A slot freed at socket close let each
    // disconnect start another one while the last stayed queued in the load limiter: a probe left 58
    // loads queued while the gate reported none. The real app and its own gate, nothing stubbed but a
    // slower load.
    const root = await mkdtemp(join(tmpdir(), "dfir-heavy-abandon-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore, {
      scope: new ScopeStore(store),
      falsePositives: new FalsePositiveStore(store),
    });
    const admit = vi.spyOn(HeavyReadGate.prototype, "admit");
    const app = createApp(store, { stateStore, reportWriter });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(emptyState("c1"));
    expect((await request(app).get("/cases/c1/geo-map")).status).toBe(200);
    const gate = admit.mock.contexts[0] as HeavyReadGate; // the app's own gate
    const slow = stateStore as unknown as { loadState: (...a: unknown[]) => Promise<unknown> };
    const loadState = slow.loadState.bind(stateStore);
    vi.spyOn(slow, "loadState").mockImplementation(async (...a: unknown[]) => {
      await new Promise((r) => setTimeout(r, 100));
      return loadState(...a);
    });
    const port = await listen(app);

    let peakGate = 0;
    let peakLoads = 0;
    const sample = setInterval(() => {
      peakGate = Math.max(peakGate, gate.active + gate.waiting);
      peakLoads = Math.max(peakLoads, wholeCaseLoads.active + wholeCaseLoads.waiting);
    }, 1);
    const idle = (): boolean =>
      gate.active === 0 && gate.waiting === 0 && wholeCaseLoads.active === 0 && wholeCaseLoads.waiting === 0;
    try {
      const paths = ["/geo-map", "/geo-map.csv", "/lateral-paths", "/attack-layer.json", "/presentation"];
      // A fixed number of bursts, each dropped once its requests are in flight (not a poll loop).
      const inFlight = (): Promise<void> => new Promise((r) => setTimeout(r, 25));
      for (let round = 0; round < 15; round++) {
        const burst = [...paths, ...paths].map((p) => get(port, `/cases/c1${p}`));
        for (const r of burst) r.reply.catch(() => undefined);
        await inFlight();
        for (const r of burst) r.drop();
      }
      const health = await get(port, "/health").reply;
      expect(health.status).toBe(200);
      expect(health.ms).toBeLessThan(500);
      await until(idle, 10_000);
    } finally {
      clearInterval(sample);
    }
    expect(peakGate).toBeLessThanOrEqual(HEAVY_READ_CONCURRENCY + HEAVY_READ_QUEUE_LIMIT);
    // Every load queued or running belongs to a request still holding a slot: at most one per slot.
    expect(peakLoads).toBeGreaterThan(0);
    expect(peakLoads).toBeLessThanOrEqual(HEAVY_READ_CONCURRENCY);
    // And the gate still serves a live caller afterwards: no slot leaked.
    expect((await get(port, "/cases/c1/geo-map").reply).status).toBe(200);
    await until(idle);
  });

  it("a case-open panel read whose client left drops its queued whole-case load and frees its slot (#2121)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-heavy-panel-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const admit = vi.spyOn(HeavyReadGate.prototype, "admit");
    const app = createApp(store, { stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(emptyState("c1"));
    expect((await request(app).get("/cases/c1/sessions")).status).toBe(200);
    // #2126: that read kept the case's state for the panels; an edit makes the next read load afresh.
    await stateStore.save(emptyState("c1"));
    const gate = admit.mock.contexts[0] as HeavyReadGate; // the app's own gate
    const reads = vi.spyOn(stateStore as unknown as { loadState: () => Promise<unknown> }, "loadState");
    const port = await listen(app);
    // Both load permits held elsewhere, so each route's whole-case load waits in the limiter.
    const busy = [deferred(), deferred()];
    const holders = busy.map((b) => wholeCaseLoads.run(() => b.promise));
    try {
      for (const path of ["/sessions", "/ioc-risk", "/customer-exposure", "/cockpit"]) {
        const gone = get(port, `/cases/c1${path}`);
        gone.reply.catch(() => undefined);
        await until(() => wholeCaseLoads.waiting === 1);
        expect(gate.active, path).toBe(1);
        gone.drop();
        // The queued load is dropped, so the slot is free while the permits are still held.
        await until(() => wholeCaseLoads.waiting === 0 && gate.active === 0);
      }
    } finally {
      busy.forEach((b) => b.resolve());
      await Promise.all(holders);
    }
    expect(reads).not.toHaveBeenCalled(); // no load ever ran for a client that had gone
    expect((await get(port, "/cases/c1/sessions").reply).status).toBe(200);
  });

  // #2128: the routes that reach the whole-case load through a helper (the host-scope loader, the
  // second-look sweep, the known-unknowns block) dropped the request signal on the way down, so their
  // queued load still ran for a client that had left.
  it("an indirect case-open panel read whose client left drops its queued whole-case load too (#2128)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-heavy-indirect-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const admit = vi.spyOn(HeavyReadGate.prototype, "admit");
    const app = createApp(store, {
      stateStore,
      pipeline,
      aiConfigured: false,
      superTimelineStore: new SuperTimelineStore(store),
      hostScopeStore: new HostScopeStore(store),
      assetOverridesStore: new AssetOverridesStore(store),
      hostDuplicateDismissalStore: new HostDuplicateDismissalStore(store),
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(emptyState("c1"));
    expect((await request(app).get("/cases/c1/sessions")).status).toBe(200);
    // #2126: that read kept the case's state for the panels; an edit makes the next read load afresh.
    await stateStore.save(emptyState("c1"));
    const gate = admit.mock.contexts[0] as HeavyReadGate; // the app's own gate
    const reads = vi.spyOn(stateStore as unknown as { loadState: () => Promise<unknown> }, "loadState");
    const port = await listen(app);
    const paths = ["/host-scope", "/host-duplicates", "/second-look/preview", "/known-unknowns"];
    const busy = [deferred(), deferred()];
    const holders = busy.map((b) => wholeCaseLoads.run(() => b.promise));
    try {
      for (const path of paths) {
        const gone = get(port, `/cases/c1${path}`);
        gone.reply.catch(() => undefined);
        await until(() => wholeCaseLoads.waiting === 1);
        expect(gate.active, path).toBe(1);
        gone.drop();
        await until(() => wholeCaseLoads.waiting === 0 && gate.active === 0);
      }
    } finally {
      busy.forEach((b) => b.resolve());
      await Promise.all(holders);
    }
    expect(reads).not.toHaveBeenCalled();
    for (const path of paths) expect((await get(port, `/cases/c1${path}`).reply).status, path).toBe(200);
  });

  // #2126: the case-open panels share one full-state load. The load is tracked work on the request
  // that STARTED it, so that request's slot is held until the load settles, client gone or not. A
  // request that JOINED it frees its slot as soon as its own wait ends: the load is already counted.
  it("a departed joiner frees its slot at once; the starter's slot holds until the shared load settles (#2126)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-heavy-shared-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const admit = vi.spyOn(HeavyReadGate.prototype, "admit");
    const app = createApp(store, { stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(emptyState("c1"));
    expect((await request(app).get("/cases/c1/kerberoast-chain")).status).toBe(200);
    await stateStore.save(emptyState("c1")); // a fresh revision: the next panel read loads afresh
    const gate = admit.mock.contexts[0] as HeavyReadGate;
    const reads = vi.spyOn(stateStore as unknown as { loadState: () => Promise<unknown> }, "loadState");
    const port = await listen(app);
    const busy = [deferred(), deferred()];
    const holders = busy.map((b) => wholeCaseLoads.run(() => b.promise));
    try {
      const starter = get(port, "/cases/c1/kerberoast-chain");
      starter.reply.catch(() => undefined);
      await until(() => wholeCaseLoads.waiting === 1);
      const joiner = get(port, "/cases/c1/campaign-scope");
      joiner.reply.catch(() => undefined);
      await until(() => gate.active === 2);
      expect(wholeCaseLoads.waiting).toBe(1); // one shared load for both
      joiner.drop();
      await until(() => gate.active === 1); // the joiner's slot is free at once
      expect(wholeCaseLoads.waiting).toBe(1); // and the load the starter waits for runs on
      const stayer = get(port, "/cases/c1/campaign-scope");
      await until(() => gate.active === 2);
      starter.drop();
      await new Promise((r) => setTimeout(r, 50));
      expect(gate.active).toBe(2); // the starter's slot holds: its load is still queued for the stayer
      busy.forEach((b) => b.resolve());
      expect((await stayer.reply).status).toBe(200);
      await until(() => gate.active === 0);
    } finally {
      busy.forEach((b) => b.resolve());
      await Promise.all(holders);
    }
    expect(reads).toHaveBeenCalledTimes(1);
  });

  it("tls-graph holds its slot until its super-timeline scan settles, and the scan stops for a gone client (#2128)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-heavy-tls-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const superTimelineStore = new SuperTimelineStore(store);
    const admit = vi.spyOn(HeavyReadGate.prototype, "admit");
    const app = createApp(store, { stateStore, superTimelineStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(emptyState("c1"));
    expect((await request(app).get("/cases/c1/sessions")).status).toBe(200);
    await stateStore.save(emptyState("c1")); // #2126: a fresh revision, so tls-graph loads afresh
    const gate = admit.mock.contexts[0] as HeavyReadGate;
    // A three-page raw record whose second page is slow to read.
    const page = deferred();
    let pages = 0;
    const row = { id: "r", timestamp: "2026-06-01T00:00:00Z" } as ForensicEvent;
    vi.spyOn(superTimelineStore, "eventBatches").mockImplementation(async function* () {
      for (let i = 0; i < 3; i++) {
        if (i === 1) await page.promise;
        pages++;
        yield [row];
      }
    });
    const port = await listen(app);
    const busy = [deferred(), deferred()];
    const holders = busy.map((b) => wholeCaseLoads.run(() => b.promise));
    try {
      const gone = get(port, "/cases/c1/tls-graph");
      gone.reply.catch(() => undefined);
      await until(() => wholeCaseLoads.waiting === 1 && pages === 1);
      gone.drop();
      await until(() => wholeCaseLoads.waiting === 0);
      // The load is dropped, but the scan is still running: the slot stays held for it.
      await new Promise((r) => setTimeout(r, 50));
      expect(gate.active).toBe(1);
      page.resolve();
      await until(() => gate.active === 0);
      expect(pages).toBe(2); // the scan stopped at the next page instead of reading the rest
    } finally {
      busy.forEach((b) => b.resolve());
      await Promise.all(holders);
    }
  });

  it("the report-lite cache still serves the second request behind the gate", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-heavy-gate-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore, {
      scope: new ScopeStore(store),
      falsePositives: new FalsePositiveStore(store),
    });
    const app = createApp(store, { stateStore, reportWriter });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(emptyState("c1"));
    const load = vi.spyOn(stateStore, "load");
    const first = await request(app).get("/cases/c1/timeline-gaps");
    const second = await request(app).get("/cases/c1/timeline-gaps");
    const swim = await request(app).get("/cases/c1/swimlane");
    expect([first.status, second.status, swim.status]).toEqual([200, 200, 200]);
    expect(second.body).toEqual(first.body);
    expect(load).toHaveBeenCalledTimes(1);
    expect((await request(app).get("/cases/c1/state")).status).toBe(200);
  });
});
