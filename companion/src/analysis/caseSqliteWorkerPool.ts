import { Worker } from "node:worker_threads";
import { loadDatabaseSync } from "./sqliteRuntime.js";

// #1454: the main-thread client for the case SQLite worker source in caseSqliteWorker.ts.
//
// One writer thread keeps every write in FIFO order, exactly as before. Reads go to a small pool of
// read-only threads so a dashboard poll never queues behind an import's write batches — that queue
// is what froze every panel for minutes. Three rules keep the split as safe as the single thread:
//
//  1. Read-after-write. A read captures the last write posted for the same database file (the
//     "writer tail") and waits for it before it is posted. A read therefore waits for at most the
//     one write in flight, never the queue, and it still sees a write nobody awaited.
//  2. Initialisation is the writer's. A reader opens read-only and runs no schema DDL. When it
//     finds a file the writer has not initialised — a restore, an imported archive, a pre-WAL case
//     — it answers DFIR_SQLITE_NEEDS_INIT; the pool then asks the writer to open and close the file
//     once (`ensureDatabase`: schema, user_version, WAL conversion) and retries the read once.
//  3. Exclusive ops drain the readers. `restoreDatabase` renames a file over the live database; it
//     waits for every read in flight to settle, holds new reads, runs on the writer, then releases
//     — in `finally`, so a failure cannot leave reads blocked.
//
// The pool size is a constant, not a setting: nothing an analyst could tune.
const READ_WORKER_COUNT = 2;

const READ_OPS = new Set([
  "stateExists",
  "loadState",
  "queryEntities",
  "hasEntityIds",
  "entityCounts",
  "queryAuthObservationsWindow",
  "scanSuper",
  "querySuper",
  "getSuper",
  "listSuperProtected",
  "superMeta",
]);
// Ops that replace the database file underneath any open connection.
const EXCLUSIVE_OPS = new Set(["restoreDatabase"]);
const NEEDS_INIT = "DFIR_SQLITE_NEEDS_INIT";

type WorkerRole = "read" | "write";
type WorkerMessage = Record<string, unknown>;

interface WorkerError {
  name: string;
  message: string;
  code?: string;
  stack?: string;
}

interface WorkerReply<T> {
  requestId: number;
  value?: T;
  error?: WorkerError;
}

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
};

const settle = (): undefined => undefined;

// One thread and its in-flight requests. Lazily started, unref'd when idle so it never holds the
// process open, restarted by the next request after an exit.
class WorkerLane {
  private worker: Worker | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, PendingRequest>();

  constructor(
    private readonly source: string,
    private readonly role: WorkerRole,
  ) {}

  get pendingCount(): number {
    return this.pending.size;
  }

  request<T>(message: WorkerMessage): Promise<T> {
    const worker = this.ensureWorker();
    const id = this.nextId++;
    worker.ref();
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (value) => resolve(value as T),
        reject,
      });
      worker.postMessage({ ...message, requestId: id });
    });
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    // Validate through the shared runtime accessor before constructing the worker. This keeps the
    // startup error actionable and preserves the bundler/SEA-safe node:sqlite loading seam.
    loadDatabaseSync();
    const worker = new Worker(this.source, { eval: true, workerData: { role: this.role } });
    worker.on("message", (reply: WorkerReply<unknown>) => this.onReply(reply));
    worker.on("error", (error) => this.failAll(error));
    worker.on("exit", (code) => {
      if (code !== 0) this.failAll(new Error(`SQLite ${this.role} worker exited with code ${code}`));
      this.worker = null;
    });
    worker.unref();
    this.worker = worker;
    return worker;
  }

  private onReply(reply: WorkerReply<unknown>): void {
    const pending = this.pending.get(reply.requestId);
    if (!pending) return;
    this.pending.delete(reply.requestId);
    if (reply.error) {
      const error = new Error(reply.error.message);
      error.name = reply.error.name;
      if (reply.error.code) (error as NodeJS.ErrnoException).code = reply.error.code;
      if (reply.error.stack) error.stack = reply.error.stack;
      pending.reject(error);
    } else {
      pending.resolve(reply.value);
    }
    if (this.pending.size === 0) this.worker?.unref();
  }

  private failAll(error: Error): void {
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }
}

function pathKey(message: WorkerMessage): string | null {
  const path = message.dbPath ?? message.targetPath;
  return typeof path === "string" && path ? path : null;
}

export class CaseSqliteWorkerPool {
  private readonly writer: WorkerLane;
  private readonly readers: WorkerLane[];
  // Per file: the last write posted (settled either way), so a later read can wait for it.
  private readonly writeTails = new Map<string, Promise<undefined>>();
  // Per file: an initialisation in flight on the writer, shared by concurrent reads that need it.
  private readonly ensuring = new Map<string, Promise<boolean>>();
  private readonly inflightReads = new Set<Promise<undefined>>();
  private exclusiveChain: Promise<unknown> = Promise.resolve();
  private readsHeld: Promise<void> = Promise.resolve();

  constructor(source: string) {
    this.writer = new WorkerLane(source, "write");
    this.readers = Array.from({ length: READ_WORKER_COUNT }, () => new WorkerLane(source, "read"));
  }

  request<T>(message: WorkerMessage): Promise<T> {
    const op = String(message.op);
    if (EXCLUSIVE_OPS.has(op)) return this.exclusiveRequest<T>(message);
    if (READ_OPS.has(op)) return this.readRequest<T>(message);
    return this.writeRequest<T>(message);
  }

  private writeRequest<T>(message: WorkerMessage): Promise<T> {
    const promise = this.writer.request<T>(message);
    this.trackWriteTail(message, promise);
    return promise;
  }

  private trackWriteTail(message: WorkerMessage, promise: Promise<unknown>): void {
    const key = pathKey(message);
    if (!key) return;
    const tail = promise.then(settle, settle);
    this.writeTails.set(key, tail);
    void tail.then(() => {
      if (this.writeTails.get(key) === tail) this.writeTails.delete(key);
    });
  }

  private readRequest<T>(message: WorkerMessage): Promise<T> {
    // Registered synchronously, before any await, so an exclusive op that starts while this read
    // is still waiting for its tail or its initialisation drains it too.
    const run = this.runRead<T>(message);
    const tracked = run.then(settle, settle);
    this.inflightReads.add(tracked);
    void tracked.then(() => this.inflightReads.delete(tracked));
    return run;
  }

  private async runRead<T>(message: WorkerMessage): Promise<T> {
    const key = pathKey(message);
    const tail = key ? this.writeTails.get(key) : undefined;
    await this.readsHeld;
    await tail;
    try {
      return await this.leastBusyReader().request<T>(message);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== NEEDS_INIT || !key) throw error;
      await this.ensureDatabase(key);
      return await this.leastBusyReader().request<T>(message);
    }
  }

  private leastBusyReader(): WorkerLane {
    return this.readers.reduce((best, lane) => (lane.pendingCount < best.pendingCount ? lane : best));
  }

  // Reads are optimistic: a reader answers NEEDS_INIT for a file the writer has not initialised
  // (restored, imported, or pre-WAL), and only then does the read wait for the writer — once per
  // file, shared by every read that hit it at the same time.
  private ensureDatabase(key: string): Promise<boolean> {
    const running = this.ensuring.get(key);
    if (running) return running;
    const promise = this.writer.request<boolean>({ op: "ensureDatabase", dbPath: key });
    this.ensuring.set(key, promise);
    void promise.then(settle, settle).then(() => this.ensuring.delete(key));
    return promise;
  }

  private exclusiveRequest<T>(message: WorkerMessage): Promise<T> {
    // Snapshot and hold in the same tick as the request: a read posted after this point waits on
    // `readsHeld`, and every read posted before it is in the snapshot — no read can slip between.
    const draining = [...this.inflightReads];
    let release: () => void = () => undefined;
    this.readsHeld = new Promise<void>((resolve) => {
      release = resolve;
    });
    const run = this.exclusiveChain.then(async () => {
      try {
        await Promise.all(draining);
        const promise = this.writer.request<T>(message);
        this.trackWriteTail(message, promise);
        return await promise;
      } finally {
        release();
      }
    });
    this.exclusiveChain = run.then(settle, settle);
    return run;
  }
}
