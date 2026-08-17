import { Worker } from "node:worker_threads";
import { loadDatabaseSync } from "./sqliteRuntime.js";

// Job rows live in a per-case operational database deliberately excluded from investigation-state
// backups: restoring evidence must not rewind job history or resurrect old running work.
const WORKER_SOURCE = String.raw`
const { parentPort } = require("node:worker_threads");
const { mkdirSync } = require("node:fs");
const { dirname } = require("node:path");

const DatabaseSync = process.getBuiltinModule("node:sqlite").DatabaseSync;

function openDatabase(path) {
  mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path, { enableForeignKeyConstraints: true });
  db.exec(
    "PRAGMA journal_mode=DELETE;" +
    "PRAGMA synchronous=FULL;" +
    "PRAGMA busy_timeout=10000;" +
    "CREATE TABLE IF NOT EXISTS job_ledger (" +
      "id TEXT PRIMARY KEY," +
      "scope_key TEXT NOT NULL," +
      "case_id TEXT," +
      "status TEXT NOT NULL," +
      "priority TEXT NOT NULL," +
      "queued_at TEXT NOT NULL," +
      "updated_at TEXT NOT NULL," +
      "ended_at TEXT," +
      "idempotency_key TEXT," +
      "run_manifest_id TEXT," +
      "payload TEXT NOT NULL" +
    ");" +
    "CREATE UNIQUE INDEX IF NOT EXISTS job_ledger_idempotency_idx " +
      "ON job_ledger(scope_key, idempotency_key) WHERE idempotency_key IS NOT NULL;" +
    "CREATE INDEX IF NOT EXISTS job_ledger_scope_order_idx " +
      "ON job_ledger(scope_key, queued_at DESC, id DESC);" +
    "CREATE INDEX IF NOT EXISTS job_ledger_status_idx " +
      "ON job_ledger(status, updated_at);"
  );
  return db;
}

function withTransaction(db, fn) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const value = fn();
    db.exec("COMMIT");
    return value;
  } catch (error) {
    try { db.exec("ROLLBACK"); } catch {}
    throw error;
  }
}

function putJob(message) {
  const db = openDatabase(message.dbPath);
  try {
    return withTransaction(db, () => {
      const job = message.job;
      if (message.insertOnly && job.idempotencyKey) {
        const existing = db.prepare(
          "SELECT payload FROM job_ledger WHERE scope_key=? AND idempotency_key=?"
        ).get(message.scopeKey, job.idempotencyKey);
        if (existing) return { inserted: false, payload: existing.payload };
      }
      if (message.insertOnly) {
        db.prepare(
          "INSERT INTO job_ledger " +
          "(id, scope_key, case_id, status, priority, queued_at, updated_at, ended_at, " +
          "idempotency_key, run_manifest_id, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).run(
          job.id, message.scopeKey, job.caseId, job.status, job.priority, job.queuedAt,
          job.updatedAt, job.endedAt || null, job.idempotencyKey || null,
          job.runManifestId || null, message.payload
        );
        return { inserted: true };
      }
      const result = db.prepare(
        "UPDATE job_ledger SET status=?, priority=?, updated_at=?, ended_at=?, " +
        "run_manifest_id=?, payload=? WHERE id=?"
      ).run(
        job.status, job.priority, job.updatedAt, job.endedAt || null,
        job.runManifestId || null, message.payload, job.id
      );
      if (Number(result.changes) !== 1) {
        throw new Error("cannot update missing job " + job.id);
      }
      return { inserted: false };
    });
  } finally {
    db.close();
  }
}

function listJobs(message) {
  const db = openDatabase(message.dbPath);
  try {
    return db.prepare(
      "SELECT payload FROM job_ledger WHERE scope_key=? ORDER BY queued_at DESC, id DESC"
    ).all(message.scopeKey).map((row) => row.payload);
  } finally {
    db.close();
  }
}

// Scoped by scope_key as well as id: the id is the primary key, but every other statement here
// carries the scope and a DELETE that did not would be the one place a wrong dbPath could reach
// across scopes unnoticed.
function deleteJob(message) {
  const db = openDatabase(message.dbPath);
  try {
    return Number(db.prepare(
      "DELETE FROM job_ledger WHERE scope_key=? AND id=?"
    ).run(message.scopeKey, message.jobId).changes);
  } finally {
    db.close();
  }
}

function pruneJobs(message) {
  const db = openDatabase(message.dbPath);
  try {
    return withTransaction(db, () => {
      const count = Number(db.prepare(
        "SELECT count(*) AS n FROM job_ledger WHERE scope_key=?"
      ).get(message.scopeKey).n);
      const remove = Math.max(0, count - message.max);
      if (!remove) return 0;
      const result = db.prepare(
        "DELETE FROM job_ledger WHERE id IN (" +
          "SELECT id FROM job_ledger WHERE scope_key=? " +
          "AND status IN ('succeeded','failed','cancelled','interrupted') " +
          "ORDER BY coalesce(ended_at, updated_at), queued_at, id LIMIT ?" +
        ")"
      ).run(message.scopeKey, remove);
      return Number(result.changes);
    });
  } finally {
    db.close();
  }
}

function dispatch(message) {
  switch (message.op) {
    case "putJob": return putJob(message);
    case "listJobs": return listJobs(message);
    case "deleteJob": return deleteJob(message);
    case "pruneJobs": return pruneJobs(message);
    default: throw new Error("unknown job-ledger worker operation: " + message.op);
  }
}

parentPort.on("message", (message) => {
  try {
    parentPort.postMessage({ requestId: message.requestId, value: dispatch(message) });
  } catch (error) {
    parentPort.postMessage({
      requestId: message.requestId,
      error: {
        name: error && error.name ? error.name : "Error",
        message: error && error.message ? error.message : String(error),
        code: error && error.code,
        stack: error && error.stack,
      },
    });
  }
});
`;

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

class JobLedgerWorker {
  private worker: Worker | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, PendingRequest>();

  request<T>(message: Record<string, unknown>): Promise<T> {
    const worker = this.ensureWorker();
    const requestId = this.nextId++;
    worker.ref();
    return new Promise<T>((resolve, reject) => {
      this.pending.set(requestId, {
        resolve: (value) => resolve(value as T),
        reject,
      });
      worker.postMessage({ ...message, requestId });
    });
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    loadDatabaseSync();
    const worker = new Worker(WORKER_SOURCE, { eval: true });
    worker.on("message", (reply: WorkerReply<unknown>) => this.onReply(reply));
    worker.on("error", (error) => this.failAll(error));
    worker.on("exit", (code) => {
      if (code !== 0) this.failAll(new Error(`job-ledger SQLite worker exited with code ${code}`));
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

export const jobLedgerWorker = new JobLedgerWorker();
