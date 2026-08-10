import type { CapturePayload, DroppedCapture } from "./types.js";

const STORE = "captures";

/**
 * What the sender decided about one queued capture (#215).
 *
 * The queue used to receive a bare boolean, which collapsed "the companion is down, try later"
 * and "the companion says this capture can never be accepted" into the same answer. A queued
 * capture whose case has since been deleted (404), closed (423) or removed (410) then sat at the
 * head of the queue forever, and every valid capture behind it was never uploaded.
 *
 *  - `sent`  — accepted; delete it and continue.
 *  - `retry` — transient (unreachable, 5xx); stop here and keep this entry AND the ones behind it,
 *              so ordering is preserved for the next drain.
 *  - `drop`  — permanent (4xx); discard this entry and carry on with the rest, reporting it so the
 *              analyst finds out rather than silently losing evidence.
 */
export interface QueueSendResult {
  outcome: "sent" | "retry" | "drop";
  status?: number;        // HTTP status where known; 0 when fetch itself failed
  errorMessage?: string;  // the companion's explanation, for the popup diagnostic
}

/** What one drain pass did, so callers can surface dropped captures instead of losing them quietly. */
export interface DrainSummary {
  sent: number;
  dropped: DroppedCapture[];
}

export class CaptureQueue {
  constructor(private readonly dbName = "dfir-capture-queue") {}

  private draining = false;

  private open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore(STORE, { keyPath: "key", autoIncrement: true });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  /** Run `fn` against an open connection and close it afterwards, however it ends. */
  private async withDb<T>(fn: (db: IDBDatabase) => Promise<T>): Promise<T> {
    const db = await this.open();
    try {
      return await fn(db);
    } finally {
      // Left open, every operation leaked a connection — and a still-open connection blocks a
      // future version upgrade, which would strand the queue rather than migrate it.
      db.close();
    }
  }

  /**
   * One transaction, resolved when the TRANSACTION completes — not when the individual request
   * succeeds.
   *
   * That distinction is the whole point. A request's onsuccess fires while its transaction is still
   * open, so `await enqueue(...)` used to return before anything was durable. In a Manifest V3
   * service worker, which can be suspended the moment it goes idle, "the caller believes the capture
   * is saved" and "the capture is saved" were two different things, and the gap was where evidence
   * went missing. Resolving from oncomplete, and rejecting from onabort/onerror, makes the promise
   * mean what its callers already assumed.
   */
  private txOn<T>(
    db: IDBDatabase,
    mode: IDBTransactionMode,
    fn: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      let result: T;
      const req = fn(tx.objectStore(STORE));
      req.onsuccess = () => {
        result = req.result;
      };
      // A request error left unhandled aborts the transaction, so onabort is the backstop rather
      // than the exception: either way the promise rejects and nothing is reported durable.
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => resolve(result);
      tx.onabort = () => reject(tx.error ?? new Error("capture queue transaction aborted"));
      tx.onerror = () => reject(tx.error ?? new Error("capture queue transaction failed"));
    });
  }

  private tx<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    return this.withDb((db) => this.txOn<T>(db, mode, fn));
  }

  async enqueue(payload: CapturePayload): Promise<void> {
    await this.tx("readwrite", (s) => s.add({ payload }));
  }

  async size(): Promise<number> {
    return this.tx<number>("readonly", (s) => s.count());
  }

  async clear(): Promise<void> {
    await this.tx("readwrite", (s) => s.clear());
  }

  // Sends queued payloads oldest-first. Stops at the first RETRYABLE failure (keeping it and
  // everything behind it, so order is preserved); discards permanently-rejected entries and
  // continues past them, reporting them in the summary.
  async drain(sender: (p: CapturePayload) => Promise<QueueSendResult>): Promise<DrainSummary> {
    const summary: DrainSummary = { sent: 0, dropped: [] };
    if (this.draining) return summary;
    this.draining = true;
    try {
      // ONE connection for the whole drain. Enumeration opened one and every deletion opened
      // another, so draining fifty captures meant fifty-one connections — pure churn, and fifty-one
      // chances to leave one open.
      return await this.withDb(async (db) => {
        const entries: { key: number; payload: CapturePayload }[] = await new Promise((resolve, reject) => {
          const out: { key: number; payload: CapturePayload }[] = [];
          const tx = db.transaction(STORE, "readonly");
          const cursorReq = tx.objectStore(STORE).openCursor();
          cursorReq.onsuccess = () => {
            const cursor = cursorReq.result;
            if (cursor) {
              out.push({ key: cursor.key as number, payload: (cursor.value as { payload: CapturePayload }).payload });
              cursor.continue();
            }
          };
          cursorReq.onerror = () => reject(cursorReq.error);
          // Resolved from the transaction, like every other operation here — the cursor is finished
          // only once the transaction that owns it is.
          tx.oncomplete = () => resolve(out);
          tx.onabort = () => reject(tx.error ?? new Error("capture queue drain aborted"));
        });

        for (const entry of entries) {
          const result = await sender(entry.payload);
          if (result.outcome === "retry") return summary; // keep this and all later entries
          if (result.outcome === "drop") {
            summary.dropped.push({
              payload: entry.payload,
              status: result.status ?? 0,
              ...(result.errorMessage ? { errorMessage: result.errorMessage } : {}),
            });
          } else {
            summary.sent += 1;
          }
          // Both "sent" and "drop" remove the entry — a permanently-rejected capture must not stay
          // at the head of the queue blocking the ones behind it. Awaiting the transaction (not the
          // request) means a capture is never counted as handled while its removal is still open:
          // a suspend in that window would have resurrected an already-delivered capture.
          await this.txOn(db, "readwrite", (s) => s.delete(entry.key));
        }
        return summary;
      });
    } finally {
      this.draining = false;
    }
  }
}
