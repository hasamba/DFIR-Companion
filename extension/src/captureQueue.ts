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

  private tx<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    return this.open().then((db) => new Promise<T>((resolve, reject) => {
      const store = db.transaction(STORE, mode).objectStore(STORE);
      const req = fn(store);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    }));
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
      const db = await this.open();
      const entries: { key: number; payload: CapturePayload }[] = await new Promise((resolve, reject) => {
        const out: { key: number; payload: CapturePayload }[] = [];
        const cursorReq = db.transaction(STORE, "readonly").objectStore(STORE).openCursor();
        cursorReq.onsuccess = () => {
          const cursor = cursorReq.result;
          if (cursor) {
            out.push({ key: cursor.key as number, payload: (cursor.value as { payload: CapturePayload }).payload });
            cursor.continue();
          } else resolve(out);
        };
        cursorReq.onerror = () => reject(cursorReq.error);
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
        // at the head of the queue blocking the ones behind it.
        await this.tx("readwrite", (s) => s.delete(entry.key));
      }
      return summary;
    } finally {
      this.draining = false;
    }
  }
}
