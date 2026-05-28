import type { CapturePayload } from "./types.js";

const STORE = "captures";

export class CaptureQueue {
  constructor(private readonly dbName = "dfir-capture-queue") {}

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

  // Sends queued payloads oldest-first; stops on first failure, keeping the rest.
  async drain(sender: (p: CapturePayload) => Promise<boolean>): Promise<void> {
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
      const ok = await sender(entry.payload);
      if (!ok) return; // keep this and all later entries
      await this.tx("readwrite", (s) => s.delete(entry.key));
    }
  }
}
