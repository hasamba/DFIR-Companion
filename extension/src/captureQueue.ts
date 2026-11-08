import type { CapturePayload, DroppedCapture } from "./types.js";
import { companionServerKey } from "./casePasswordSession.js";

const STORE = "captures";

/**
 * Most captures the offline queue holds (#2396). A wrong token used to add a full PNG on every
 * 30 s tick until the browser quota ran out. At the cap a NEW capture is refused (and the analyst
 * told); captures already waiting are never evicted to make room — that would delete evidence.
 */
export const MAX_QUEUED_CAPTURES = 200;

/** The queue already holds MAX_QUEUED_CAPTURES; this capture could not be added. */
export class CaptureQueueFullError extends Error {
  constructor(readonly limit: number) {
    super(`offline queue full (${limit} captures waiting)`);
    this.name = "CaptureQueueFullError";
  }
}

/** Where a capture is to be delivered — the companion it was taken for (#2396). */
export interface EnqueueOptions {
  companionUrl?: string;
  /**
   * The caller uploads this row itself right now: register it as live before enqueue resolves, so
   * a drain running meanwhile cannot send it a second time. The caller must call endLive(key).
   */
  live?: boolean;
}

/** First wait before a kept (access-refused) capture is re-sent (#2263). */
export const KEPT_BACKOFF_BASE_MS = 60_000;
/** Longest wait between re-sends of a kept capture (#2263). */
export const KEPT_BACKOFF_MAX_MS = 30 * 60_000;

/**
 * How long to wait after the `attempts`-th refusal before re-sending a kept capture: one minute,
 * doubling each time, capped at thirty minutes (#2263). A nonsense count is the first attempt.
 */
export function keptBackoffMs(attempts: number): number {
  const n = Number.isFinite(attempts) && attempts >= 1 ? Math.floor(attempts) : 1;
  // The exponent is clamped so a huge count cannot overflow to Infinity before the cap applies.
  return Math.min(KEPT_BACKOFF_BASE_MS * 2 ** Math.min(n - 1, 30), KEPT_BACKOFF_MAX_MS);
}

/**
 * One stored queue row. `attempts`, `nextAttemptAt` and the `last*` refusal fields exist only on a
 * kept capture (#2263); a row written by an older extension has just `payload` and is due now.
 */
interface QueueRecord {
  key: number;
  payload: CapturePayload;
  /** The companion this capture was taken for (#2396); absent on rows from an older extension. */
  companionUrl?: string;
  attempts?: number;
  nextAttemptAt?: number;
  lastStatus?: number;
  lastErrorMessage?: string;
  lastErrorCode?: string;
}

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
 *  - `skip`  — refused for who is asking, not for what was sent (401/403 after a token or case
 *              switch, #2254): KEEP this entry and carry on with the rest. It must not be `retry` —
 *              that would stop the drain and block every valid capture behind it, the #215 bug again.
 */
export interface QueueSendResult {
  outcome: "sent" | "retry" | "drop" | "skip";
  status?: number;        // HTTP status where known; 0 when fetch itself failed
  errorMessage?: string;  // the companion's explanation, for the popup diagnostic
  errorCode?: string;     // the companion's machine-readable reason, when it gave one
}

/** What one drain pass did, so callers can surface dropped captures instead of losing them quietly. */
export interface DrainSummary {
  sent: number;
  dropped: DroppedCapture[];
  /** Entries refused for access and left in the queue (`skip`, #2254). */
  kept: DroppedCapture[];
  /** Entries taken for a different companion than the one being drained to — kept, not sent (#2396). */
  elsewhere: number;
  /**
   * The drain stopped on an error part-way. What it did before that (sent, dropped) is still in
   * this summary, so a capture already discarded is never reported as nothing (#2396).
   */
  error?: string;
  /** Another drain was already running, so this one did nothing. */
  busy?: boolean;
  /** The HTTP status that stopped the drain (`retry`; 0 = unreachable), when one did. */
  stoppedStatus?: number;
}

/** Which companion a drain delivers to; rows bound to another one stay queued (#2396). */
export interface DrainOptions {
  companionUrl?: string;
}

function reported(payload: CapturePayload, result: QueueSendResult): DroppedCapture {
  return {
    payload,
    status: result.status ?? 0,
    ...(result.errorMessage ? { errorMessage: result.errorMessage } : {}),
    ...(result.errorCode ? { errorCode: result.errorCode } : {}),
  };
}

/** The refusal stored on a kept record, re-reported while it waits out its backoff. */
function lastRefusal(rec: QueueRecord): QueueSendResult {
  return {
    outcome: "skip",
    ...(rec.lastStatus !== undefined ? { status: rec.lastStatus } : {}),
    ...(rec.lastErrorMessage ? { errorMessage: rec.lastErrorMessage } : {}),
    ...(rec.lastErrorCode ? { errorCode: rec.lastErrorCode } : {}),
  };
}

/**
 * Is this record waiting out its backoff? Missing or malformed fields mean due. So does a
 * nextAttemptAt further away than the cap allows — the clock moved backwards — so a kept capture
 * can never be stranded for longer than one maximum window.
 */
function isDeferred(rec: QueueRecord, now: number): boolean {
  const at = rec.nextAttemptAt;
  if (typeof at !== "number" || !Number.isFinite(at)) return false;
  return at > now && at - now <= KEPT_BACKOFF_MAX_MS;
}

/** The record after one more access refusal: attempt counted, next re-send pushed out (#2263). */
function withRefusal(rec: QueueRecord, result: QueueSendResult, now: number): QueueRecord {
  const attempts = (typeof rec.attempts === "number" && Number.isFinite(rec.attempts) ? rec.attempts : 0) + 1;
  return {
    key: rec.key,
    payload: rec.payload,
    ...(rec.companionUrl ? { companionUrl: rec.companionUrl } : {}),
    attempts,
    nextAttemptAt: now + keptBackoffMs(attempts),
    ...(result.status !== undefined ? { lastStatus: result.status } : {}),
    ...(result.errorMessage ? { lastErrorMessage: result.errorMessage } : {}),
    ...(result.errorCode ? { lastErrorCode: result.errorCode } : {}),
  };
}

export class CaptureQueue {
  constructor(
    private readonly dbName = "dfir-capture-queue",
    private readonly now: () => number = () => Date.now(),
  ) {}

  private draining = false;
  // Rows a live capture is uploading right now (#2396). In memory on purpose: after the worker is
  // suspended the set is gone, which is exactly when a drain should pick those rows up.
  private readonly live = new Set<number>();

  endLive(key: number): void {
    this.live.delete(key);
  }

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

  /**
   * Add a capture and return its key. The count check and the add share ONE transaction, so two
   * captures racing for the last slot cannot both get in (#2396). Rejects with
   * CaptureQueueFullError at the cap; resolves only once the row is committed.
   */
  async enqueue(payload: CapturePayload, options: EnqueueOptions = {}): Promise<number> {
    const record = { payload, ...(options.companionUrl ? { companionUrl: options.companionUrl } : {}) };
    const key = await this.withDb((db) => new Promise<number>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      let added: number | undefined;
      let full = false;
      const count = store.count();
      count.onsuccess = () => {
        if (count.result >= MAX_QUEUED_CAPTURES) {
          full = true;
          return; // nothing written; the empty transaction completes
        }
        const add = store.add(record);
        add.onsuccess = () => { added = add.result as number; };
      };
      tx.oncomplete = () => {
        if (full || added === undefined) { reject(new CaptureQueueFullError(MAX_QUEUED_CAPTURES)); return; }
        if (options.live) this.live.add(added);
        resolve(added);
      };
      tx.onabort = () => reject(tx.error ?? new Error("capture queue transaction aborted"));
      tx.onerror = () => reject(tx.error ?? new Error("capture queue transaction failed"));
    }));
    return key;
  }

  /** Remove one row; resolves once the deletion is committed. */
  async remove(key: number): Promise<void> {
    await this.tx("readwrite", (s) => s.delete(key));
  }

  async size(): Promise<number> {
    return this.tx<number>("readonly", (s) => s.count());
  }

  async clear(): Promise<void> {
    await this.tx("readwrite", (s) => s.clear());
  }

  // Sends queued payloads oldest-first. Stops at the first RETRYABLE failure (keeping it and
  // everything behind it, so order is preserved); discards permanently-rejected entries and
  // continues past them, reporting them in the summary; keeps SKIPPED entries in place and
  // continues past them too (#2254), backing off before re-sending them (#2263).
  //
  // Only the KEYS are read up front (#2396). Each row is loaded just before it is sent, so a drain
  // holds one screenshot in memory, never sends a row a live capture is uploading, and never
  // re-sends a row that live capture already delivered and removed.
  async drain(
    sender: (p: CapturePayload) => Promise<QueueSendResult>,
    options: DrainOptions = {},
  ): Promise<DrainSummary> {
    const summary: DrainSummary = { sent: 0, dropped: [], kept: [], elsewhere: 0 };
    if (this.draining) return { ...summary, busy: true };
    this.draining = true;
    try {
      // ONE connection for the whole drain.
      return await this.withDb(async (db) => {
        const keys = await this.txOn<IDBValidKey[]>(db, "readonly", (s) => s.getAllKeys());
        const target = options.companionUrl ? companionServerKey(options.companionUrl) : "";
        try {
          for (const rawKey of keys) {
            const key = rawKey as number;
            if (this.live.has(key)) continue;
            const value = await this.txOn<unknown>(db, "readonly", (s) => s.get(key));
            if (!value || this.live.has(key)) continue; // delivered meanwhile, or now being uploaded
            const entry = { ...(value as Omit<QueueRecord, "key">), key };
            // Taken for another companion: never replay it to this one, never delete it here.
            // Compared as server identity, so "http://LOCALHOST:4773/" and "http://localhost:4773" match.
            if (entry.companionUrl && target && companionServerKey(entry.companionUrl) !== target) {
              summary.elsewhere += 1;
              continue;
            }
            // A kept capture still inside its backoff window is NOT uploaded again (#2263). It is
            // still reported as kept, so the amber badge and popup note stay up while it waits.
            if (isDeferred(entry, this.now())) {
              summary.kept.push(reported(entry.payload, lastRefusal(entry)));
              continue;
            }
            const result = await sender(entry.payload);
            if (result.outcome === "retry") {
              summary.stoppedStatus = result.status ?? 0;
              return summary; // keep this and all later entries
            }
            if (result.outcome === "skip") {
              summary.kept.push(reported(entry.payload, result));
              // Left in the queue — not deleted — with its attempt count and next re-send time.
              await this.txOn(db, "readwrite", (s) => s.put(withRefusal(entry, result, this.now())));
              continue;
            }
            if (result.outcome === "drop") {
              summary.dropped.push(reported(entry.payload, result));
            } else {
              summary.sent += 1;
            }
            // Both "sent" and "drop" remove the entry — a permanently-rejected capture must not stay
            // at the head of the queue blocking the ones behind it. Awaiting the transaction (not the
            // request) means a capture is never counted as handled while its removal is still open.
            await this.txOn(db, "readwrite", (s) => s.delete(key));
          }
        } catch (err) {
          summary.error = err instanceof Error ? err.message : String(err);
        }
        return summary;
      });
    } finally {
      this.draining = false;
    }
  }
}
