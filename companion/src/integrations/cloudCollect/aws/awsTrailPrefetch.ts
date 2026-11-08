// S3 trail fetch-ahead (#2380): the next few trail objects the walk WILL return are downloaded while
// the engine commits the current page. It is only a cache of bytes held in memory: the engine still
// asks for, and commits, one page at a time in order, so the manifest, page tokens, the checkpoint and
// Resume are exactly what sequential collection gives. Nothing is written to disk from here.
//
// Guarantees (the evidence engine depends on them):
//   - Bounded: at most `depth` objects in flight or held; only objects whose listed Size is known and
//     at most MAX_PREFETCH_OBJECT_BYTES; the listed bytes in flight or held stay under
//     MAX_PREFETCH_HELD_BYTES. An object outside those bounds is simply fetched when asked for.
//   - Failure is never decided here. A prefetch that fails leaves a "failed" marker until the walk
//     reaches that key; the caller then fetches it the normal way, ONCE — so a denied object is still
//     a skip and a throttle still goes to the engine's retry budget. A key with any entry is never
//     prefetched again, and a throttle stops all prefetching for this walk (no amplified SlowDown).
//   - Cancel is terminal. The prefetcher owns an AbortController, aborted when any request signal it
//     served aborts, or on close(). A download is GetObject AND its body in one promise under that
//     signal. close() aborts and waits until every download has settled.

import { GetObjectCommand } from "@aws-sdk/client-s3";
import { rateLimitOf } from "../collectRateLimit.js";
import { sendAws, type AwsSender } from "./awsCollectTypes.js";

export const PREFETCH_DEPTH = 6;
export const MAX_PREFETCH_OBJECT_BYTES = 8 * 1024 * 1024;
export const MAX_PREFETCH_HELD_BYTES = 32 * 1024 * 1024;

/** A GetObject answer without its stream: what the page records about the download. */
export interface GotMeta {
  VersionId?: string;
  ETag?: string;
  LastModified?: Date;
  $metadata?: { requestId?: string };
}

export interface FetchedObject {
  meta: GotMeta;
  body: Uint8Array;
}

/** An object the walk will return next, with its listed size. */
export interface PrefetchCandidate {
  bucket: string;
  key: string;
  size?: number;
}

type Entry =
  | { state: "pending"; size: number; done: Promise<void> }
  | { state: "ready"; size: number; value: FetchedObject }
  | { state: "failed"; size: number };

const idOf = (bucket: string, key: string): string => `${bucket}\n${key}`;

/** Which candidates to start now, in walk order, within the limits. PURE. */
export function pickPrefetch(
  candidates: readonly PrefetchCandidate[],
  held: { count: number; bytes: number; has: (id: string) => boolean },
  depth: number,
): PrefetchCandidate[] {
  const picked: PrefetchCandidate[] = [];
  let { count, bytes } = held;
  for (const c of candidates) {
    if (count >= depth) break;
    if (held.has(idOf(c.bucket, c.key))) continue;
    // Unknown or large: not prefetched — it is fetched when the walk reaches it.
    if (c.size === undefined || c.size > MAX_PREFETCH_OBJECT_BYTES) continue;
    if (bytes + c.size > MAX_PREFETCH_HELD_BYTES) break;
    picked.push(c);
    count += 1;
    bytes += c.size;
  }
  return picked;
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : Object.assign(new Error("aborted"), { name: "AbortError" });
}

/** Wait for `p`, or reject at once when `signal` aborts. */
function untilAbort(p: Promise<void>, signal?: AbortSignal): Promise<void> {
  if (!signal) return p;
  if (signal.aborted) return Promise.reject(abortReason(signal));
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortReason(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

export class TrailPrefetcher {
  private readonly entries = new Map<string, Entry>();
  private readonly inflight = new Set<Promise<void>>();
  private readonly controller = new AbortController();
  private readonly linked = new WeakSet<AbortSignal>();
  private stopped = false;

  constructor(
    private readonly s3: AwsSender,
    private readonly depth: number = PREFETCH_DEPTH,
  ) {}

  /** Downloads in flight now (tests: nothing may be left after close()). */
  get active(): number {
    return this.inflight.size;
  }

  private link(signal?: AbortSignal): void {
    if (!signal || this.linked.has(signal)) return;
    this.linked.add(signal);
    if (signal.aborted) this.controller.abort(signal.reason);
    else signal.addEventListener("abort", () => this.controller.abort(signal.reason), { once: true });
  }

  /**
   * Start downloads for the next objects. `upcoming` is the walk's order after `current`;
   * entries no longer upcoming (a skip, a new partition) are dropped once settled.
   */
  fill(current: PrefetchCandidate, upcoming: readonly PrefetchCandidate[], signal?: AbortSignal): void {
    this.link(signal);
    // The current object is about to be taken: its download is kept, never dropped as "passed".
    const wanted = new Set([current, ...upcoming].map((c) => idOf(c.bucket, c.key)));
    for (const [id, e] of this.entries) if (e.state !== "pending" && !wanted.has(id)) this.entries.delete(id);
    if (this.stopped || this.depth <= 0 || this.controller.signal.aborted) return;
    let bytes = 0;
    for (const e of this.entries.values()) bytes += e.size;
    const count = Math.max(this.entries.size, this.inflight.size);
    const picks = pickPrefetch(upcoming, { count, bytes, has: (id) => this.entries.has(id) }, this.depth);
    for (const c of picks) this.start(c);
  }

  private start(c: PrefetchCandidate): void {
    const id = idOf(c.bucket, c.key);
    const size = c.size ?? 0;
    const signal = this.controller.signal;
    const done = (async () => {
      const got = await sendAws<GotMeta & { Body?: { transformToByteArray(): Promise<Uint8Array> } }>(
        this.s3,
        new GetObjectCommand({ Bucket: c.bucket, Key: c.key }),
        signal,
      );
      const body = (await got.Body?.transformToByteArray()) ?? new Uint8Array();
      const { Body: _stream, ...meta } = got;
      if (this.entries.get(id)?.state === "pending")
        this.entries.set(id, { state: "ready", size, value: { meta, body } });
    })().catch((err: unknown) => {
      if (this.entries.get(id)?.state === "pending") this.entries.set(id, { state: "failed", size });
      if (rateLimitOf(err, Date.now())) this.stopped = true;
    });
    const tracked = done.finally(() => this.inflight.delete(tracked));
    this.inflight.add(tracked);
    this.entries.set(id, { state: "pending", size, done });
  }

  /**
   * The object if a prefetch got it; undefined when there was none or it failed (fetch it the normal
   * way). Waits for one still downloading. Rejects when `signal` aborts — cancel is terminal.
   */
  async take(bucket: string, key: string, signal?: AbortSignal): Promise<FetchedObject | undefined> {
    this.link(signal);
    const id = idOf(bucket, key);
    const entry = this.entries.get(id);
    if (!entry) return undefined;
    if (entry.state === "pending") await untilAbort(entry.done, signal);
    if (signal?.aborted) throw abortReason(signal);
    const settled = this.entries.get(id);
    this.entries.delete(id);
    return settled?.state === "ready" ? settled.value : undefined;
  }

  /** Abort every download and wait until all have settled. Idempotent. */
  async close(): Promise<void> {
    this.stopped = true;
    this.controller.abort();
    await Promise.allSettled([...this.inflight]);
    this.entries.clear();
  }
}
