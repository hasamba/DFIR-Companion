import { createHash } from "node:crypto";

// The Idempotency-Key dedupe of POST /cases/:id/watson/message. A client that lost the answer to a
// message sends it again with the same key: the request attaches to the first round, or gets the
// saved chat when that round is done, so Watson does not answer (and bill) the message two times.
//
// The claim is synchronous, so two concurrent identical requests share one start(). A key is scoped
// to the case and the user identity. An entry keeps only the round's disposition and a hash of the
// text, never the chat. An "answered" or "cancelled" round is kept for the window and replayed. A
// "failed" round, or a start that rejected (a refusal), is forgotten once it settles, so a resend
// runs again. Memory only: a restarted server knows no key.

export const WATSON_IDEMPOTENCY_WINDOW_MS = 10 * 60_000;
/** Settled entries kept at most; a running entry is never evicted (the admission cap bounds those). */
export const WATSON_IDEMPOTENCY_MAX = 200;
export const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9_-]{8,64}$/;

export type WatsonMessageDisposition = "answered" | "cancelled" | "failed";

/** Whose key it is: the case, and the user identity id ("local" without login), never a display name. */
export interface DedupeScope {
  caseId: string;
  identityId: string;
}

export type DedupeClaim<T> = { kind: "first" | "repeat"; promise: Promise<T> } | { kind: "conflict" };

interface Entry<T> {
  readonly fingerprint: string;
  readonly promise: Promise<T>;
  /** When the round settled with a kept disposition; null while it runs. */
  readonly settledAt: number | null;
}

const fingerprintOf = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

const entryKey = (scope: DedupeScope, key: string): string =>
  JSON.stringify([scope.caseId, scope.identityId, key]);

export class WatsonMessageDedupe<T extends { disposition: WatsonMessageDisposition }> {
  private readonly entries = new Map<string, Entry<T>>();

  constructor(private readonly now: () => number = Date.now) {}

  run(scope: DedupeScope, key: string, text: string, start: () => Promise<T>): DedupeClaim<T> {
    this.expire();
    const id = entryKey(scope, key);
    const fingerprint = fingerprintOf(text);
    const hit = this.entries.get(id);
    if (hit)
      return hit.fingerprint === fingerprint
        ? { kind: "repeat", promise: hit.promise }
        : { kind: "conflict" };
    const promise = start();
    const entry: Entry<T> = { fingerprint, promise, settledAt: null };
    this.entries.set(id, entry);
    promise.then(
      (result) => this.settle(id, entry, result.disposition !== "failed"),
      () => this.settle(id, entry, false),
    );
    return { kind: "first", promise };
  }

  private settle(id: string, entry: Entry<T>, keep: boolean): void {
    if (this.entries.get(id) !== entry) return;
    if (!keep) {
      this.entries.delete(id);
      return;
    }
    this.entries.set(id, { ...entry, settledAt: this.now() });
    this.evict();
  }

  /** Drops the settled entries older than the window. */
  private expire(): void {
    const oldest = this.now() - WATSON_IDEMPOTENCY_WINDOW_MS;
    for (const [id, e] of this.entries) {
      if (e.settledAt !== null && e.settledAt < oldest) this.entries.delete(id);
    }
  }

  /** Drops the oldest settled entries beyond the cap. */
  private evict(): void {
    const settled = [...this.entries].filter(([, e]) => e.settledAt !== null);
    const extra = settled.length - WATSON_IDEMPOTENCY_MAX;
    if (extra <= 0) return;
    const byAge = settled.sort(([, a], [, b]) => (a.settledAt ?? 0) - (b.settledAt ?? 0));
    for (const [id] of byAge.slice(0, extra)) this.entries.delete(id);
  }
}
