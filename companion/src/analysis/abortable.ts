// #1915: small helpers for work a client may give up on.
//
// A request whose client disconnected should stop WAITING at once, and work it alone asked for
// should never start. Work that other callers share must never be cancelled by one of them leaving:
// that would fail a load another caller is still waiting for (report integrity first).
//
//   - untilAborted: one caller stops waiting on a shared promise; the work itself carries on.
//   - JoinedSignal: the signal of SHARED work. It aborts only when every caller that joined it with
//     a signal has aborted, and never once a caller joined without one (nobody can cancel it then).

/** An Error named "AbortError", the name fetch and AbortSignal use. */
export function abortError(): Error {
  const err = new Error("the client went away before the work finished");
  err.name = "AbortError";
  return err;
}

export function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === "AbortError";
}

/** `work`, or an AbortError as soon as `signal` aborts. Never cancels `work` itself. */
export function untilAborted<T>(work: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return work;
  if (signal.aborted) return Promise.reject(abortError());
  let onAbort = (): void => undefined;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(abortError());
    signal.addEventListener("abort", onAbort, { once: true });
  });
  return Promise.race([work, aborted]).finally(() => signal.removeEventListener("abort", onAbort));
}

/** The abort signal of work shared by several callers: aborted only once all of them have gone. */
export class JoinedSignal {
  private readonly controller = new AbortController();
  private live = 0;
  private pinned = false;

  /** `onAbandoned` runs just before the shared signal aborts, so the owner can stop handing it out. */
  constructor(private readonly onAbandoned: () => void = () => undefined) {}

  get signal(): AbortSignal {
    return this.controller.signal;
  }

  /** Count a caller in. Without a signal the caller can never leave, so the work is never cancelled. */
  join(signal?: AbortSignal): void {
    if (!signal) {
      this.pinned = true;
      return;
    }
    this.live++;
    signal.addEventListener("abort", () => this.leave(), { once: true });
  }

  private leave(): void {
    this.live--;
    if (this.live > 0 || this.pinned || this.controller.signal.aborted) return;
    this.onAbandoned();
    this.controller.abort();
  }
}
