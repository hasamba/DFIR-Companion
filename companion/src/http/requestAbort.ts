// #1915: notice when a request's client has gone away, so no more work is done for it.
//
// A client that timed out still had its whole projection computed and serialised, then written to
// a dead socket; a burst of those kept the main thread busy long after the clients stopped. A route
// takes this signal and passes it to the shared loads it waits on (reports/stateLoadGate.ts), and
// checks clientGone() after each await before computing or sending anything more.

import type { Response } from "express";

const SIGNAL_KEY = "requestAbortSignal";

/** Aborts when this response's client disconnects before the answer was fully sent. One per request. */
export function requestAbortSignal(res: Response): AbortSignal {
  const existing = res.locals[SIGNAL_KEY] as AbortSignal | undefined;
  if (existing) return existing;
  const controller = new AbortController();
  if (res.destroyed) controller.abort();
  else
    res.once("close", () => {
      if (!res.writableEnded) controller.abort();
    });
  res.locals[SIGNAL_KEY] = controller.signal;
  return controller.signal;
}

/** True once the client is gone: nothing more should be computed or written for this request. */
export function clientGone(res: Response): boolean {
  return res.destroyed || requestAbortSignal(res).aborted;
}
