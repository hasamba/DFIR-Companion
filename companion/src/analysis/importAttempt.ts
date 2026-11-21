import { AsyncLocalStorage } from "node:async_hooks";

/**
 * "This import has actually started" — the moment an import attempt is granted the case's import
 * section (analysis/importLock.ts), not the moment it was queued for it (#2713).
 *
 * The drop folder's crash-loop guard (composition/dropInFlight.ts) counts an attempt only once the
 * file's import holds the section: up to four files of one sweep run at once and all of them queue on
 * that one section, so a file still waiting behind another must not be blamed when the other one
 * kills the server. The sweep runs each file inside `runImportAttempt`, and the import lock calls
 * `noteImportSectionStart` when it grants a section — no import seam has to pass anything along.
 * Outside an attempt (every other import path) the note is a no-op. The drop folder also calls it
 * itself before reading a large under-cap file whole (composition/dropWholeRead.ts, #2785).
 */
interface Attempt {
  started: boolean;
  /** Set once `fn` settled: work it left running (a tool hand-off) takes sections after the attempt. */
  closed: boolean;
  onStart: () => Promise<void>;
}

const attempts = new AsyncLocalStorage<Attempt>();

/** Run `fn` as one import attempt; `onStart` runs once, when its first import section is granted. */
export async function runImportAttempt<T>(onStart: () => Promise<void>, fn: () => Promise<T>): Promise<T> {
  const attempt: Attempt = { started: false, closed: false, onStart };
  try {
    return await attempts.run(attempt, fn);
  } finally {
    attempt.closed = true;
  }
}

/** Called by the import lock once a section is granted, before the import does anything. */
export async function noteImportSectionStart(): Promise<void> {
  const attempt = attempts.getStore();
  if (!attempt || attempt.started || attempt.closed) return;
  attempt.started = true;
  await attempt.onStart();
}
