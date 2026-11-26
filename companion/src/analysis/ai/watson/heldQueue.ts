import { copyFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../../../storage/atomicWrite.js";
import type { ForensicEvent } from "../../stateTypes.js";

// The per-case outbox of held Watson promotions a RE-GRADE found (#2918): rows of a Watson paste whose
// grading finished later — at start-up, at the next import's sweep, or in a streamed / drop-folder
// settle — after the paste's own chat turn had passed. A re-grade has no chat turn to offer them in, so
// it queues the finalized raised copies here (state/watson-held-queue.json) and heldOffer.ts moves them
// into the Watson chat as held-rows cards. The file survives a restart, so a suggestion is offered
// even when the process stops between the re-grade and the chat write.
//
// Every entry has a sequence number: an offer acknowledges exactly the entries it read (id AND seq),
// so a newer copy queued meanwhile is never removed unseen. Writers for one case run one at a time.
// A corrupt file is kept beside the new one (never silently replaced) and read as empty.

export const HELD_QUEUE_FILE = "watson-held-queue.json";
/** The most rows the outbox holds. Past it a re-grade keeps its rows marked and retries later. */
export const HELD_QUEUE_MAX = 5000;

export interface QueuedHeld {
  seq: number;
  /** When the row was queued. */
  at: string;
  /** The finalized raised copy, as the card offers it. */
  event: ForensicEvent;
}

interface QueueFile {
  version: 1;
  next: number;
  entries: QueuedHeld[];
}

/** The outbox is full: the caller keeps its rows marked, so a later re-grade queues them again. */
export class HeldQueueFull extends Error {
  constructor(waiting: number, adding: number) {
    super(`the held-promotion queue is full (${waiting} waiting, ${adding} more)`);
    this.name = "HeldQueueFull";
  }
}

const EMPTY: QueueFile = { version: 1, next: 1, entries: [] };
const chains = new Map<string, Promise<unknown>>();

const pathOf = (stateDir: string): string => join(stateDir, HELD_QUEUE_FILE);

/** One at a time per file. A throwing step rejects only its own call. */
function serialized<T>(stateDir: string, fn: () => Promise<T>): Promise<T> {
  const key = pathOf(stateDir);
  const run = (chains.get(key) ?? Promise.resolve()).then(fn);
  const tail = run.catch(() => undefined);
  chains.set(key, tail);
  void tail.then(() => {
    if (chains.get(key) === tail) chains.delete(key);
  });
  return run;
}

const isEvent = (v: unknown): v is ForensicEvent => {
  if (typeof v !== "object" || v === null) return false;
  const e = v as Record<string, unknown>;
  return (
    typeof e.id === "string" &&
    typeof e.severity === "string" &&
    typeof e.description === "string" &&
    typeof e.timestamp === "string" &&
    Array.isArray(e.sourceScreenshots)
  );
};

function parseEntries(raw: unknown): QueuedHeld[] {
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((x): QueuedHeld[] => {
    if (typeof x !== "object" || x === null) return [];
    const o = x as Record<string, unknown>;
    if (typeof o.seq !== "number" || !Number.isInteger(o.seq) || !isEvent(o.event)) return [];
    return [{ seq: o.seq, at: typeof o.at === "string" ? o.at : "", event: o.event }];
  });
}

async function load(stateDir: string, log?: (line: string) => void): Promise<QueueFile> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(pathOf(stateDir), "utf8")) as unknown;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return EMPTY;
    if (!(err instanceof SyntaxError)) throw err;
    const kept = `${pathOf(stateDir)}.corrupt-${new Date().toISOString().replace(/[:.]/g, "-")}`;
    await copyFile(pathOf(stateDir), kept);
    log?.(`[watson] the held-promotion queue was unreadable; it is kept as ${kept}`);
    return EMPTY;
  }
  if (typeof raw !== "object" || raw === null) return EMPTY;
  const o = raw as Record<string, unknown>;
  const entries = parseEntries(o.entries);
  const top = entries.reduce((m, e) => Math.max(m, e.seq), 0);
  const next = typeof o.next === "number" && Number.isInteger(o.next) && o.next > top ? o.next : top + 1;
  return { version: 1, next, entries };
}

const save = (stateDir: string, file: QueueFile): Promise<void> =>
  atomicWrite(pathOf(stateDir), JSON.stringify(file));

/**
 * Queue raised copies (a new copy of a queued id replaces it with a new seq). Throws HeldQueueFull
 * when the outbox would pass HELD_QUEUE_MAX; nothing is written then.
 */
export function enqueueHeld(
  stateDir: string,
  events: readonly ForensicEvent[],
  log?: (line: string) => void,
): Promise<void> {
  if (!events.length) return Promise.resolve();
  return serialized(stateDir, async () => {
    const file = await load(stateDir, log);
    const replaced = new Set(events.map((e) => e.id));
    const kept = file.entries.filter((q) => !replaced.has(q.event.id));
    const fresh = [...new Map(events.map((e) => [e.id, e] as const)).values()];
    if (kept.length + fresh.length > HELD_QUEUE_MAX) throw new HeldQueueFull(kept.length, fresh.length);
    const at = new Date().toISOString();
    const added = fresh.map((event, i) => ({ seq: file.next + i, at, event }));
    await save(stateDir, { version: 1, next: file.next + added.length, entries: [...kept, ...added] });
  });
}

/** The queued entries, oldest first. */
export function readHeldQueue(stateDir: string, log?: (line: string) => void): Promise<QueuedHeld[]> {
  return serialized(stateDir, async () => (await load(stateDir, log)).entries);
}

/** Remove exactly these entries (id and seq): a copy queued after they were read stays. */
export function ackHeld(stateDir: string, acked: readonly QueuedHeld[]): Promise<void> {
  if (!acked.length) return Promise.resolve();
  return serialized(stateDir, async () => {
    const file = await load(stateDir);
    const done = new Set(acked.map((q) => `${q.seq}\0${q.event.id}`));
    const entries = file.entries.filter((q) => !done.has(`${q.seq}\0${q.event.id}`));
    if (entries.length === file.entries.length) return;
    await save(stateDir, { ...file, entries });
  });
}
