/**
 * Reads an append-only JSONL audit log (imports.jsonl, custody.jsonl) without re-reading the whole
 * file when the only change since the last read is an append THIS PROCESS made through append()
 * (#2584).
 *
 * The callers used to read and parse the whole log every time: the sequence allocator for the
 * highest number on disk (#1119), and the custody chain for the hash of its last line (#231). That
 * re-read is deliberate. A line can land in the log without going through this process — a crash
 * between the custody append and its head pin (#2150), a second process, a sync client, an analyst's
 * hand edit, a whole-case restore — and the file, not memory, is the authority (#2253). But it made
 * every import cost O(log size): ~4 MB of custody log re-parsed four times per file by the end of a
 * 3,872-file drop.
 *
 * So the answer of the last full read is kept per (log, fold) with a fingerprint of the file it was
 * read from: device, inode, size, modification AND status-change time (ns), and the file's last
 * bytes. It is used only while the file still carries exactly that fingerprint. The one change it
 * follows is this process's own append, made through append() under the same per-log lock: the bytes
 * are known, the file is re-checked right after the write (same inode, grown by exactly those bytes,
 * those bytes at its end), and only then is the snapshot moved forward. ANY other change — an append
 * by another writer, a truncation, an in-place edit anywhere in the file (it moves mtime and ctime;
 * restoring mtime with utimes moves ctime), a replacement (new inode), a delete — leaves a file whose
 * fingerprint no snapshot holds, so the next read is the old full read, with its answer or its error
 * (a corrupted line still fails closed every time: nothing is cached after a read that threw).
 * A full read is cached only when a second fstat after it shows the file did not move during it.
 * Snapshots are also dropped for another case incarnation, on a case delete or reseed
 * (CaseStore.forgetInMemory), and once older than FULL_REREAD_MAX_AGE_MS since their full read.
 *
 * What a fingerprint cannot see: a same-size rewrite that lands within the file system's timestamp
 * granularity of this process's own last write AND leaves the last bytes intact — or one that also
 * forges ctime, which needs the system clock moved. The periodic full read bounds that to
 * FULL_REREAD_MAX_AGE_MS; for custody, verifyChain detects such an edit independently.
 */
import { open, stat } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { StateLock } from "../analysis/stateLock.js";

/** A snapshot older than this (since its full read) is not used; the next read is a full one. */
export const FULL_REREAD_MAX_AGE_MS = 30_000;

/** How many of the file's last bytes a snapshot keeps and re-checks before every use. */
const TAIL_WINDOW_BYTES = 4096;

/**
 * Folds each non-blank line of a log into a state. `step` may throw (a corrupted line): the full
 * read passes the error to the caller and caches nothing. `rawIndex` is the line's 0-based index in
 * `text.split("\n")`, blank lines included.
 */
export interface LogFold<S> {
  readonly id: string;
  readonly initial: S;
  step(state: S, line: string, rawIndex: number): S;
}

/** How a read was served — tests assert on it; callers never need it. */
export type LogTailRead = "absent" | "full" | "cached";

export interface LogTailResult<S> {
  state: S;
  /** Non-blank lines in the log (custody's "records"). */
  lineCount: number;
  /** The last non-blank line, verbatim; null for an empty or missing log. */
  lastLine: string | null;
  read: LogTailRead;
}

interface Fingerprint {
  dev: bigint;
  ino: bigint;
  size: number;
  mtimeNs: bigint;
  ctimeNs: bigint;
}

interface Snapshot extends Fingerprint {
  caseId: string;
  generation: string;
  path: string;
  fold: LogFold<unknown>;
  /** The file's last ≤ TAIL_WINDOW_BYTES bytes at `size`. */
  tail: Buffer;
  /** Count of "\n" in the file — the raw index the next appended line starts at. */
  newlines: number;
  state: unknown;
  lineCount: number;
  lastLine: string | null;
  /** performance.now() of the full read behind this snapshot. */
  fullAt: number;
}

interface Scope {
  caseId: string;
  generation: string;
}

const NEWLINE = 0x0a;

export class AppendOnlyLogTail {
  private readonly snapshots = new Map<string, Snapshot>();
  // Per log: a read's check-then-use and an append's check-write-recheck never interleave in-process.
  private readonly lock = new StateLock();

  constructor(private readonly now: () => number = () => performance.now()) {}

  read<S>(scope: Scope, path: string, fold: LogFold<S>): Promise<LogTailResult<S>> {
    return this.lock.runExclusive(path, () => this.readLocked(scope, path, fold));
  }

  /**
   * Append `text` (whole lines, ending in "\n") by running `write`, and move this log's snapshots
   * forward over exactly those lines — only when the file before the write still carried the
   * snapshot's fingerprint and after it is that file grown by exactly `text`. Otherwise every
   * snapshot of the log is dropped. `write`'s own errors propagate unchanged.
   */
  append(path: string, text: string, write: () => Promise<void>): Promise<void> {
    return this.lock.runExclusive(path, async () => {
      const before = await fingerprintAt(path);
      const current = this.snapshotsOf(path).filter((s) => before !== null && sameFile(s, before));
      this.dropPath(path);
      await write();
      if (current.length === 0 || !text.endsWith("\n")) return;
      const added = Buffer.from(text, "utf8");
      const after = await fingerprintAt(path);
      if (!after || after.dev !== before!.dev || after.ino !== before!.ino) return;
      if (after.size !== before!.size + added.length) return;
      if (!(await bytesAt(path, after.size - added.length, added))) return;
      for (const snap of current) {
        const next = advance(snap, after, added);
        if (next) this.snapshots.set(keyOf(snap.fold.id, path), next);
      }
    });
  }

  /** Drop every snapshot of a deleted or replaced case. */
  forget(caseId: string): void {
    for (const [key, snap] of this.snapshots) if (snap.caseId === caseId) this.snapshots.delete(key);
  }

  private async readLocked<S>(scope: Scope, path: string, fold: LogFold<S>): Promise<LogTailResult<S>> {
    const key = keyOf(fold.id, path);
    let handle: FileHandle;
    try {
      handle = await open(path, "r");
    } catch (err) {
      this.dropPath(path);
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return { state: fold.initial, lineCount: 0, lastLine: null, read: "absent" };
      }
      throw err;
    }
    try {
      const st = await fingerprintOf(handle);
      const snap = this.snapshots.get(key);
      if (snap && this.usable(snap, scope, st) && (await tailStillThere(handle, snap))) {
        return { state: snap.state as S, lineCount: snap.lineCount, lastLine: snap.lastLine, read: "cached" };
      }
      this.snapshots.delete(key);
      return await this.fullRead(handle, key, path, scope, st, fold);
    } finally {
      await handle.close();
    }
  }

  private usable(snap: Snapshot, scope: Scope, st: Fingerprint): boolean {
    return (
      snap.caseId === scope.caseId &&
      snap.generation === scope.generation &&
      sameFile(snap, st) &&
      this.now() - snap.fullAt < FULL_REREAD_MAX_AGE_MS
    );
  }

  private async fullRead<S>(
    handle: FileHandle,
    key: string,
    path: string,
    scope: Scope,
    st: Fingerprint,
    fold: LogFold<S>,
  ): Promise<LogTailResult<S>> {
    const bytes = await handle.readFile();
    const parts = bytes.toString("utf8").split("\n");
    let state = fold.initial;
    let lineCount = 0;
    let lastLine: string | null = null;
    for (const [index, line] of parts.entries()) {
      if (!line.trim()) continue;
      state = fold.step(state, line, index); // throws to the caller; nothing is cached
      lineCount += 1;
      lastLine = line;
    }
    // Cache only a read of exactly the bytes the fingerprint describes, on a line boundary, from a
    // file that did not move while it was read (a second fstat agrees with the first).
    const whole = bytes.length === st.size && (st.size === 0 || bytes[bytes.length - 1] === NEWLINE);
    if (whole && sameFile(st, await fingerprintOf(handle))) {
      this.snapshots.set(key, {
        ...scope,
        ...st,
        path,
        fold,
        tail: lastBytes(bytes),
        newlines: parts.length - 1,
        state,
        lineCount,
        lastLine,
        fullAt: this.now(),
      });
    }
    return { state, lineCount, lastLine, read: "full" };
  }

  private snapshotsOf(path: string): Snapshot[] {
    return [...this.snapshots.values()].filter((s) => s.path === path);
  }

  private dropPath(path: string): void {
    for (const [key, snap] of this.snapshots) if (snap.path === path) this.snapshots.delete(key);
  }
}

function keyOf(foldId: string, path: string): string {
  return `${foldId}\0${path}`;
}

function sameFile(a: Fingerprint, b: Fingerprint): boolean {
  return (
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.size === b.size &&
    a.mtimeNs === b.mtimeNs &&
    a.ctimeNs === b.ctimeNs
  );
}

/** `snap` folded over this process's own appended bytes; null when a line will not fold (dropped). */
function advance(snap: Snapshot, after: Fingerprint, added: Buffer): Snapshot | null {
  const parts = added.toString("utf8").split("\n");
  let { state, lineCount, lastLine } = snap;
  try {
    for (let i = 0; i < parts.length - 1; i++) {
      const line = parts[i];
      if (!line.trim()) continue;
      state = snap.fold.step(state, line, snap.newlines + i);
      lineCount += 1;
      lastLine = line;
    }
  } catch {
    return null;
  }
  return {
    ...snap,
    ...after,
    tail: lastBytes(Buffer.concat([snap.tail, added])),
    newlines: snap.newlines + parts.length - 1,
    state,
    lineCount,
    lastLine,
  };
}

async function fingerprintOf(handle: FileHandle): Promise<Fingerprint> {
  return toFingerprint(await handle.stat({ bigint: true }));
}

async function fingerprintAt(path: string): Promise<Fingerprint | null> {
  try {
    return toFingerprint(await stat(path, { bigint: true }));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

function toFingerprint(st: { dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint }) {
  return { dev: st.dev, ino: st.ino, size: Number(st.size), mtimeNs: st.mtimeNs, ctimeNs: st.ctimeNs };
}

/** The snapshot's last bytes are still at the same offset. */
async function tailStillThere(handle: FileHandle, snap: Snapshot): Promise<boolean> {
  if (snap.tail.length === 0) return true;
  const now = await readRange(handle, snap.size - snap.tail.length, snap.tail.length);
  return now.equals(snap.tail);
}

async function bytesAt(path: string, position: number, expected: Buffer): Promise<boolean> {
  const handle = await open(path, "r");
  try {
    return (await readRange(handle, position, expected.length)).equals(expected);
  } finally {
    await handle.close();
  }
}

async function readRange(handle: FileHandle, position: number, length: number): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  let filled = 0;
  while (filled < length) {
    const { bytesRead } = await handle.read(buffer, filled, length - filled, position + filled);
    if (bytesRead === 0) break;
    filled += bytesRead;
  }
  return filled === length ? buffer : buffer.subarray(0, filled);
}

function lastBytes(bytes: Buffer): Buffer {
  return Buffer.from(bytes.subarray(Math.max(0, bytes.length - TAIL_WINDOW_BYTES)));
}
