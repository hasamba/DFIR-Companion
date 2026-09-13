import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";

// How far each destination has forwarded each case's activity log (#929).
//
// THIS FILE IS WHY THE EXPORT IS SAFE TO RESTART. #929's proposal had no notion of a position: an
// exporter that simply "batches activity log entries and POSTs them" either re-sends a case's whole
// history every time it runs, or forwards only what it happened to see while it was up and loses
// everything appended during a restart. Neither is an audit trail.
//
// The position is a COUNT OF RAW LINES consumed from the append-only activity.jsonl — not a count
// of parsed entries and not a byte offset. Raw lines because ActivityLogStore skips a corrupt line
// rather than failing, so counting parsed entries would shift the position by one for every skipped
// line and re-send a good entry forever. Lines rather than bytes because the file is only ever
// appended to, so a line index is stable, and a truncated final line cannot make the next read
// start mid-record.

const cursorFileSchema = z.record(z.string(), z.number());

/** `${destinationId}\u0000${caseId}` — NUL cannot occur in either id, so the key cannot collide. */
function key(destinationId: string, caseId: string): string {
  return `${destinationId}\u0000${caseId}`;
}

export class AuditCursorStore {
  private readonly lock = new StateLock();

  constructor(private readonly file: string) {}

  private async loadAll(): Promise<Record<string, number>> {
    try {
      const parsed = cursorFileSchema.safeParse(JSON.parse(await readFile(this.file, "utf8")));
      return parsed.success ? parsed.data : {};
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  private async persist(all: Record<string, number>): Promise<void> {
    const dir = dirname(this.file);
    if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, JSON.stringify(all, null, 2));
  }

  /** Lines already forwarded. 0 for a pair never seen, which is also "send everything". */
  async get(destinationId: string, caseId: string): Promise<number> {
    const value = (await this.loadAll())[key(destinationId, caseId)];
    return Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
  }

  /**
   * Advance the high-water mark. NEVER moves it backwards: two overlapping sends would otherwise
   * let the slower one rewind the position and re-send entries the SIEM already holds.
   */
  set(destinationId: string, caseId: string, lines: number): Promise<void> {
    return this.lock.runExclusive(this.file, async () => {
      const all = await this.loadAll();
      const k = key(destinationId, caseId);
      const next = Math.max(all[k] ?? 0, Math.max(0, Math.floor(lines)));
      if (all[k] === next) return;
      await this.persist({ ...all, [k]: next });
    });
  }

  /**
   * Force one pair back to the beginning. `set` refuses to move backwards on purpose, so a
   * backfill — the one operation that legitimately rewinds — needs its own door.
   */
  reset(destinationId: string, caseId: string): Promise<void> {
    return this.lock.runExclusive(this.file, async () => {
      const all = await this.loadAll();
      const k = key(destinationId, caseId);
      if (!(k in all)) return;
      const next = { ...all };
      delete next[k];
      await this.persist(next);
    });
  }

  /** Drop every position for a removed destination, so a re-added one starts clean. */
  clearDestination(destinationId: string): Promise<void> {
    return this.lock.runExclusive(this.file, async () => {
      const all = await this.loadAll();
      const prefix = `${destinationId}\u0000`;
      const next = Object.fromEntries(Object.entries(all).filter(([k]) => !k.startsWith(prefix)));
      if (Object.keys(next).length === Object.keys(all).length) return;
      await this.persist(next);
    });
  }
}
