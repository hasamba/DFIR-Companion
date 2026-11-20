import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import { isSafeDropRelpath } from "../storage/dropRelpath.js";
import { isSafeZipEntryPath } from "./caseRestore.js";
import type { DropFileStat } from "./dropScan.js";

/**
 * Hunt-zip result files held over a size limit, and the analyst's decisions (#2746):
 * `state/hunt-held.json`. One record per ARCHIVE (the ledger's id: relpath, size and every member's
 * name, CRC and sizes), so a different zip dropped under the same name never inherits a decision.
 *
 * - The holds are worked out once, the first time an archive is seen, and frozen: totals never shrink
 *   as members import, and a settings change does not re-evaluate an archive already held.
 * - `waiting` is set only when the zip's last run ended with nothing left but undecided holds. The sweep
 *   then leaves that zip alone (no Jobs row every poll) until a decision arrives or the file changes.
 * - A decided entry is removed once its outcome is in the zip's ledger.
 *
 * The file is validated on load, and an entry naming an unsafe path is dropped: it is machine-local,
 * but nothing here trusts it more than the drop status does.
 */

const entrySchema = z.object({
  member: z.string().refine(isSafeZipEntryPath),
  artifact: z.string().catch(""),
  host: z.string().catch(""),
  bytes: z.number().catch(0),
  groupBytes: z.number().catch(0),
  reason: z.enum(["host", "total"]).catch("total"),
  limitMb: z.number().catch(0),
  decision: z.enum(["import", "skip"]).optional().catch(undefined),
});

const validEntries = z
  .array(z.unknown())
  .catch([])
  .transform((list) => list.flatMap((e) => (entrySchema.safeParse(e).success ? [entrySchema.parse(e)] : [])));

const archiveSchema = z.object({
  archiveId: z.string().regex(/^[0-9a-f]{8,64}$/),
  relpath: z.string().refine(isSafeDropRelpath),
  size: z.number(),
  mtimeMs: z.number(),
  waiting: z.boolean().catch(false),
  entries: validEntries,
});

// A bundle hunt's artifact held over a limit (#2753): held as a whole, decided per artifact, and the
// decision is followed by every later collect of that hunt (a collect re-reads the full results).
const huntEntrySchema = z.object({
  artifact: z
    .string()
    .min(1)
    .max(256)
    .regex(/^[^\u0000-\u001f]+$/),
  bytes: z.number().catch(0),
  /** The PC(s) whose results crossed the per-PC limit (capped), empty for the across-PCs limit. */
  hosts: z.array(z.string().max(256)).max(20).catch([]),
  hostBytes: z.number().catch(0),
  reason: z.enum(["host", "total"]).catch("total"),
  limitMb: z.number().catch(0),
  decision: z.enum(["import", "skip"]).optional().catch(undefined),
});
const huntSchema = z.object({
  huntId: z.string().regex(/^H\.[A-Za-z0-9]{1,64}$/),
  entries: z
    .array(z.unknown())
    .catch([])
    .transform((list) =>
      list.flatMap((e) => (huntEntrySchema.safeParse(e).success ? [huntEntrySchema.parse(e)] : [])),
    ),
});

const validList = <S extends z.ZodTypeAny>(schema: S) =>
  z
    .array(z.unknown())
    .catch([])
    .transform((list): z.output<S>[] =>
      list.flatMap((a) => {
        const r = schema.safeParse(a);
        return r.success ? [r.data as z.output<S>] : [];
      }),
    );

const fileSchema = z.object({
  archives: validList(archiveSchema),
  hunts: validList(huntSchema),
});

export type HeldEntry = z.infer<typeof entrySchema>;
export type HeldArchive = z.infer<typeof archiveSchema>;
export type HeldDecision = "import" | "skip";
export type HeldHuntEntry = z.infer<typeof huntEntrySchema>;
export type HeldHunt = z.infer<typeof huntSchema>;

export interface HuntDecisionInput {
  huntId: string;
  artifact: string;
  decision: HeldDecision;
}

interface HeldFile {
  archives: HeldArchive[];
  hunts: HeldHunt[];
}

export interface DecisionInput {
  archiveId: string;
  member: string;
  decision: HeldDecision;
}

export const HUNT_HELD_FILE = "hunt-held.json";

export class HuntHeldStore {
  private readonly queues = new Map<string, Promise<unknown>>();

  constructor(private readonly stateDir: (caseId: string) => string) {}

  private path(caseId: string): string {
    return join(this.stateDir(caseId), HUNT_HELD_FILE);
  }

  private async read(caseId: string): Promise<HeldFile> {
    try {
      return fileSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT" || err instanceof SyntaxError)
        return { archives: [], hunts: [] };
      throw err;
    }
  }

  /** One read-modify-write of the whole file for a case, after every earlier one; no `next`, no write. */
  private serialFile<T>(caseId: string, fn: (file: HeldFile) => { next?: HeldFile; result: T }): Promise<T> {
    const run = (this.queues.get(caseId) ?? Promise.resolve()).then(async () => {
      const { next, result } = fn(await this.read(caseId));
      if (next) await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return result;
    });
    this.queues.set(
      caseId,
      run.catch(() => undefined),
    );
    return run;
  }

  /** The zip records; the hunt records are carried through unchanged. */
  private serial<T>(
    caseId: string,
    fn: (list: HeldArchive[]) => { next?: HeldArchive[]; result: T },
  ): Promise<T> {
    return this.serialFile(caseId, (file) => {
      const { next, result } = fn(file.archives);
      return next ? { next: { ...file, archives: next }, result } : { result };
    });
  }

  /** The hunt records; the zip records are carried through unchanged. */
  private serialHunts<T>(
    caseId: string,
    fn: (list: HeldHunt[]) => { next?: HeldHunt[]; result: T },
  ): Promise<T> {
    return this.serialFile(caseId, (file) => {
      const { next, result } = fn(file.hunts);
      return next ? { next: { ...file, hunts: next }, result } : { result };
    });
  }

  listHunts(caseId: string): Promise<HeldHunt[]> {
    return this.serialHunts(caseId, (list) => ({ result: list }));
  }

  /**
   * Record one collect pass's held artifacts. A held artifact keeps any decision it has; an undecided
   * entry for an artifact this pass downloaded but did not hold is dropped (it now fits). Entries for
   * artifacts this pass did not download are kept as they are, and decided entries are never dropped.
   */
  putHuntHolds(
    caseId: string,
    huntId: string,
    downloaded: readonly string[],
    held: readonly HeldHuntEntry[],
  ): Promise<void> {
    return this.serialHunts(caseId, (list) => {
      const prev = list.find((h) => h.huntId === huntId)?.entries ?? [];
      const heldNames = new Set(held.map((e) => e.artifact));
      const fetched = new Set(downloaded);
      const kept = prev.filter((e) => !heldNames.has(e.artifact) && (e.decision || !fetched.has(e.artifact)));
      const fresh = held.map((e) => {
        const before = prev.find((p) => p.artifact === e.artifact);
        return before?.decision ? { ...e, decision: before.decision } : { ...e, decision: undefined };
      });
      const entries = [...kept, ...fresh];
      const rest = list.filter((h) => h.huntId !== huntId);
      if (!entries.length && rest.length === list.length) return { result: undefined };
      return { next: entries.length ? [...rest, { huntId, entries }] : rest, result: undefined };
    });
  }

  /** Apply decisions to held hunt artifacts that exist; returns the decisions applied. */
  decideHunts(caseId: string, decisions: readonly HuntDecisionInput[]): Promise<HuntDecisionInput[]> {
    return this.serialHunts(caseId, (list) => {
      const applied: HuntDecisionInput[] = [];
      const next = list.map((h) => ({
        ...h,
        entries: h.entries.map((e) => {
          const d = decisions.find((x) => x.huntId === h.huntId && x.artifact === e.artifact);
          if (!d) return e;
          applied.push(d);
          return { ...e, decision: d.decision };
        }),
      }));
      return applied.length ? { next, result: applied } : { result: [] };
    });
  }

  list(caseId: string): Promise<HeldArchive[]> {
    return this.serial(caseId, (list) => ({ result: list }));
  }

  get(caseId: string, archiveId: string): Promise<HeldArchive | undefined> {
    return this.serial(caseId, (list) => ({ result: list.find((a) => a.archiveId === archiveId) }));
  }

  /** Replace (or add) one archive's record; no entries left removes it. */
  put(caseId: string, archive: HeldArchive): Promise<void> {
    return this.serial(caseId, (list) => {
      const rest = list.filter((a) => a.archiveId !== archive.archiveId);
      return { next: archive.entries.length ? [...rest, archive] : rest, result: undefined };
    });
  }

  /** Edit one archive's CURRENT record in place (decisions that arrived meanwhile are kept). */
  update(
    caseId: string,
    archiveId: string,
    fn: (rec: HeldArchive) => HeldArchive,
  ): Promise<HeldArchive | undefined> {
    return this.serial(caseId, (list) => {
      const rec = list.find((a) => a.archiveId === archiveId);
      if (!rec) return { result: undefined };
      const next = fn(rec);
      const rest = list.filter((a) => a.archiveId !== archiveId);
      return { next: next.entries.length ? [...rest, next] : rest, result: next };
    });
  }

  remove(caseId: string, archiveId: string): Promise<void> {
    return this.serial(caseId, (list) =>
      list.some((a) => a.archiveId === archiveId)
        ? { next: list.filter((a) => a.archiveId !== archiveId), result: undefined }
        : { result: undefined },
    );
  }

  /** Apply the analyst's decisions to entries that exist; returns how many were applied. */
  decide(caseId: string, decisions: readonly DecisionInput[]): Promise<number> {
    return this.serial(caseId, (list) => {
      let applied = 0;
      const next = list.map((a) => {
        const mine = decisions.filter((d) => d.archiveId === a.archiveId);
        if (!mine.length) return a;
        let touched = false;
        const entries = a.entries.map((e) => {
          const d = mine.find((x) => x.member === e.member);
          if (!d) return e;
          applied += 1;
          touched = true;
          return { ...e, decision: d.decision };
        });
        return touched ? { ...a, entries, waiting: false } : a;
      });
      return applied ? { next, result: applied } : { result: 0 };
    });
  }

  /** Drop the records of zips no longer in drop/. */
  prune(caseId: string, listing: readonly DropFileStat[]): Promise<void> {
    const present = new Set(listing.map((f) => f.relpath.replace(/\\/g, "/")));
    return this.serial(caseId, (list) => {
      const next = list.filter((a) => present.has(a.relpath));
      return next.length === list.length ? { result: undefined } : { next, result: undefined };
    });
  }

  /**
   * `ready` without the zips that wait only for the analyst: the record matches the file as it is now,
   * the zip's last run left nothing else to do, and no decision has arrived since.
   */
  async excludeAwaiting(caseId: string, ready: readonly DropFileStat[]): Promise<DropFileStat[]> {
    const list = await this.list(caseId);
    if (!list.length) return [...ready];
    return ready.filter((f) => {
      const rel = f.relpath.replace(/\\/g, "/");
      const rec = list.find((a) => a.relpath === rel);
      const idle =
        rec &&
        rec.waiting &&
        rec.size === f.size &&
        rec.mtimeMs === f.mtimeMs &&
        rec.entries.every((e) => !e.decision);
      return !idle;
    });
  }
}

const stores = new WeakMap<object, HuntHeldStore>();

/** One store per case store, shared by the drop sweep and the held-artifacts routes. */
export function huntHeldStoreFor(cases: { stateDir: (caseId: string) => string }): HuntHeldStore {
  let s = stores.get(cases);
  if (!s) {
    s = new HuntHeldStore((caseId) => cases.stateDir(caseId));
    stores.set(cases, s);
  }
  return s;
}
