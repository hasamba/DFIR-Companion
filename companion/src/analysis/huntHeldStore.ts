import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import { isSafeDropRelpath } from "../storage/dropRelpath.js";

/**
 * Hunt results held over the size limits (#2746, #2753, #2755): `state/hunt-held.json`.
 *
 * THE DROP FOLDER IS THE STATE. A held result is a file under `drop/_held/<the path it would have in
 * drop/>`; this store only adds what the dashboard shows about it (artifact, PC, size, the limit it
 * crossed) and remembers what the files cannot:
 *
 * - `held`: the details of each file under `_held/` (a file with no details is still listed).
 * - `approved`: files the analyst released (Import anyway) or skipped, by path, size and modification
 *   time. A file that matches is never held again, so it imports when it is in drop/ — after Import
 *   anyway, or when the analyst moves a skipped file back. A move keeps the modification time, so a
 *   different file under the same name is not approved. The newest MAX_APPROVED are kept.
 * - `pending`: an unzipped hunt folder's files chosen to be held, recorded BEFORE any is moved, so a
 *   crash part-way finishes that decision instead of recomputing a smaller one from what is left.
 * - `hunts`: a bundle hunt's per-artifact decisions, followed by every later collect of that hunt.
 *
 * Validated on load; an entry naming an unsafe path is dropped.
 */

const MAX_LIST = 5000;
const MAX_APPROVED = 1000;

const metaSchema = z.object({
  origin: z.enum(["zip", "hunt", "file", "folder"]).catch("file"),
  /** What it came from: the zip's relpath, the hunt id, or the dropped path. */
  source: z.string().max(1024).catch(""),
  artifact: z.string().max(256).catch(""),
  host: z.string().max(256).catch(""),
  bytes: z.number().catch(0),
  groupBytes: z.number().catch(0),
  reason: z.enum(["host", "total"]).catch("host"),
  limitMb: z.number().catch(0),
  huntId: z.string().max(80).optional().catch(undefined),
});

const heldSchema = metaSchema.extend({
  /** Relative to drop/, starting with `_held/`. */
  rel: z
    .string()
    .refine(isSafeDropRelpath)
    .refine((r) => r.startsWith("_held/")),
});

const approvedSchema = z.object({
  relpath: z.string().refine(isSafeDropRelpath),
  size: z.number(),
  mtimeMs: z.number(),
});

const pendingSchema = z.object({ relpath: z.string().refine(isSafeDropRelpath), meta: metaSchema });

/** #2753 stored `entries: [{ artifact, decision? }]`; carried over into the decisions map. */
function fromLegacyHunt(raw: unknown): unknown {
  if (!raw || typeof raw !== "object" || "decisions" in raw) return raw;
  const entries = (raw as { entries?: unknown }).entries;
  const decisions: Record<string, unknown> = {};
  if (Array.isArray(entries))
    for (const e of entries) {
      const { artifact, decision } = (e ?? {}) as { artifact?: unknown; decision?: unknown };
      if (typeof artifact === "string" && (decision === "import" || decision === "skip"))
        decisions[artifact] = decision;
    }
  return { ...raw, decisions };
}

const huntSchema = z.preprocess(
  fromLegacyHunt,
  z.object({
    huntId: z.string().regex(/^H\.[A-Za-z0-9]{1,64}$/),
    decisions: z.record(z.string().max(256), z.enum(["import", "skip"])).catch({}),
  }),
);

const validList = <S extends z.ZodTypeAny>(schema: S) =>
  z
    .array(z.unknown())
    .catch([])
    .transform((list): z.output<S>[] =>
      list.slice(-MAX_LIST).flatMap((a) => {
        const r = schema.safeParse(a);
        return r.success ? [r.data as z.output<S>] : [];
      }),
    );

const fileSchema = z.object({
  held: validList(heldSchema),
  approved: validList(approvedSchema),
  pending: validList(pendingSchema),
  hunts: validList(huntSchema),
});

export type HeldMeta = z.infer<typeof metaSchema>;
export type HeldFileInfo = z.infer<typeof heldSchema>;
export type Approval = z.infer<typeof approvedSchema>;
export type PendingHold = z.infer<typeof pendingSchema>;
export type HeldDecision = "import" | "skip";
export type HeldState = z.infer<typeof fileSchema>;

export const HUNT_HELD_FILE = "hunt-held.json";

export interface FileIdentity {
  relpath: string;
  size: number;
  mtimeMs: number;
}

export function isApproved(state: HeldState, f: FileIdentity): boolean {
  const rel = f.relpath.replace(/\\/g, "/");
  return state.approved.some(
    (a) => a.relpath === rel && a.size === f.size && Math.abs(a.mtimeMs - f.mtimeMs) < 1,
  );
}

export class HuntHeldStore {
  private readonly queues = new Map<string, Promise<unknown>>();

  constructor(private readonly stateDir: (caseId: string) => string) {}

  private path(caseId: string): string {
    return join(this.stateDir(caseId), HUNT_HELD_FILE);
  }

  private async read(caseId: string): Promise<HeldState> {
    try {
      return fileSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT" || err instanceof SyntaxError)
        return { held: [], approved: [], pending: [], hunts: [] };
      throw err;
    }
  }

  /** One read-modify-write for a case after every earlier one; no `next`, no write. */
  private serial<T>(caseId: string, fn: (s: HeldState) => { next?: HeldState; result: T }): Promise<T> {
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

  load(caseId: string): Promise<HeldState> {
    return this.serial(caseId, (s) => ({ result: s }));
  }

  /** Record (or replace) the details of a held file. */
  putHeld(caseId: string, info: HeldFileInfo): Promise<void> {
    return this.serial(caseId, (s) => ({
      next: { ...s, held: [...s.held.filter((h) => h.rel !== info.rel), info] },
      result: undefined,
    }));
  }

  /** Forget the details of held files that are gone (imported, skipped, or moved by hand). */
  forgetMissing(caseId: string, heldRels: ReadonlySet<string>): Promise<void> {
    return this.serial(caseId, (s) => {
      const held = s.held.filter((h) => heldRels.has(h.rel));
      return held.length === s.held.length
        ? { result: undefined }
        : { next: { ...s, held }, result: undefined };
    });
  }

  /** Approve a file (released or skipped by the analyst), dropping the details of the held file it was. */
  approve(caseId: string, approval: Approval, fromHeldRel: string): Promise<void> {
    return this.serial(caseId, (s) => ({
      next: {
        ...s,
        held: s.held.filter((h) => h.rel !== fromHeldRel),
        approved: [...s.approved.filter((a) => a.relpath !== approval.relpath), approval].slice(
          -MAX_APPROVED,
        ),
      },
      result: undefined,
    }));
  }

  /** Add an unzipped folder's chosen holds, and/or clear the ones that were carried out. */
  setPending(caseId: string, add: readonly PendingHold[], done: readonly string[] = []): Promise<void> {
    return this.serial(caseId, (s) => {
      const drop = new Set([...done, ...add.map((p) => p.relpath)]);
      const pending = [...s.pending.filter((p) => !drop.has(p.relpath)), ...add];
      return { next: { ...s, pending }, result: undefined };
    });
  }

  huntDecisions(caseId: string, huntId: string): Promise<Record<string, HeldDecision>> {
    return this.serial(caseId, (s) => ({
      result: s.hunts.find((h) => h.huntId === huntId)?.decisions ?? {},
    }));
  }

  decideHunt(caseId: string, huntId: string, artifact: string, decision: HeldDecision): Promise<void> {
    return this.serial(caseId, (s) => {
      const prev = s.hunts.find((h) => h.huntId === huntId)?.decisions ?? {};
      const hunts = [
        ...s.hunts.filter((h) => h.huntId !== huntId),
        { huntId, decisions: { ...prev, [artifact]: decision } },
      ];
      return { next: { ...s, hunts }, result: undefined };
    });
  }
}

const stores = new WeakMap<object, HuntHeldStore>();

/** One store per case store, shared by the drop sweep, the hunt collect and the routes. */
export function huntHeldStoreFor(cases: { stateDir: (caseId: string) => string }): HuntHeldStore {
  let s = stores.get(cases);
  if (!s) {
    s = new HuntHeldStore((caseId) => cases.stateDir(caseId));
    stores.set(cases, s);
  }
  return s;
}
