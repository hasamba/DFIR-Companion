// The per-artifact Velociraptor import ledger (#2700): per case, per hunt or flow, per artifact,
// what the last import got — its status, row count, the server fingerprint taken before the read,
// and the settings it imported with. A re-import compares it with the server's current state and
// reads only what is new, changed or was not read in full (veloReimport.ts).
//
// The ledger is a convenience, never evidence: a missing, corrupt or wrong-shaped file reads as
// empty, which makes every artifact look stale — the same full re-read as before this existed.
// It can only ever cause extra reading, never a skipped one. Undo deletes it (importUndo.ts).

import { createHash } from "node:crypto";
import { mkdir, readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";

const LEDGER_FILE = "velo-import-ledger.json";

const entrySchema = z.object({
  importedAt: z.string(),
  // pending = the run started this artifact and did not finish it (an ingest failed, a crash).
  status: z.enum(["pending", "complete", "partial", "failed"]),
  rows: z.number().int().nonnegative(),
  gaps: z.array(z.enum(["truncated", "unread"])).optional(),
  fingerprint: z.string().optional(),
  superOnly: z.boolean(),
  minSeverity: z.string(),
});
export type LedgerEntry = z.infer<typeof entrySchema>;

const fileSchema = z.object({
  version: z.literal(1),
  sources: z.record(z.string(), z.record(z.string(), entrySchema)),
});
type LedgerFile = z.infer<typeof fileSchema>;

export interface LedgerStore {
  metadataDir(caseId: string): string;
}

export type LedgerRef = { kind: "hunt"; huntId: string } | { kind: "flow"; clientId: string; flowId: string };

/** The source key: the server and org it came from, then the hunt or the client's flow. */
export function veloLedgerKey(namespace: string, ref: LedgerRef): string {
  const ns = createHash("sha256").update(namespace).digest("hex").slice(0, 16);
  return ref.kind === "hunt" ? `${ns}|hunt:${ref.huntId}` : `${ns}|flow:${ref.clientId}/${ref.flowId}`;
}

const pathOf = (store: LedgerStore, caseId: string): string => join(store.metadataDir(caseId), LEDGER_FILE);

// One writer per ledger file: every read-modify-write and delete queues behind the previous one.
const queues = new Map<string, Promise<unknown>>();
function enqueue<T>(path: string, fn: () => Promise<T>): Promise<T> {
  const prev = queues.get(path) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  const settled = run.catch(() => undefined);
  queues.set(path, settled);
  void settled.then(() => {
    if (queues.get(path) === settled) queues.delete(path);
  });
  return run;
}

async function load(path: string): Promise<LedgerFile> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, sources: {} };
    throw err;
  }
  try {
    const parsed = fileSchema.safeParse(JSON.parse(text));
    return parsed.success ? parsed.data : { version: 1, sources: {} };
  } catch {
    return { version: 1, sources: {} }; // torn or hand-edited: forget it, everything re-reads
  }
}

/** One source's entries, by artifact; {} when the case has none. */
export async function readVeloLedger(
  store: LedgerStore,
  caseId: string,
  key: string,
): Promise<Record<string, LedgerEntry>> {
  const path = pathOf(store, caseId);
  const file = await enqueue(path, () => load(path));
  return { ...(file.sources[key] ?? {}) };
}

/** Upsert one artifact's entry. */
export function recordVeloArtifact(
  store: LedgerStore,
  caseId: string,
  key: string,
  artifact: string,
  entry: LedgerEntry,
): Promise<void> {
  const path = pathOf(store, caseId);
  return enqueue(path, async () => {
    const file = await load(path);
    const next: LedgerFile = {
      version: 1,
      sources: { ...file.sources, [key]: { ...(file.sources[key] ?? {}), [artifact]: entry } },
    };
    await mkdir(store.metadataDir(caseId), { recursive: true }); // the first write can precede any import
    await atomicWrite(path, JSON.stringify(next));
  });
}

/** Forget every source of the case (Undo, or a failed ledger write). */
export function clearVeloImportLedger(store: LedgerStore, caseId: string): Promise<void> {
  const path = pathOf(store, caseId);
  return enqueue(path, async () => {
    try {
      await unlink(path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
  });
}
