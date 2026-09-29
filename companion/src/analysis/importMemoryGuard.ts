import { getHeapStatistics } from "node:v8";
import { maxEventsDefault } from "./eventAggregate.js";

/**
 * The import memory guard (#1874).
 *
 * An import's peak memory grows with the size of the WHOLE case, not with the file: every import
 * loads and saves the full investigation state several times (snapshot, merge, stamp, tag, demote,
 * undo checkpoint). Past what the machine can give, the kernel kills the server — every case at
 * once, with nothing to restart it. This guard refuses the import first, with a message that says
 * why and what to do. It runs after the evidence is stored, so a refusal loses nothing.
 *
 * The estimate is linear in events and deliberately simple, calibrated on measured runs (SIEM rows,
 * `npm run dev`'s 8 GB old-space limit):
 * - one 35,000-row import into a fresh case peaked at 4.8 GB of process memory, and one 20,000-row
 *   import at 3.1 GB — about 130 KB of peak RSS per event, counting the SQLite worker, native
 *   memory and the garbage V8 has not collected yet (it collects lazily below its limit);
 * - the same 35,000-row import completed under a 1.5 GB heap limit — at most about 44 KB of live
 *   heap per event.
 * The case count comes from the index, so it is exact, not sampled from GC timing. The rows an
 * import will add are estimated from the file's size — about one event per 200 bytes, which
 * over-counts every format we measured — capped by DFIR_MAX_EVENTS. When the caller does not know
 * the size (a Velociraptor monitor poll), the default cap of 2,000 stands in: an operator who
 * raised DFIR_MAX_EVENTS for a full MFT import must not have every small import refused.
 *
 * Admitted imports RESERVE their estimates — memory and heap — until their import section is
 * released, so two cases importing at once cannot both be admitted against the same free memory or
 * the one process-wide V8 heap.
 *
 * Only a caller that has already stored the evidence is admitted through here (analysis/importLock.ts
 * runs admission only when given a size hint), so "the file is saved in the case" is true.
 */
export const IMPORT_RSS_BYTES_PER_EVENT = 128 * 1024;
export const IMPORT_HEAP_BYTES_PER_EVENT = 48 * 1024;
export const IMPORT_INPUT_BYTES_PER_EVENT = 200;
const UNSIZED_INCOMING_EVENTS = 2000;

export class ImportMemoryRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImportMemoryRefusedError";
  }
}

export interface MemorySnapshot {
  /** What the process can still allocate — free memory, capped by any container limit. */
  availableBytes: number;
  /** Current resident memory. Counted as usable: garbage in it is reclaimed before the OS is asked. */
  rssBytes: number;
  heapLimitBytes: number;
}

export interface MemoryAssessmentInput extends MemorySnapshot {
  caseEvents: number;
  incomingEvents: number;
  /** Estimates other admitted imports hold. */
  reservedBytes: number;
  /** Their heap estimates: the V8 heap is one per process, shared by every case's import. */
  reservedHeapBytes?: number;
}

export type MemoryAssessment =
  { ok: true; needBytes: number; heapNeedBytes: number } | { ok: false; needBytes: number; message: string };

const gb = (bytes: number): string => `${(bytes / 1024 ** 3).toFixed(1)} GB`;
const count = (n: number): string => n.toLocaleString("en-US");

export function assessImportMemory(input: MemoryAssessmentInput): MemoryAssessment {
  const events = input.caseEvents + input.incomingEvents;
  const needBytes = events * IMPORT_RSS_BYTES_PER_EVENT;
  const usable = input.availableBytes + input.rssBytes - input.reservedBytes;
  const heapNeed = events * IMPORT_HEAP_BYTES_PER_EVENT;
  const refused = (why: string, fix: string): MemoryAssessment => ({
    ok: false,
    needBytes,
    message:
      `Import refused to protect the server: this case holds ${count(input.caseEvents)} events, and ` +
      `${why} The file is saved in the case and nothing was changed. ${fix} Then import the file ` +
      `again. To import anyway, set DFIR_IMPORT_MEMORY_GUARD=off.`,
  });
  if (needBytes > usable) {
    return refused(
      `processing another import needs about ${gb(needBytes)} of memory, but the server can use ` +
        `about ${gb(Math.max(0, usable))}${input.reservedBytes > 0 ? " while other imports run" : ""}.`,
      "Free memory on the machine, give the server more, or wait for other imports to finish.",
    );
  }
  // Not less the heap in use now: the per-event figure is already a total, and most of what V8
  // reports as used between imports is garbage it has not collected yet.
  const reservedHeap = input.reservedHeapBytes ?? 0;
  if (heapNeed > input.heapLimitBytes - reservedHeap) {
    return refused(
      `processing it needs about ${gb(heapNeed)} of JavaScript heap, but the server's heap limit is ` +
        `${gb(input.heapLimitBytes)}${reservedHeap > 0 ? `, ${gb(reservedHeap)} of it held by other imports` : ""}.`,
      reservedHeap > 0
        ? "Wait for other imports to finish, or restart the server with a larger heap (node --max-old-space-size=<MB>)."
        : "Restart the server with a larger heap (node --max-old-space-size=<MB>).",
    );
  }
  return { ok: true, needBytes, heapNeedBytes: heapNeed };
}

/** What the caller knows about the import it is about to run. */
export interface ImportAdmissionHint {
  /** Size of the artifact being imported, when known. */
  incomingBytes?: number;
  /** Rows the artifact holds, when the caller has counted them; preferred over the size. */
  incomingEvents?: number;
}

/** Admit an import for a case; resolves to the release for its reservation, or throws the refusal. */
export interface ImportAdmission {
  admit(caseId: string, hint?: ImportAdmissionHint): Promise<() => void>;
}

export interface ImportMemoryGuard extends ImportAdmission {
  reservedBytes(): number;
}

export interface ImportMemoryGuardDeps {
  countEvents(caseId: string): Promise<number>;
  probe?: () => MemorySnapshot;
  /** The per-import event cap; DFIR_MAX_EVENTS by default. */
  maxEvents?: () => number;
}

export function estimateIncomingEvents(maxEvents: number, hint?: ImportAdmissionHint): number {
  const rows = hint?.incomingEvents;
  if (typeof rows === "number" && Number.isFinite(rows) && rows >= 0) return Math.min(maxEvents, rows);
  const bytes = hint?.incomingBytes;
  if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes < 0) {
    return Math.min(maxEvents, UNSIZED_INCOMING_EVENTS);
  }
  return Math.min(maxEvents, Math.ceil(bytes / IMPORT_INPUT_BYTES_PER_EVENT));
}

export function importMemoryGuardEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = (env.DFIR_IMPORT_MEMORY_GUARD ?? "").trim().toLowerCase();
  return !["off", "0", "false", "no"].includes(value);
}

export function processMemorySnapshot(): MemorySnapshot {
  return {
    availableBytes: process.availableMemory(),
    rssBytes: process.memoryUsage.rss(),
    heapLimitBytes: getHeapStatistics().heap_size_limit,
  };
}

const NOTHING_RESERVED = (): void => {};

export function createImportMemoryGuard(deps: ImportMemoryGuardDeps): ImportMemoryGuard {
  const probe = deps.probe ?? processMemorySnapshot;
  const maxEvents = deps.maxEvents ?? maxEventsDefault;
  let reserved = 0;
  let reservedHeap = 0;
  return {
    reservedBytes: () => reserved,
    async admit(caseId, hint) {
      if (!importMemoryGuardEnabled()) return NOTHING_RESERVED;
      let caseEvents: number;
      try {
        caseEvents = await deps.countEvents(caseId);
      } catch {
        // Fail open: a guard that cannot count must never be the reason an import is lost.
        return NOTHING_RESERVED;
      }
      const verdict = assessImportMemory({
        caseEvents,
        incomingEvents: estimateIncomingEvents(maxEvents(), hint),
        reservedBytes: reserved,
        reservedHeapBytes: reservedHeap,
        ...probe(),
      });
      if (!verdict.ok) throw new ImportMemoryRefusedError(verdict.message);
      reserved += verdict.needBytes;
      reservedHeap += verdict.heapNeedBytes;
      let held = true;
      return () => {
        if (!held) return;
        held = false;
        reserved -= verdict.needBytes;
        reservedHeap -= verdict.heapNeedBytes;
      };
    },
  };
}
