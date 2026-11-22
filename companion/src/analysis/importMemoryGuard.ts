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
 * The estimate is linear in events and deliberately simple. First calibrated on SIEM rows (#1874),
 * re-measured across the main import paths in #2814 (synthetic data, a real server child, one case
 * per run, peak RSS sampled every 200 ms through the settle and a 20 s tail). Whole-file
 * Velociraptor ran with DFIR_IMPORT_BULK_MIN_MB raised, SIEM and EVTX XML with DFIR_MAX_EVENTS=50000,
 * so one file could add that many events; the rest ran at the defaults.
 * - RSS, under `npm run dev`'s 8 GB old-space limit. Imports into small cases cost the most per
 *   event: 123 KB at 20,000 events (whole-file Velociraptor), 115 KB at 35,000 (SIEM), 98 KB at
 *   35,000 (EVTX XML), 97 KB at 70,000 (the issue's bulk Velociraptor seed, default settings). Large
 *   cases cost less per event: 47-63 KB at 100,000-176,000 (bulk and whole-file Velociraptor, SIEM,
 *   EVTX XML), up to 9.3 GB at 176,000 on a long-running server. A real-world case of about 145,000
 *   events was killed at 11.4 GB (>= 80 KB per event, its true peak unknown). The small-case runs and
 *   that floor leave no room to lower 128 KB: it covers every run measured except the one below, and
 *   the killed one by 1.5x. A fixed base plus a smaller slope was rejected: much of the small-case
 *   peak is garbage that scales with the heap limit, so a base fitted at 8 GB over-charges a small
 *   machine.
 * - Heap, by pass/fail under a smaller old-space limit, against V8's whole heap limit (what this
 *   guard compares with): a 35,000-row SIEM import into an empty case completes under a 948 MB limit
 *   (`--max-old-space-size=900`; live heap 805 MB, the tightest run), and imports into a
 *   176,000-180,000-event case (a 50,000-row SIEM file; small Velociraptor and SIEM files) complete
 *   under 4,144 MB (`=4096`). 36 KB is 1.3x the first and 1.5x the second. (#1874's figure was 48 KB:
 *   the same SIEM import completed under 1.5 GB.)
 * - Not covered by either figure: a large file read whole whose kept rows are capped. A 100 MB SIEM
 *   file kept at 2,000 rows peaked about 0.9 GB above the idle server with 660 MB of live heap, against
 *   estimates of 250 MB and 70 MB. Its memory follows the file, not the events.
 * The case count comes from the index, so it is exact, not sampled from GC timing. The rows an
 * import will add are estimated from the file's size — about one event per 200 bytes, which
 * over-counts every format we measured — capped by DFIR_MAX_EVENTS. When the caller does not know
 * the size (a Velociraptor monitor poll), the default cap of 2,000 stands in: an operator who
 * raised DFIR_MAX_EVENTS for a full MFT import must not have every small import refused. The same
 * 2,000 stands in for an uncapped caller that cannot give a size, not lowered by DFIR_MAX_EVENTS.
 *
 * Admitted imports RESERVE their estimates — memory and heap — until their import section is
 * released, so two cases importing at once cannot both be admitted against the same free memory or
 * the one process-wide V8 heap.
 *
 * Only a caller that has already stored the evidence is admitted through here (analysis/importLock.ts
 * runs admission only when given a size hint), so "the file is saved in the case" is true.
 *
 * An import that can outgrow its admission — the bulk Velociraptor importer keeps every graded row,
 * not DFIR_MAX_EVENTS of them (#2812) — re-checks itself as it grows (`openSectionCheck`): against the
 * real count, with its own reservation set aside, growing that reservation when it still fits. Only
 * the import SECTION's admission can be re-checked (ImportLock marks it), so a caller that took the
 * section without a size hint — evidence perhaps not stored yet — is never refused mid-run.
 */
export const IMPORT_RSS_BYTES_PER_EVENT = 128 * 1024;
export const IMPORT_HEAP_BYTES_PER_EVENT = 36 * 1024;
export const IMPORT_INPUT_BYTES_PER_EVENT = 200;
const UNSIZED_INCOMING_EVENTS = 2000;

export class ImportMemoryRefusedError extends Error {
  /**
   * True when other admitted imports held reservations at the refusal: memory may free up once they
   * finish, so a caller able to retry later (the drop folder, #2785) waits instead of failing.
   */
  readonly othersReserved: boolean;
  constructor(message: string, othersReserved = false) {
    super(message);
    this.othersReserved = othersReserved;
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
  /** The refusal's wording for what was stored and how to retry — see ImportAdmissionHint. */
  wording?: RefusalWording;
}

/**
 * What a refusal tells the analyst about their evidence and the retry. The defaults fit an uploaded
 * file; a path that stores something else (a hunt's rows) or retries differently (Collect now) says so.
 */
export interface RefusalWording {
  /** A sentence without its full stop, e.g. "The file is saved in the case". */
  saved?: string;
  /** What to do once memory is free, e.g. "import the file again". */
  retry?: string;
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
      `${why} ${input.wording?.saved ?? "The file is saved in the case"} and nothing was changed. ${fix} ` +
      `Then ${input.wording?.retry ?? "import the file again"}. To import anyway, set DFIR_IMPORT_MEMORY_GUARD=off.`,
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
  /** The refusal's wording, when the default ("the file is saved…import the file again") is untrue. */
  wording?: RefusalWording;
  /** The work is not bound by DFIR_MAX_EVENTS (a Sigma re-grade re-parses every stored file), so the
   *  estimate is not capped by it either. */
  uncapped?: boolean;
}

/** How the admission is held. */
export interface AdmitOptions {
  /** The case's import section holds it (ImportLock): the running import may re-check it (#2812). */
  section?: boolean;
}

/** Admit an import for a case; resolves to the release for its reservation, or throws the refusal. */
export interface ImportAdmission {
  admit(caseId: string, hint?: ImportAdmissionHint, opts?: AdmitOptions): Promise<() => void>;
}

/** Re-check the running import with `addedEvents` rows added so far; throws the refusal (#2812). */
export type SectionMemoryCheck = (addedEvents: number) => void;

export interface ImportMemoryGuard extends ImportAdmission {
  reservedBytes(): number;
  /**
   * A re-check for the import running in the case's section, based on the case's event count NOW
   * (one indexed count per call, so rows an earlier file of the same section committed are counted).
   * Null — nothing to re-check, never a refusal — when the guard is off, the section was admitted
   * without a size hint or not at all, or the case cannot be counted.
   */
  openSectionCheck(caseId: string): Promise<SectionMemoryCheck | null>;
}

export interface ImportMemoryGuardDeps {
  countEvents(caseId: string): Promise<number>;
  probe?: () => MemorySnapshot;
  /** The per-import event cap; DFIR_MAX_EVENTS by default. */
  maxEvents?: () => number;
}

export function estimateIncomingEvents(maxEvents: number, hint?: ImportAdmissionHint): number {
  const rows = hint?.incomingEvents;
  const sized = hint?.uncapped ? Number.MAX_SAFE_INTEGER : maxEvents;
  if (typeof rows === "number" && Number.isFinite(rows) && rows >= 0) return Math.min(sized, rows);
  const bytes = hint?.incomingBytes;
  if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes < 0) {
    return Math.min(sized, UNSIZED_INCOMING_EVENTS);
  }
  return Math.min(sized, Math.ceil(bytes / IMPORT_INPUT_BYTES_PER_EVENT));
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

/** One admitted import's reservation; replaced, never mutated, when a re-check grows it. */
interface Reservation {
  readonly events: number;
  readonly needBytes: number;
  readonly heapNeedBytes: number;
  readonly wording?: RefusalWording;
}

export function createImportMemoryGuard(deps: ImportMemoryGuardDeps): ImportMemoryGuard {
  const probe = deps.probe ?? processMemorySnapshot;
  const maxEvents = deps.maxEvents ?? maxEventsDefault;
  let reserved = 0;
  let reservedHeap = 0;
  // The reservation each case's import SECTION holds — one at most: the import lock is per case.
  const sections = new Map<string, { token: object; held: Reservation }>();

  const hold = (next: Reservation, prev?: Reservation): void => {
    reserved += next.needBytes - (prev?.needBytes ?? 0);
    reservedHeap += next.heapNeedBytes - (prev?.heapNeedBytes ?? 0);
  };

  const recheck = (caseId: string, token: object, caseEvents: number, addedEvents: number): void => {
    const entry = sections.get(caseId);
    if (!entry || entry.token !== token || !importMemoryGuardEnabled()) return;
    const own = entry.held;
    if (caseEvents + addedEvents <= own.events) return; // within what it holds: nothing to ask
    const othersBytes = reserved - own.needBytes;
    const othersHeap = reservedHeap - own.heapNeedBytes;
    const verdict = assessImportMemory({
      caseEvents,
      incomingEvents: addedEvents,
      reservedBytes: othersBytes,
      reservedHeapBytes: othersHeap,
      wording: own.wording,
      ...probe(),
    });
    if (!verdict.ok) throw new ImportMemoryRefusedError(verdict.message, othersBytes > 0 || othersHeap > 0);
    const grown: Reservation = {
      events: caseEvents + addedEvents,
      needBytes: Math.max(own.needBytes, verdict.needBytes),
      heapNeedBytes: Math.max(own.heapNeedBytes, verdict.heapNeedBytes),
      wording: own.wording,
    };
    hold(grown, own);
    sections.set(caseId, { token, held: grown });
  };

  return {
    reservedBytes: () => reserved,
    async admit(caseId, hint, opts) {
      if (!importMemoryGuardEnabled()) return NOTHING_RESERVED;
      let caseEvents: number;
      try {
        caseEvents = await deps.countEvents(caseId);
      } catch {
        // Fail open: a guard that cannot count must never be the reason an import is lost.
        return NOTHING_RESERVED;
      }
      const incomingEvents = estimateIncomingEvents(maxEvents(), hint);
      const verdict = assessImportMemory({
        caseEvents,
        incomingEvents,
        reservedBytes: reserved,
        reservedHeapBytes: reservedHeap,
        wording: hint?.wording,
        ...probe(),
      });
      if (!verdict.ok) throw new ImportMemoryRefusedError(verdict.message, reserved > 0 || reservedHeap > 0);
      const admitted: Reservation = {
        events: caseEvents + incomingEvents,
        needBytes: verdict.needBytes,
        heapNeedBytes: verdict.heapNeedBytes,
        wording: hint?.wording,
      };
      hold(admitted);
      const token = {};
      if (opts?.section) sections.set(caseId, { token, held: admitted });
      let held = true;
      return () => {
        if (!held) return;
        held = false;
        const entry = sections.get(caseId);
        const current = entry?.token === token ? entry.held : admitted; // grown by re-checks, if any
        if (entry?.token === token) sections.delete(caseId);
        reserved -= current.needBytes;
        reservedHeap -= current.heapNeedBytes;
      };
    },
    async openSectionCheck(caseId) {
      const entry = sections.get(caseId);
      if (!entry || !importMemoryGuardEnabled()) return null;
      let caseEvents: number;
      try {
        caseEvents = await deps.countEvents(caseId);
      } catch {
        return null; // fail open, as admission does
      }
      return (addedEvents) => recheck(caseId, entry.token, caseEvents, addedEvents);
    },
  };
}

/** What the server's guard counts a case with: the forensic table's index (the state store). */
export interface ForensicEventIndex {
  queryForensicTimeline(
    caseId: string,
    query: { limit: number; includeTotal: boolean },
  ): Promise<{ total: number }>;
}

/** The server's guard, sized from the case's indexed event count; no index → every case counts 0. */
export function createCaseImportMemoryGuard(index?: ForensicEventIndex): ImportMemoryGuard {
  return createImportMemoryGuard({
    countEvents: async (caseId) =>
      index ? (await index.queryForensicTimeline(caseId, { limit: 1, includeTotal: true })).total : 0,
  });
}
