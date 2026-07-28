import { readFile, appendFile, mkdir } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { join, relative, isAbsolute, sep } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { StateLock } from "./stateLock.js";

// Evidence here is disk images, memory dumps and Plaso super-timelines — routinely 400 MB+, and
// past V8's ~512 MB string ceiling. readFile() would OOM on exactly the artifacts custody matters
// most for, so hash in 1 MB chunks and never hold the file in memory.
export async function hashFile(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path, { highWaterMark: 1 << 20 })) {
    hash.update(chunk as Buffer);
  }
  return hash.digest("hex");
}

/**
 * What happened to the artifact. A custody chain is a sequence of events, not a one-off inventory
 * line — "collected" alone cannot answer who has since held or released the evidence.
 */
export const CUSTODY_EVENTS = ["collected", "accessed", "transferred", "exported"] as const;
export type CustodyEvent = (typeof CUSTODY_EVENTS)[number];

export function isCustodyEvent(value: unknown): value is CustodyEvent {
  return typeof value === "string" && (CUSTODY_EVENTS as readonly string[]).includes(value);
}

export interface CustodyRecord {
  /** Always absolute, in both directions — see StoredCustodyRecord for how it is persisted. */
  artifactPath: string;
  sha256: string;
  collectedBy: string;
  collectedAt: string;
  source: string;
  trigger: string;
  caseId: string;
  event: CustodyEvent;
  /** Position in this case's custody chain. Strictly increasing; gaps are legal (see nextCustodySeq). */
  seq: number;
  /** SHA-256 of the preceding stored line; "" for the first record in the log. */
  prevHash: string;
}

/**
 * What a caller hands to record(). `seq` and `prevHash` are the chain's business and are assigned
 * here, never accepted from outside — a caller that could pick its own would be able to forge a
 * link. `event` defaults to "collected".
 */
export type CustodyRecordInput = Omit<CustodyRecord, "seq" | "prevHash" | "event"> & { event?: CustodyEvent };

/**
 * How a record is written to custody.jsonl. An absolute path is only valid for as long as the case
 * folder stays put, and it does not: archiving moves it to <root>/_archived/<caseId>, and the whole
 * cases root moves on a DFIR_CASES_DIR change, a container remount or a restore from backup. Every
 * artifact recorded before such a move would then verify as "missing" — the integrity check would
 * cry tampering over evidence sitting intact one directory across.
 *
 * So an artifact that lives inside the case dir is stored relative to it and re-resolved through the
 * (archive-aware) caseDir() on every read. Evidence collected from outside the case dir — mounted
 * images, external tool output, the POST /cases/:id/custody case — has nothing to be relative TO, so
 * it keeps its absolute path and omits the marker. Records written before this distinction existed
 * also lack the marker, which is exactly right: they are absolute.
 *
 * This stays internal. Callers hand in and get back absolute paths, unchanged.
 */
interface StoredCustodyRecord extends CustodyRecord {
  relativeTo?: "case-dir";
}

export interface CustodyMismatch {
  artifactPath: string;
  recordedSha256: string;
  actualSha256: string | null;
  reason: "hash-mismatch" | "missing";
}

/** A place where the log stopped being a chain: an entry was altered, removed, or replayed. */
export interface CustodyChainBreak {
  /** 1-indexed position in custody.jsonl, so the break is findable even if seq itself was forged. */
  line: number;
  seq: number | null;
  reason: "prev-hash-mismatch" | "seq-out-of-order";
}

/** Hash of one stored line, exactly as it sits in the file — the unit the chain links together. */
function hashLine(line: string): string {
  return createHash("sha256").update(line, "utf8").digest("hex");
}

export class CustodyStore {
  // Serializes the read-tail → append critical section per case. Two concurrent imports would
  // otherwise both read the same tail line, compute the same prevHash, and fork the chain into two
  // records claiming the same predecessor — which reads exactly like tampering afterwards.
  private readonly appendLock = new StateLock();

  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return this.cases.custodyLogPath(caseId);
  }

  /** The stored lines of custody.jsonl, verbatim; [] when the log does not exist yet. */
  private async storedLines(caseId: string): Promise<string[]> {
    try {
      return (await readFile(this.path(caseId), "utf8")).split("\n").filter((l) => l.trim().length > 0);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  /**
   * Whether artifactPath lives inside the case dir, and if so where. Deliberately derived from the
   * path rather than declared by the caller: an artifact the companion stored itself always lands
   * inside the case dir and externally collected evidence generally does not, so the two are already
   * distinguishable — and a manual record that does name an in-case file gets the same
   * relocation-proofing for free.
   */
  private caseRelative(caseId: string, artifactPath: string): string | null {
    const rel = relative(this.cases.caseDir(caseId), artifactPath);
    // "" is the case dir itself; ".." escapes it; an absolute result means a different root entirely.
    if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return null;
    return rel;
  }

  async record(caseId: string, input: CustodyRecordInput): Promise<CustodyRecord> {
    return (await this.appendChained(caseId, [input]))[0];
  }

  /**
   * Append a batch of records as one unbroken run of the chain, under a single lock acquisition.
   * A batch shares the lock rather than looping over record() so that an export of a thousand
   * artifacts costs one read of the log instead of a thousand reads of a log that keeps growing.
   */
  private async appendChained(caseId: string, inputs: CustodyRecordInput[]): Promise<CustodyRecord[]> {
    if (inputs.length === 0) return [];
    return this.appendLock.runExclusive(caseId, async () => {
      const lines = await this.storedLines(caseId);
      // The chain links STORED lines, not resolved ones: a case-relative path is what is actually on
      // disk, so archiving the case (which rewrites no lines) leaves every link intact. Chaining the
      // resolved absolute form would break the whole chain the moment the folder moved.
      let prevHash = lines.length === 0 ? "" : hashLine(lines[lines.length - 1]);
      const records: CustodyRecord[] = [];
      const pending: string[] = [];

      for (const input of inputs) {
        const record: CustodyRecord = {
          ...input,
          event: isCustodyEvent(input.event) ? input.event : "collected",
          seq: await this.cases.nextCustodySeq(caseId),
          prevHash,
        };
        const rel = this.caseRelative(caseId, record.artifactPath);
        const stored: StoredCustodyRecord = rel === null ? record : { ...record, artifactPath: rel, relativeTo: "case-dir" };
        const line = JSON.stringify(stored);
        // Each line in the batch links to the one before it, exactly as separate appends would.
        prevHash = hashLine(line);
        pending.push(line);
        records.push(record);
      }

      await mkdir(this.cases.metadataDir(caseId), { recursive: true });
      await appendFile(this.path(caseId), pending.join("\n") + "\n", "utf8");
      // Callers get back the absolute form — the relative one never leaves this class.
      return records;
    });
  }

  /**
   * Record that every artifact under custody left the instance — one `exported` event per artifact,
   * because a per-artifact chain that omits "this left the building" is not a custody chain.
   *
   * Each artifact is re-hashed rather than reusing the hash on file: the export must state the bytes
   * it actually carried out. An artifact that has since been deleted is skipped, since nothing about
   * it left. Call this AFTER the export succeeds, so a failed export never logs one that happened.
   */
  async recordExport(caseId: string, opts: { exportedBy: string; destination: string }): Promise<CustodyRecord[]> {
    const existing = await this.load(caseId);
    const artifactPaths = [...new Set(existing.map((r) => r.artifactPath))];
    const exportedAt = new Date().toISOString();
    const inputs: CustodyRecordInput[] = [];

    for (const artifactPath of artifactPaths) {
      let sha256: string;
      try {
        sha256 = await hashFile(artifactPath);
      } catch {
        continue;
      }
      inputs.push({
        artifactPath, sha256, caseId, event: "exported",
        collectedBy: opts.exportedBy, collectedAt: exportedAt,
        source: opts.destination, trigger: "export",
      });
    }
    return this.appendChained(caseId, inputs);
  }

  async load(caseId: string): Promise<CustodyRecord[]> {
    let text: string;
    try {
      text = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const records: CustodyRecord[] = [];
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      try {
        records.push(this.resolve(caseId, JSON.parse(line) as StoredCustodyRecord));
      } catch {
        // skip a malformed line
      }
    }
    return records;
  }

  /**
   * Rebuild the absolute path from wherever the case folder is NOW, so a record outlives an archive
   * or a moved cases root. A record with no marker is already absolute — that covers both external
   * evidence and everything written before the marker existed.
   */
  private resolve(caseId: string, stored: StoredCustodyRecord): CustodyRecord {
    const { relativeTo, ...rest } = stored;
    const record: CustodyRecord = {
      ...rest,
      // Records written before the chain existed have no event; they were all collections.
      event: isCustodyEvent(stored.event) ? stored.event : "collected",
    };
    if (relativeTo !== "case-dir") return record;
    return { ...record, artifactPath: join(this.cases.caseDir(caseId), stored.artifactPath) };
  }

  /**
   * Walk the log and report every place it stopped being a chain. Each line carries the hash of the
   * line before it, so editing or deleting an entry is detectable at the FOLLOWING line — the one
   * whose recorded predecessor no longer matches what is actually there.
   *
   * Two things are deliberately not breaks. Records that predate the chain carry no prevHash and are
   * skipped rather than condemned; a chained record that follows one links onto it normally. And a
   * jump in seq is fine — nextCustodySeq burns a number on a failed append by design, so gaps are
   * expected. Only a seq that fails to ADVANCE is a break: that is a replay or a rewrite.
   *
   * What this cannot catch on its own is truncation of the tail — lopping off the last N lines leaves
   * a perfectly valid shorter chain. Detecting that needs the head seq + hash recorded somewhere the
   * log itself cannot reach, which is the signed manifest's job (#231 item 2).
   */
  async verifyChain(caseId: string): Promise<CustodyChainBreak[]> {
    const lines = await this.storedLines(caseId);
    const breaks: CustodyChainBreak[] = [];
    let lastSeq: number | null = null;

    for (let i = 0; i < lines.length; i++) {
      let stored: StoredCustodyRecord;
      try {
        stored = JSON.parse(lines[i]) as StoredCustodyRecord;
      } catch {
        continue; // matches load()'s tolerance of a malformed line
      }
      const seq = typeof stored.seq === "number" ? stored.seq : null;

      if (typeof stored.prevHash === "string") {
        const expected = i === 0 ? "" : hashLine(lines[i - 1]);
        if (stored.prevHash !== expected) breaks.push({ line: i + 1, seq, reason: "prev-hash-mismatch" });
      }
      if (seq !== null && lastSeq !== null && seq <= lastSeq) {
        breaks.push({ line: i + 1, seq, reason: "seq-out-of-order" });
      }
      if (seq !== null) lastSeq = seq;
    }
    return breaks;
  }

  async verifyIntegrity(caseId: string): Promise<CustodyMismatch[]> {
    const records = await this.load(caseId);
    const mismatches: CustodyMismatch[] = [];
    for (const record of records) {
      let actual: string | null = null;
      try {
        actual = await hashFile(record.artifactPath);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          mismatches.push({ artifactPath: record.artifactPath, recordedSha256: record.sha256, actualSha256: null, reason: "missing" });
          continue;
        }
        throw err;
      }
      if (actual !== record.sha256) {
        mismatches.push({ artifactPath: record.artifactPath, recordedSha256: record.sha256, actualSha256: actual, reason: "hash-mismatch" });
      }
    }
    return mismatches;
  }
}
