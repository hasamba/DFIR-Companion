import { readFile, appendFile, mkdir } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { join, relative, isAbsolute, sep } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";

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

export interface CustodyRecord {
  /** Always absolute, in both directions — see StoredCustodyRecord for how it is persisted. */
  artifactPath: string;
  sha256: string;
  collectedBy: string;
  collectedAt: string;
  source: string;
  trigger: string;
  caseId: string;
}

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

export class CustodyStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.metadataDir(caseId), "custody.jsonl");
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

  async record(caseId: string, record: CustodyRecord): Promise<CustodyRecord> {
    const rel = this.caseRelative(caseId, record.artifactPath);
    const stored: StoredCustodyRecord = rel === null ? record : { ...record, artifactPath: rel, relativeTo: "case-dir" };
    await mkdir(this.cases.metadataDir(caseId), { recursive: true });
    await appendFile(this.path(caseId), JSON.stringify(stored) + "\n", "utf8");
    // The caller gets back what it handed in — the relative form never leaves this class.
    return record;
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
    if (stored.relativeTo !== "case-dir") return stored;
    const { relativeTo: _relativeTo, ...record } = stored;
    return { ...record, artifactPath: join(this.cases.caseDir(caseId), stored.artifactPath) };
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
