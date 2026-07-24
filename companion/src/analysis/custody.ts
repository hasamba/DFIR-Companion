import { readFile, appendFile, mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";

export interface CustodyRecord {
  artifactPath: string;
  sha256: string;
  collectedBy: string;
  collectedAt: string;
  source: string;
  trigger: string;
  caseId: string;
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

  async record(caseId: string, record: CustodyRecord): Promise<CustodyRecord> {
    await mkdir(this.cases.metadataDir(caseId), { recursive: true });
    await appendFile(this.path(caseId), JSON.stringify(record) + "\n", "utf8");
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
        records.push(JSON.parse(line) as CustodyRecord);
      } catch {
        // skip a malformed line
      }
    }
    return records;
  }

  async verifyIntegrity(caseId: string): Promise<CustodyMismatch[]> {
    const records = await this.load(caseId);
    const mismatches: CustodyMismatch[] = [];
    for (const record of records) {
      let actual: string | null = null;
      try {
        const bytes = await readFile(record.artifactPath);
        actual = createHash("sha256").update(bytes).digest("hex");
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
