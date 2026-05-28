import { mkdir, writeFile, appendFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseMeta, CaptureMetadata } from "../types.js";

export interface CreateCaseInput {
  caseId: string;
  name: string;
  investigator: string;
  aiProvider: string | null;
}

export class CaseStore {
  constructor(private readonly root: string) {}

  caseDir(caseId: string): string {
    return join(this.root, caseId);
  }
  screenshotsDir(caseId: string): string {
    return join(this.caseDir(caseId), "screenshots");
  }
  metadataDir(caseId: string): string {
    return join(this.caseDir(caseId), "metadata");
  }
  stateDir(caseId: string): string {
    return join(this.caseDir(caseId), "state");
  }
  reportsDir(caseId: string): string {
    return join(this.caseDir(caseId), "reports");
  }
  capturesLogPath(caseId: string): string {
    return join(this.metadataDir(caseId), "captures.jsonl");
  }
  caseMetaPath(caseId: string): string {
    return join(this.caseDir(caseId), "case.json");
  }

  async createCase(input: CreateCaseInput): Promise<CaseMeta> {
    const meta: CaseMeta = {
      caseId: input.caseId,
      name: input.name,
      createdAt: new Date().toISOString(),
      investigator: input.investigator,
      aiProvider: input.aiProvider,
    };
    for (const dir of [
      this.screenshotsDir(input.caseId),
      this.metadataDir(input.caseId),
      this.stateDir(input.caseId),
      this.reportsDir(input.caseId),
    ]) {
      await mkdir(dir, { recursive: true });
    }
    await writeFile(this.caseMetaPath(input.caseId), JSON.stringify(meta, null, 2), "utf8");
    return meta;
  }

  async saveScreenshot(caseId: string, filename: string, bytes: Buffer): Promise<string> {
    const path = join(this.screenshotsDir(caseId), filename);
    await writeFile(path, bytes);
    return path;
  }

  async appendCapture(caseId: string, metadata: CaptureMetadata): Promise<CaptureMetadata> {
    await appendFile(this.capturesLogPath(caseId), JSON.stringify(metadata) + "\n", "utf8");
    return metadata;
  }

  async nextSequenceNumber(caseId: string): Promise<number> {
    try {
      const log = await readFile(this.capturesLogPath(caseId), "utf8");
      const lines = log.split("\n").filter((l) => l.trim().length > 0);
      return lines.length + 1;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return 1;
      throw err;
    }
  }
}
