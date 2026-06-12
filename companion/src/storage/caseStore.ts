import { mkdir, writeFile, appendFile, readFile, stat, readdir } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { join } from "node:path";
import type { CaseMeta, CaptureMetadata, ImportMetadata } from "../types.js";

export interface CreateCaseInput {
  caseId: string;
  name: string;
  investigator: string;
  aiProvider: string | null;
}

export function isValidCaseId(caseId: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(caseId) && !caseId.includes("..");
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
  importsDir(caseId: string): string {
    return join(this.caseDir(caseId), "imports");
  }
  capturesLogPath(caseId: string): string {
    return join(this.metadataDir(caseId), "captures.jsonl");
  }
  importsLogPath(caseId: string): string {
    return join(this.metadataDir(caseId), "imports.jsonl");
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
      this.importsDir(input.caseId),
    ]) {
      await mkdir(dir, { recursive: true });
    }
    await writeFile(this.caseMetaPath(input.caseId), JSON.stringify(meta, null, 2), "utf8");
    return meta;
  }

  // True once a case has been created (its case.json exists). Backs the capture guard:
  // the companion never creates a case as a side effect of ingesting evidence — creation
  // is a deliberate dashboard action — so an unknown caseId is rejected, not auto-created.
  async caseExists(caseId: string): Promise<boolean> {
    try {
      await stat(this.caseMetaPath(caseId));
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw err;
    }
  }

  // One case's metadata (case.json), or null when the case doesn't exist / has no valid meta.
  // Cheaper than listCases() when only a single case's name/investigator is needed (e.g. the
  // mobile summary stamps the display name).
  async getCaseMeta(caseId: string): Promise<CaseMeta | null> {
    try {
      return JSON.parse(await readFile(this.caseMetaPath(caseId), "utf8")) as CaseMeta;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  // All cases that have a readable case.json, newest first. Backs GET /cases so the
  // extension can present a picker of existing cases instead of creating its own.
  async listCases(): Promise<CaseMeta[]> {
    let entries: Dirent[];
    try {
      entries = await readdir(this.root, { withFileTypes: true });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const metas: CaseMeta[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      try {
        metas.push(JSON.parse(await readFile(this.caseMetaPath(entry.name), "utf8")) as CaseMeta);
      } catch {
        // a directory without a valid case.json is not a case — skip it
      }
    }
    metas.sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0));
    return metas;
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

  // Persist an uploaded CSV verbatim as evidence (mkdirs for cases created before
  // the imports/ dir existed). Returns the stored absolute path.
  async saveImport(caseId: string, filename: string, text: string): Promise<string> {
    await mkdir(this.importsDir(caseId), { recursive: true });
    const path = join(this.importsDir(caseId), filename);
    await writeFile(path, text, "utf8");
    return path;
  }

  async appendImport(caseId: string, metadata: ImportMetadata): Promise<ImportMetadata> {
    await mkdir(this.metadataDir(caseId), { recursive: true });
    await appendFile(this.importsLogPath(caseId), JSON.stringify(metadata) + "\n", "utf8");
    return metadata;
  }

  async nextImportSeq(caseId: string): Promise<number> {
    try {
      const log = await readFile(this.importsLogPath(caseId), "utf8");
      return log.split("\n").filter((l) => l.trim().length > 0).length + 1;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return 1;
      throw err;
    }
  }
}
