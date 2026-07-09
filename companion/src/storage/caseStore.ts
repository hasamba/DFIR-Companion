import { mkdir, writeFile, appendFile, readFile, stat, readdir } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { CaseMeta, CaptureMetadata, ImportMetadata } from "../types.js";
import type { OcrIndex, OcrIndexEntry } from "../analysis/ocrSearch.js";
import { atomicWrite } from "./atomicWrite.js";

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

  get casesRoot(): string { return this.root; }

  // A case normally lives at <root>/<caseId>. Once archived (see archiveCaseFolder), it moves to
  // <root>/_archived/<caseId> instead — every other path helper derives from this one, so nothing
  // else in the codebase needs to know which location a given case is in.
  caseDir(caseId: string): string {
    const active = join(this.root, caseId);
    if (existsSync(active)) return active;
    const archived = join(this.root, "_archived", caseId);
    if (existsSync(archived)) return archived;
    return active; // doesn't exist yet (e.g. about to be created) — active root is the default
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
  // Screenshot OCR full-text search index (#176). A sidecar — NOT captures.jsonl, which is
  // append-only — keyed by screenshotFile so a re-OCR replaces a row instead of duplicating it.
  ocrIndexPath(caseId: string): string {
    return join(this.metadataDir(caseId), "ocr.json");
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

  /** Atomically patch case.json with the given fields. Unknown fields are preserved. */
  async updateCaseMeta(caseId: string, patch: Partial<CaseMeta>): Promise<CaseMeta> {
    const existing = (await this.getCaseMeta(caseId)) ?? { caseId, name: "", createdAt: "", investigator: "", aiProvider: null } as CaseMeta;
    const updated = { ...existing, ...patch, caseId } as CaseMeta;
    await atomicWrite(this.caseMetaPath(caseId), JSON.stringify(updated, null, 2));
    return updated;
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

  // Load the case's OCR search index (#176), or {} when it doesn't exist yet / is unreadable.
  // A corrupt index is non-fatal — it's a derived cache, rebuildable via `npm run ocr-index`.
  async loadOcrIndex(caseId: string): Promise<OcrIndex> {
    try {
      const parsed = JSON.parse(await readFile(this.ocrIndexPath(caseId), "utf8"));
      return parsed && typeof parsed === "object" ? (parsed as OcrIndex) : {};
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      return {};
    }
  }

  // Merge one OCR entry into the index by screenshotFile (immutable update) and write it
  // atomically — the metadata/ dir may live in a Dropbox/OneDrive-synced cases/ root, so the
  // rename can hit a transient lock (see atomicWrite.ts).
  async putOcrEntry(caseId: string, entry: OcrIndexEntry): Promise<void> {
    await mkdir(this.metadataDir(caseId), { recursive: true });
    const index = await this.loadOcrIndex(caseId);
    const updated: OcrIndex = { ...index, [entry.screenshotFile]: entry };
    await atomicWrite(this.ocrIndexPath(caseId), JSON.stringify(updated, null, 2));
  }
}
