import { mkdir, writeFile, appendFile, readFile, stat, readdir, rename, rm } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { CaseMeta, CaptureMetadata, ImportMetadata } from "../types.js";
import type { OcrIndex, OcrIndexEntry } from "../analysis/ocrSearch.js";
import { atomicWrite } from "./atomicWrite.js";

const ARCHIVED_DIRNAME = "_archived";

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
    const archived = join(this.root, ARCHIVED_DIRNAME, caseId);
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

  // Non-destructive "remove from active list": moves the whole case folder under _archived/.
  // Nothing is deleted — caseDir()'s fallback means every other method keeps working unchanged.
  // Rejects (via rename's ENOENT) if caseId doesn't currently exist in the active root.
  // Known limitation: no locking against a concurrent request reading/writing the same case
  // mid-move — acceptable for now since this is a single-user localhost tool.
  async archiveCaseFolder(caseId: string): Promise<void> {
    const archivedRoot = join(this.root, ARCHIVED_DIRNAME);
    await mkdir(archivedRoot, { recursive: true });
    await rename(join(this.root, caseId), join(archivedRoot, caseId));
  }

  // Inverse of archiveCaseFolder: moves the case back into the active root.
  // Rejects (via rename's ENOENT) if caseId isn't currently archived under _archived/.
  async restoreCaseFolder(caseId: string): Promise<void> {
    await rename(join(this.root, ARCHIVED_DIRNAME, caseId), join(this.root, caseId));
  }

  // Permanently deletes a case's folder — recursive, irreversible. Works whether the case is
  // currently active or archived (via the archive-aware caseDir()). Deliberately WITHOUT
  // { force: true } on the directory itself, so it throws (ENOENT) for a caseId that doesn't
  // currently exist, consistent with archiveCaseFolder/restoreCaseFolder's existing rejection
  // behavior. Refuses to delete a directory that doesn't actually contain a case.json — this is
  // the most dangerous method in this class (genuinely irreversible, unlike the archive/restore
  // moves), so it shouldn't silently wipe an unrelated directory that happens to share the name.
  async deleteCaseFolder(caseId: string): Promise<void> {
    const dir = this.caseDir(caseId);
    if (!(await this.caseExists(caseId))) {
      throw new Error(`refusing to delete "${caseId}": no case.json found at ${dir}`);
    }
    await rm(dir, { recursive: true });
  }

  // NOTE: does not itself guard against an id collision with an archived case (caseDir()
  // resolves to the archived location and this would silently overwrite its case.json).
  // Callers are responsible for that check — see POST /cases in server.ts, which calls
  // caseExists() (archive-aware) and 409s before ever reaching here.
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
  // Scans both the active root and _archived/ so archived cases stay listable (filtered
  // client-side by status) without needing a separate index.
  async listCases(): Promise<CaseMeta[]> {
    const metas: CaseMeta[] = [];
    for (const dir of [this.root, join(this.root, ARCHIVED_DIRNAME)]) {
      let entries: Dirent[];
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw err;
      }
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (dir === this.root && entry.name === ARCHIVED_DIRNAME) continue; // not a case — the archived-cases folder itself
        try {
          metas.push(JSON.parse(await readFile(this.caseMetaPath(entry.name), "utf8")) as CaseMeta);
        } catch {
          // a directory without a valid case.json is not a case — skip it
        }
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
