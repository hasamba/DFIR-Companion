import { mkdir, writeFile, appendFile, readFile, stat, readdir, rename, rm } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import type { CaseMeta, CaptureMetadata, ImportMetadata } from "../types.js";
import type { OcrIndex, OcrIndexEntry } from "../analysis/ocrSearch.js";
import { StateLock } from "../analysis/stateLock.js";
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

/** What the caller knows about where an artifact came from; only the capture path has all of it. */
export interface ArtifactProvenance {
  source?: string;
  trigger?: string;
  collectedBy?: string;
}

/** An artifact that has just been written to disk, announced to the artifact-stored listener. */
export interface StoredArtifact {
  caseId: string;
  path: string;
  sha256: string;
  kind: "screenshot" | "import";
  provenance?: ArtifactProvenance;
}

export type ArtifactStoredListener = (artifact: StoredArtifact) => void | Promise<void>;

export class CaseStore {
  // Serializes evidence-sequence allocation per case+kind (#214). Reading "audit-log length + 1"
  // is a read-modify-write: two ingestions racing for the same case both read the same length and
  // both got the same number, and when their filenames also matched, one evidence file silently
  // overwrote the other. The lock makes allocation atomic; the high-water mark below makes it
  // correct even before the audit line lands.
  private readonly seqLock = new StateLock();

  // Highest sequence number handed out per `<kind>:<caseId>` in this process. The audit line is
  // appended AFTER the evidence is written, so between reserving a number and recording it the log
  // still has its old length — without this, a second caller arriving in that window would read the
  // same length and reuse the number. Numbers are therefore never reused, only ever skipped (a
  // failed ingestion burns its number, which is the safe direction for provenance).
  private readonly seqHighWater = new Map<string, number>();

  // Serializes the OCR index read-modify-write per case (see putOcrEntry).
  private readonly ocrLock = new StateLock();

  // Notified after every artifact write below, so chain-of-custody is recorded for ALL stored
  // evidence rather than only where a caller remembered to ask (#231). It lives here, at the two
  // methods that actually write evidence, because saveImport alone has 25 call sites — instrumenting
  // them individually would guarantee a gap, and every future one would start life uncovered.
  // Injected rather than imported so storage/ keeps knowing nothing about custody.
  private artifactStoredListener: ArtifactStoredListener | null = null;

  constructor(private readonly root: string) {}

  get casesRoot(): string { return this.root; }

  /** Register the (single) listener notified after each artifact write. */
  onArtifactStored(listener: ArtifactStoredListener): void {
    this.artifactStoredListener = listener;
  }

  // Called only AFTER the bytes are safely on disk, and deliberately not caught here: an artifact
  // whose custody record silently failed to append is exactly the gap this feature exists to close,
  // so it surfaces to the caller the same way saveScreenshot's `wx` collision does. The evidence
  // itself is already written, so a raised error costs the caller its response, never the artifact.
  private async announceArtifact(artifact: StoredArtifact): Promise<void> {
    await this.artifactStoredListener?.(artifact);
  }

  /** Reserve the next never-yet-used sequence number for this case+kind. */
  private reserveSequence(kind: "capture" | "import" | "custody", caseId: string, countOnDisk: () => Promise<number>): Promise<number> {
    const key = `${kind}:${caseId}`;
    return this.seqLock.runExclusive(key, async () => {
      // Disk is authoritative across restarts (the map starts empty); the map is authoritative
      // for numbers already handed out but not yet appended. The later of the two is correct.
      const next = Math.max((await countOnDisk()) + 1, (this.seqHighWater.get(key) ?? 0) + 1);
      this.seqHighWater.set(key, next);
      return next;
    });
  }

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
  custodyLogPath(caseId: string): string {
    return join(this.metadataDir(caseId), "custody.jsonl");
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

  // `wx` = create-exclusive: fail if the file exists rather than overwrite it (#214). Sequence
  // numbers are unique now, so a collision should be impossible — which is exactly why hitting one
  // must raise instead of destroying evidence that is already on disk.
  async saveScreenshot(caseId: string, filename: string, bytes: Buffer, provenance?: ArtifactProvenance): Promise<string> {
    const path = join(this.screenshotsDir(caseId), filename);
    await writeFile(path, bytes, { flag: "wx" });
    // Hash the buffer we just wrote rather than re-reading the file: same bytes, no second pass
    // over evidence that can run to hundreds of megabytes.
    await this.announceArtifact({ caseId, path, sha256: createHash("sha256").update(bytes).digest("hex"), kind: "screenshot", provenance });
    return path;
  }

  async appendCapture(caseId: string, metadata: CaptureMetadata): Promise<CaptureMetadata> {
    await appendFile(this.capturesLogPath(caseId), JSON.stringify(metadata) + "\n", "utf8");
    return metadata;
  }

  async nextSequenceNumber(caseId: string): Promise<number> {
    return this.reserveSequence("capture", caseId, () => this.countLogLines(this.capturesLogPath(caseId)));
  }

  /** Number of records in an append-only .jsonl audit log; 0 when it does not exist yet. */
  private async countLogLines(path: string): Promise<number> {
    try {
      return (await readFile(path, "utf8")).split("\n").filter((l) => l.trim().length > 0).length;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return 0;
      throw err;
    }
  }

  // Persist an uploaded CSV verbatim as evidence (mkdirs for cases created before
  // the imports/ dir existed). Returns the stored absolute path.
  async saveImport(caseId: string, filename: string, text: string, provenance?: ArtifactProvenance): Promise<string> {
    await mkdir(this.importsDir(caseId), { recursive: true });
    const path = join(this.importsDir(caseId), filename);
    // Create-exclusive, for the same reason as saveScreenshot above (#214).
    await writeFile(path, text, { encoding: "utf8", flag: "wx" });
    // utf8 in, utf8 on disk — so this matches what a later re-read hashes during verification.
    await this.announceArtifact({ caseId, path, sha256: createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex"), kind: "import", provenance });
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

  // Ordinal for the next chain-of-custody entry (#231). Same allocator as captures and imports, so a
  // custody record that fails to append burns its number rather than letting the next one reuse it —
  // gaps are the safe direction for provenance, reuse is not.
  async nextCustodySeq(caseId: string): Promise<number> {
    return this.reserveSequence("custody", caseId, () => this.countLogLines(this.custodyLogPath(caseId)));
  }

  async nextImportSeq(caseId: string): Promise<number> {
    return this.reserveSequence("import", caseId, () => this.countLogLines(this.importsLogPath(caseId)));
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
  // rename can hit a transient lock (see atomicWrite.ts). Serialize the read-modify-write cycle
  // per case: the OCR queue deliberately runs two workers concurrently, and atomic rename alone
  // cannot prevent both workers reading the same old index and one clobbering the other's entry.
  // In-process only, like every other lock here — `npm run ocr-index` is a second writer from a
  // separate process, so run it against an idle case.
  async putOcrEntry(caseId: string, entry: OcrIndexEntry): Promise<void> {
    return this.ocrLock.runExclusive(caseId, async () => {
      await mkdir(this.metadataDir(caseId), { recursive: true });
      const index = await this.loadOcrIndex(caseId);
      const updated: OcrIndex = { ...index, [entry.screenshotFile]: entry };
      await atomicWrite(this.ocrIndexPath(caseId), JSON.stringify(updated, null, 2));
    });
  }
}
