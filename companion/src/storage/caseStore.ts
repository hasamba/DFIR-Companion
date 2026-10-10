import {
  mkdir,
  writeFile,
  appendFile,
  readFile,
  stat,
  readdir,
  rename,
  rm,
  rmdir,
  unlink,
} from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import type { CaseMeta, CaptureMetadata, ImportMetadata } from "../types.js";
import type { OcrIndex, OcrIndexEntry } from "../analysis/ocrSearch.js";
import { StateLock } from "../analysis/stateLock.js";
import { atomicWrite } from "./atomicWrite.js";
import { copyHandleHashed } from "./handleCopy.js";
import { ARCHIVED_DIRNAME, newCaseGeneration, runWhileCaseClosed, withCaseWrite } from "./caseIncarnation.js";
import type { CaseWriteRefusal, Vacated } from "./caseIncarnation.js";
import { forgetCaseKeyedState } from "./caseKeyedState.js";
import {
  CaseAlreadyExistsError,
  CaseArchivedError,
  CaseBeingDeletedError,
  CaseFolderLeftoverError,
  CaseLifecycleError,
  CaseNotFoundError,
} from "./caseErrors.js";

// How long a delete, archive or reseed waits for writes already admitted to the case folder (#1855).
const WRITE_QUIESCE_MS = 30_000;
const RETIRED_IDS_FILENAME = ".dfir-companion-retired-cases.json";

export interface CreateCaseInput {
  caseId: string;
  name: string;
  investigator: string;
  aiProvider: string | null;
  /**
   * Runs inside the case lock right after the id is claimed, before anything else is written. The
   * create route clears access rows a deleted case with this id left behind (#1831). If it throws,
   * the claim is undone and the create fails.
   */
  onClaimed?: () => void | Promise<void>;
}

export function isValidCaseId(caseId: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(caseId) && !caseId.includes("..");
}

export * from "./caseErrors.js";

/** A check run on the current case.json inside the metadata lock; it throws to refuse. */
export type CaseMetaGuard = (current: CaseMeta) => void;

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
  sha1?: string;
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

  // Serializes the retired-case-id ledger read-modify-write (see retireCaseId).
  private readonly retiredLock = new StateLock();

  // Serializes, per case, every case.json write against the folder moves and the delete (#1808). A
  // status or password write that landed mid-rm made the rm fail with ENOTEMPTY; one that landed
  // between an archive's move and its status write could strand the case (#1809).
  private readonly metaLock = new StateLock();

  // Ids with a delete in flight, counted so two deletes of one id cannot clear each other's mark.
  // Set when deleteCaseFolder is called, cleared once its locked section (rm + cleanup) ends (#1826).
  private readonly deleting = new Map<string, number>();

  // Notified after every artifact write below, so chain-of-custody is recorded for ALL stored
  // evidence rather than only where a caller remembered to ask (#231). It lives here, in the methods
  // that write evidence (saveScreenshot, saveImport, saveRawImport, saveImportFromHandle), because
  // saveImport alone has 25 call sites — instrumenting
  // them individually would guarantee a gap, and every future one would start life uncovered.
  // Injected rather than imported so storage/ keeps knowing nothing about custody.
  private artifactStoredListener: ArtifactStoredListener | null = null;

  private readonly writeQuiesceMs: number;

  constructor(
    private readonly root: string,
    opts: { writeQuiesceMs?: number } = {},
  ) {
    this.writeQuiesceMs = opts.writeQuiesceMs ?? WRITE_QUIESCE_MS;
  }

  get casesRoot(): string {
    return this.root;
  }

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
  private reserveSequence(
    kind: "capture" | "import" | "custody",
    caseId: string,
    maxOnDisk: () => Promise<number>,
  ): Promise<number> {
    const key = `${kind}:${caseId}`;
    return this.seqLock.runExclusive(key, async () => {
      // Disk is authoritative across restarts (the map starts empty); the map is authoritative
      // for numbers already handed out but not yet appended. The later of the two is correct.
      // `maxOnDisk` must return the HIGHEST recorded sequence number, never a line count (#1119):
      // a reservation burned by a failed append (no line written) still consumed a number, so a
      // line count under-reports how many numbers were actually issued once the process restarts
      // and `seqHighWater` resets — max(sequenceNumber) is correct regardless of any such gaps.
      const next = Math.max((await maxOnDisk()) + 1, (this.seqHighWater.get(key) ?? 0) + 1);
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
  // Serialized against case.json writes and the delete (metaLock); evidence writers are not locked,
  // and rely on the closed/archived write guards instead.
  // With `status`, the move and the status write are one step under the metadata lock, and a failed
  // status write moves the folder back — so no other write can see the case moved but not re-labelled.
  async archiveCaseFolder(caseId: string, status?: CaseMeta["status"]): Promise<CaseMeta | null> {
    const active = join(this.root, caseId);
    const archived = join(this.root, ARCHIVED_DIRNAME, caseId);
    return this.metaLock.runExclusive(caseId, async () => {
      await this.whileClosed(
        caseId,
        "moved",
        async () => {
          await mkdir(join(this.root, ARCHIVED_DIRNAME), { recursive: true });
          await rename(active, archived);
        },
        ["active"],
      );
      return status ? this.relabelAfterMove(caseId, status, archived, active) : null;
    });
  }

  // Inverse of archiveCaseFolder: moves the case back into the active root, same `status` contract.
  // Rejects (via rename's ENOENT) if caseId isn't currently archived under _archived/.
  async restoreCaseFolder(caseId: string, status?: CaseMeta["status"]): Promise<CaseMeta | null> {
    const active = join(this.root, caseId);
    const archived = join(this.root, ARCHIVED_DIRNAME, caseId);
    return this.metaLock.runExclusive(caseId, async () => {
      await this.whileClosed(caseId, "moved", () => rename(archived, active), ["archived"]);
      return status ? this.relabelAfterMove(caseId, status, active, archived) : null;
    });
  }

  // Close the case to new writes, wait for admitted ones, then act; a late write to a place the case
  // left is refused afterwards instead of recreating it (#1855). The caller holds metaLock.
  // #1866: a deleted or replaced case's in-memory state (sequence high-water marks, and every
  // CaseKeyedMap/Set under this root, clearing their timers) never carries into a same-id successor.
  private forgetInMemory(caseId: string): void {
    for (const key of [...this.seqHighWater.keys()]) {
      if (key.slice(key.indexOf(":") + 1) === caseId) this.seqHighWater.delete(key);
    }
    forgetCaseKeyedState(this.root, caseId);
  }

  private whileClosed<T>(caseId: string, reason: CaseWriteRefusal, act: () => Promise<T>, vacated: Vacated) {
    const busy = () =>
      new CaseLifecycleError(`writes to case ${caseId} are still in progress — try again`, 409);
    return runWhileCaseClosed(
      this.root,
      caseId,
      { reason, timeoutMs: this.writeQuiesceMs, busy },
      act,
      vacated,
    );
  }

  // Held under metaLock by the caller. Writes the status at the folder's new place; on failure moves
  // the folder back (best-effort) and rethrows, so the move and the label land together or not at all.
  private async relabelAfterMove(
    caseId: string,
    status: CaseMeta["status"],
    movedTo: string,
    movedFrom: string,
  ): Promise<CaseMeta> {
    try {
      return await this.writeCaseMetaLocked(caseId, { status });
    } catch (err) {
      const rolledBack = await rename(movedTo, movedFrom).then(
        () => "",
        (undo: Error) => `; moving it back also failed (${undo.message}) — the folder stays at ${movedTo}`,
      );
      throw new Error(`status write after the move failed: ${(err as Error).message}${rolledBack}`, {
        cause: err,
      });
    }
  }

  /** True when the case's folder sits under _archived/ — whatever its case.json says. Lets restore
   *  recover a case a pre-#1809 status change left there labelled open or closed. */
  isInArchive(caseId: string): boolean {
    return existsSync(join(this.root, ARCHIVED_DIRNAME, caseId)) && !existsSync(join(this.root, caseId));
  }

  /** Set a case open or closed. Refuses an archived case: only restore takes it out (#1809). */
  setCaseStatus(caseId: string, status: "open" | "closed"): Promise<CaseMeta> {
    return this.updateCaseMeta(caseId, { status }, (current) => {
      if (current.status === "archived") throw new CaseArchivedError(caseId);
    });
  }

  // Permanently deletes a case's folder — recursive, irreversible. Works whether the case is
  // currently active or archived (via the archive-aware caseDir()). Deliberately WITHOUT
  // { force: true } on the directory itself, so it throws (ENOENT) for a caseId that doesn't
  // currently exist, consistent with archiveCaseFolder/restoreCaseFolder's existing rejection
  // behavior. Refuses to delete a directory that doesn't actually contain a case.json — this is
  // the most dangerous method in this class (genuinely irreversible, unlike the archive/restore
  // moves), so it shouldn't silently wipe an unrelated directory that happens to share the name.
  //
  //
  // Runs under the metadata lock (#1808), so no case.json write lands during the rm. With
  // `closedOnly`, refuses a case that is not closed or archived AT THAT MOMENT: an archive-first
  // export can run long enough for the case to be reopened after the route's own status check.
  //
  // `afterDelete` runs inside the same lock, right after the rm, and only when the rm succeeded: the
  // cleanup of state that outlives the folder (roles, jobs) must finish before a create of the same
  // id can start, or it revokes the new case's roles (#1826). It must not throw — the folder is
  // already gone. createCase refuses the id for as long as this call is in flight.
  async deleteCaseFolder(
    caseId: string,
    opts: { closedOnly?: boolean; afterDelete?: () => Promise<void> } = {},
  ): Promise<void> {
    this.deleting.set(caseId, (this.deleting.get(caseId) ?? 0) + 1);
    try {
      await this.metaLock.runExclusive(caseId, async () => {
        const dir = this.caseDir(caseId);
        const meta = await this.getCaseMeta(caseId);
        if (!meta) throw new Error(`refusing to delete "${caseId}": no case.json found at ${dir}`);
        if (opts.closedOnly && meta.status !== "closed" && meta.status !== "archived") {
          throw new CaseLifecycleError(
            `case ${caseId} must be closed or archived before it can be deleted`,
            409,
          );
        }
        await this.whileClosed(caseId, "deleted", () => rm(dir, { recursive: true }), ["active", "archived"]);
        this.forgetInMemory(caseId);
        await opts.afterDelete?.();
      });
    } finally {
      const left = (this.deleting.get(caseId) ?? 1) - 1;
      if (left > 0) this.deleting.set(caseId, left);
      else this.deleting.delete(caseId);
    }
  }

  // Case ids retired by a delete. An incident number is not free again once it has been used: the
  // reports, ZIP archives and .dfircase exports written before the delete still carry it, so
  // reissuing it would file two unrelated investigations under one number. Kept at the cases root
  // (a dot-file, like the global job ledger) rather than inside any case, because the whole point
  // is to outlive every folder it names.
  private retiredCaseIdsPath(): string {
    return join(this.root, RETIRED_IDS_FILENAME);
  }

  // A missing or corrupt ledger reads as empty rather than throwing: not knowing which numbers are
  // retired must never be able to block creating a case.
  async listRetiredCaseIds(): Promise<string[]> {
    try {
      const parsed: unknown = JSON.parse(await readFile(this.retiredCaseIdsPath(), "utf8"));
      if (!Array.isArray(parsed)) return [];
      return parsed.filter((id): id is string => typeof id === "string" && isValidCaseId(id)).sort();
    } catch {
      return [];
    }
  }

  // Read-modify-write, so it serializes on a lock the same way the OCR index and sequence
  // allocation do — two deletes landing together must not drop one of the two ids.
  async retireCaseId(caseId: string): Promise<void> {
    if (!isValidCaseId(caseId)) throw new Error(`refusing to retire invalid caseId "${caseId}"`);
    await this.retiredLock.runExclusive(RETIRED_IDS_FILENAME, async () => {
      const retired = await this.listRetiredCaseIds();
      if (retired.includes(caseId)) return;
      const next = [...retired, caseId].sort();
      await atomicWrite(this.retiredCaseIdsPath(), JSON.stringify(next, null, 2));
    });
  }

  // Creating a case CLAIMS its id, so the write of case.json is exclusive (`wx` — O_CREAT|O_EXCL,
  // atomic on POSIX and Windows alike) and is the FIRST thing that touches the case. A caller's
  // caseExists() check cannot make this safe on its own: two requests for the same id both pass the
  // check, both used to create, and the later metadata write simply became the final case.json —
  // which under team auth handed BOTH requesters administrator on the same case. The exclusive
  // create is the single point where exactly one of them can win.
  //
  // This also subsumes the archived-collision hazard the callers used to be responsible for:
  // caseDir() resolves an archived id to its archived folder, so the claim collides there too and
  // an archived case's metadata can no longer be silently overwritten.
  //
  // The subdirectories are created only AFTER the claim succeeds, so a loser leaves nothing behind.
  // Under the metadata lock, so a create cannot land inside a delete's rm of the same id (#1808).
  // Refused outright while a delete of the same id is in flight (#1826) — checked before queueing, so
  // a create never waits behind the delete only to land inside its cleanup window.
  /** A delete of the id is in flight (see deleteCaseFolder). Whole-case imports check it (#1831). */
  isDeleting(caseId: string): boolean {
    return this.deleting.has(caseId);
  }

  /**
   * For a caller that writes a case folder itself instead of calling createCase — the demo seeder
   * (#1853). Runs `fn` under the same per-case lock and id-reuse refusals createCase applies: refused
   * while a delete of the id is in flight, and, when the id has no case yet, while a part-deleted
   * folder still holds files. `fn` learns whether the id is new, so it can clear stale access first.
   */
  async withSeedSlot<T>(caseId: string, fn: (isNew: boolean, generation: string) => Promise<T>): Promise<T> {
    if (this.deleting.has(caseId)) throw new CaseBeingDeletedError(caseId);
    return this.metaLock.runExclusive(caseId, async () => {
      const isNew = !(await this.caseExists(caseId));
      if (isNew) await this.refuseLeftoverFolder(caseId, this.caseDir(caseId));
      // #1855: the seeder writes this generation in its first case.json, so the new case is never
      // visible without one. A reseed replaces the case: old work is shut out while it runs.
      const generation = newCaseGeneration();
      const seed = async () => {
        if (!isNew) this.forgetInMemory(caseId); // a reseed replaces the case (#1866)
        const value = await fn(isNew, generation);
        await this.ensureSeedGeneration(caseId, generation);
        return value;
      };
      return isNew ? seed() : this.whileClosed(caseId, "replaced", seed, []);
    });
  }

  async createCase(input: CreateCaseInput): Promise<CaseMeta> {
    if (this.deleting.has(input.caseId)) throw new CaseBeingDeletedError(input.caseId);
    return this.metaLock.runExclusive(input.caseId, () => this.createCaseLocked(input));
  }

  // A seeder that did not write the generation it was given gets it now (#1855). Past the guard: the
  // caller holds the case lock, and a reseed holds the folder closed.
  private async ensureSeedGeneration(caseId: string, generation: string): Promise<void> {
    const meta = await this.getCaseMeta(caseId);
    if (!meta || meta.generation === generation) return;
    const next = JSON.stringify({ ...meta, generation }, null, 2);
    await atomicWrite(this.caseMetaPath(caseId), next, { caseGuard: false });
  }

  private async createCaseLocked(input: CreateCaseInput): Promise<CaseMeta> {
    const meta: CaseMeta = {
      generation: newCaseGeneration(),
      caseId: input.caseId,
      name: input.name,
      createdAt: new Date().toISOString(),
      investigator: input.investigator,
      aiProvider: input.aiProvider,
    };
    // Resolved once: caseDir() is existsSync-based, so re-resolving it after the mkdir below would
    // answer a different question than the one the claim is made against.
    const dir = this.caseDir(input.caseId);
    await this.refuseLeftoverFolder(input.caseId, dir);
    await mkdir(dir, { recursive: true });
    try {
      await writeFile(join(dir, "case.json"), JSON.stringify(meta, null, 2), {
        encoding: "utf8",
        flag: "wx",
      });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") {
        throw new CaseAlreadyExistsError(input.caseId);
      }
      throw err;
    }
    try {
      await input.onClaimed?.();
    } catch (err) {
      await this.undoClaim(dir);
      throw err;
    }
    for (const sub of [
      this.screenshotsDir(input.caseId),
      this.metadataDir(input.caseId),
      this.stateDir(input.caseId),
      this.reportsDir(input.caseId),
      this.importsDir(input.caseId),
    ]) {
      await mkdir(sub, { recursive: true });
    }
    return meta;
  }

  // A non-empty folder with no case.json is a partial delete's leftover (#1831). An empty folder is
  // harmless, and a folder that has case.json is a live case — its claim below fails as before.
  private async refuseLeftoverFolder(caseId: string, dir: string): Promise<void> {
    let entries: string[];
    try {
      entries = await readdir(dir);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
      throw err;
    }
    if (entries.length > 0 && !entries.includes("case.json")) throw new CaseFolderLeftoverError(caseId, dir);
  }

  // Removes only what the claim wrote: case.json, then the folder if it is still empty. Anything
  // that appeared in it meanwhile stays; the error the caller rethrows says the create failed.
  private async undoClaim(dir: string): Promise<void> {
    await unlink(join(dir, "case.json")).catch(() => undefined);
    await rmdir(dir).catch(() => undefined);
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
  async saveScreenshot(
    caseId: string,
    filename: string,
    bytes: Buffer,
    provenance?: ArtifactProvenance,
  ): Promise<string> {
    const path = join(this.screenshotsDir(caseId), filename);
    await withCaseWrite(path, () => writeFile(path, bytes, { flag: "wx" }));
    // Hash the buffer we just wrote rather than re-reading the file: same bytes, no second pass
    // over evidence that can run to hundreds of megabytes.
    await this.announceArtifact({
      caseId,
      path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      sha1: createHash("sha1").update(bytes).digest("hex"),
      kind: "screenshot",
      provenance,
    });
    return path;
  }

  async appendCapture(caseId: string, metadata: CaptureMetadata): Promise<CaptureMetadata> {
    const path = this.capturesLogPath(caseId);
    await withCaseWrite(path, () => appendFile(path, JSON.stringify(metadata) + "\n", "utf8"));
    return metadata;
  }

  async nextSequenceNumber(caseId: string): Promise<number> {
    return this.reserveSequence("capture", caseId, () =>
      this.maxSequenceInLog(this.capturesLogPath(caseId), "sequenceNumber"),
    );
  }

  /**
   * The next-safe recovery number for an append-only .jsonl audit log; 0 when the log does not
   * exist yet. `Math.max(nonEmptyLineCount, highest value of `field` seen)`, never just a line
   * count (#1119, Codex code-review finding H1/M1) and never just the field's own max in
   * isolation:
   *   - A reservation burned by a failed append never produced a line at all, so a line count alone
   *     under-reports how many numbers were issued once a restart forgets the in-memory high-water
   *     mark — the field's own max recovers past that gap.
   *   - Some historical custody rows predate the `seq` field entirely (#231) and would count as 0
   *     toward the max if only the field were read — the line count still recovers the correct
   *     floor for those, exactly matching the pre-#1119 behavior for a fully legacy log.
   * A NON-EMPTY line that fails to parse as JSON is a truncated/corrupted write, never silently
   * skipped: it throws, because silently recovering past it risks reissuing that very row's own
   * number (Codex's H1 finding — a burned reservation and a genuinely corrupted append are
   * indistinguishable from a line count alone, so this fails closed and asks for repair instead of
   * guessing). A row that parses but simply lacks `field` (the legacy-custody case above) is not an
   * error — it still counts toward the line-count floor, just not toward the field's own max.
   */
  private async maxSequenceInLog(path: string, field: "sequenceNumber" | "seq"): Promise<number> {
    let raw: string;
    try {
      raw = await readFile(path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return 0;
      throw err;
    }
    let count = 0;
    let maxField = 0;
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      count += 1;
      let row: Record<string, unknown>;
      try {
        row = JSON.parse(line) as Record<string, unknown>;
      } catch (err) {
        throw new Error(
          `${path} has a corrupted/truncated line at record ${count} — refusing to allocate a sequence number past it until it is repaired: ${(err as Error).message}`,
        );
      }
      const value = row[field];
      if (typeof value === "number" && Number.isFinite(value) && value > maxField) maxField = value;
    }
    return Math.max(count, maxField);
  }

  // Persist an uploaded CSV verbatim as evidence (mkdirs for cases created before
  // the imports/ dir existed). Returns the stored absolute path.
  async saveImport(
    caseId: string,
    filename: string,
    text: string,
    provenance?: ArtifactProvenance,
  ): Promise<string> {
    const path = join(this.importsDir(caseId), filename);
    // Create-exclusive, for the same reason as saveScreenshot above (#214).
    await this.withCaseWrite(path, async () => {
      await mkdir(this.importsDir(caseId), { recursive: true });
      await writeFile(path, text, { encoding: "utf8", flag: "wx" });
    });
    // utf8 in, utf8 on disk — so this matches what a later re-read hashes during verification.
    await this.announceArtifact({
      caseId,
      path,
      sha256: createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex"),
      sha1: createHash("sha1").update(Buffer.from(text, "utf8")).digest("hex"),
      kind: "import",
      provenance,
    });
    return path;
  }

  /**
   * Persist a BINARY original verbatim as evidence — a raw .evtx or PCAP an external parser was run
   * against (#688). saveImport above re-encodes its input as UTF-8, which silently corrupts binary
   * bytes, so preserving an original byte-for-byte needs its own method rather than a flag.
   *
   * Identical to saveImport in every other respect: same directory, same create-exclusive write
   * (#214), same artifact announcement, so the original lands in the chain of custody exactly like
   * the tool output it produced.
   */
  async saveRawImport(
    caseId: string,
    filename: string,
    bytes: Buffer,
    provenance?: ArtifactProvenance,
  ): Promise<string> {
    const path = join(this.importsDir(caseId), filename);
    await this.withCaseWrite(path, async () => {
      await mkdir(this.importsDir(caseId), { recursive: true });
      await writeFile(path, bytes, { flag: "wx" });
    });
    await this.announceArtifact({
      caseId,
      path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      sha1: createHash("sha1").update(bytes).digest("hex"),
      kind: "import",
      provenance,
    });
    return path;
  }

  /** A server file copied by its open handle (POST /import-file), hashed in the same pass (#2055). */
  async saveImportFromHandle(
    caseId: string,
    filename: string,
    handle: FileHandle,
    provenance?: ArtifactProvenance,
  ): Promise<{ path: string; bytes: number }> {
    const path = join(this.importsDir(caseId), filename);
    const { bytes, sha256, sha1 } = await this.withCaseWrite(path, async () => {
      await mkdir(this.importsDir(caseId), { recursive: true });
      return copyHandleHashed(handle, path); // create-exclusive (#214)
    });
    await this.announceArtifact({ caseId, path, sha256, sha1, kind: "import", provenance });
    return { path, bytes };
  }

  async appendImport(caseId: string, metadata: ImportMetadata): Promise<ImportMetadata> {
    await this.withCaseWrite(this.importsLogPath(caseId), async () => {
      await mkdir(this.metadataDir(caseId), { recursive: true });
      await appendFile(this.importsLogPath(caseId), JSON.stringify(metadata) + "\n", "utf8");
    });
    return metadata;
  }

  /** `fn` as one admitted write under `path`; refused for a deleted, replaced or moved case (#1855). */
  withCaseWrite<T>(path: string, fn: () => Promise<T>): Promise<T> {
    return withCaseWrite(path, fn);
  }

  /** mkdir -p for a folder inside a case, refused instead of recreating a deleted case (#1855). */
  async mkdirInCase(dir: string): Promise<void> {
    await withCaseWrite(dir, () => mkdir(dir, { recursive: true }));
  }

  /**
   * Atomically patch case.json with the given fields. Unknown fields are preserved. Throws
   * CaseNotFoundError when the case has no case.json — it never writes a default one (#1808).
   * `guard` runs on the current metadata inside the lock and throws to refuse the write.
   */
  async updateCaseMeta(caseId: string, patch: Partial<CaseMeta>, guard?: CaseMetaGuard): Promise<CaseMeta> {
    return this.metaLock.runExclusive(caseId, () => this.writeCaseMetaLocked(caseId, patch, guard));
  }

  // The body of updateCaseMeta; the caller holds metaLock for this case.
  private async writeCaseMetaLocked(
    caseId: string,
    patch: Partial<CaseMeta>,
    guard?: CaseMetaGuard,
  ): Promise<CaseMeta> {
    const existing = await this.getCaseMeta(caseId);
    if (!existing) throw new CaseNotFoundError(caseId);
    guard?.(existing);
    const updated: CaseMeta = { ...existing, ...patch, caseId };
    // The incarnation is never patched (#1855), and a legacy case is not given one here.
    if (existing.generation === undefined) delete updated.generation;
    else updated.generation = existing.generation;
    await atomicWrite(this.caseMetaPath(caseId), JSON.stringify(updated, null, 2));
    return updated;
  }

  // Ordinal for the next chain-of-custody entry (#231). Same allocator as captures and imports, so a
  // custody record that fails to append burns its number rather than letting the next one reuse it —
  // gaps are the safe direction for provenance, reuse is not.
  async nextCustodySeq(caseId: string): Promise<number> {
    return this.reserveSequence("custody", caseId, () =>
      this.maxSequenceInLog(this.custodyLogPath(caseId), "seq"),
    );
  }

  async nextImportSeq(caseId: string): Promise<number> {
    return this.reserveSequence("import", caseId, () =>
      this.maxSequenceInLog(this.importsLogPath(caseId), "sequenceNumber"),
    );
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
      await this.mkdirInCase(this.metadataDir(caseId));
      const index = await this.loadOcrIndex(caseId);
      const updated: OcrIndex = { ...index, [entry.screenshotFile]: entry };
      await atomicWrite(this.ocrIndexPath(caseId), JSON.stringify(updated, null, 2));
    });
  }
}
