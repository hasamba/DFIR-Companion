// On-disk layout of the installed detection-rule packs (#2349), and the only code that writes it.
//
//   <dir>/packs/<packId>/tags.yaml + pack.json   one IMMUTABLE folder per installed pack
//   <dir>/packs/staging-<uuid>/                  a pack being written; renamed to its id when complete
//   <dir>/active.json                            the pointer: { current, previous } pack ids
//
// WHY A POINTER. Activation used to move folders (current → previous, staging → current). Between the
// two renames there was no current pack, so an import reading the rules at that moment silently got
// the bundled set, and a crash there left it that way. Now a pack folder is complete before anything
// names it, and switching packs is one atomic rename of a small file (write temp + rename), so every
// reader resolves either the old pointer or the new one. A folder is removed only AFTER the pointer
// that stopped naming it is in place.
//
// The pointer is data on disk, so its ids are checked against PACK_ID before they are joined into a
// path. A missing pointer with no pack folders means no pack was ever installed; a missing pointer
// beside pack folders, or one that does not parse, is reported by the store (the bundled rules are
// used and the panel says why) instead of guessing — and no pack folder is deleted.

import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";

/** The fs calls the layout makes — injectable so tests can fail or delay any one step. */
export interface PackFs {
  mkdir(path: string, opts: { recursive: true }): Promise<unknown>;
  readFile(path: string, encoding: "utf8"): Promise<string>;
  writeFile(path: string, data: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  rm(path: string, opts: { recursive: true; force: true }): Promise<void>;
  readdir(path: string): Promise<string[]>;
}

export const defaultPackFs: PackFs = {
  mkdir: (p, o) => mkdir(p, o),
  readFile: (p, e) => readFile(p, e),
  writeFile: (p, d) => writeFile(p, d),
  rename: (a, b) => rename(a, b),
  rm: (p, o) => rm(p, o),
  readdir: (p) => readdir(p),
};

export interface PackPointer {
  current: string | null;
  previous: string | null;
}

export type PointerRead =
  { kind: "ok"; pointer: PackPointer } | { kind: "missing" } | { kind: "corrupt"; reason: string };

const PACK_ID = /^p-[0-9a-f]{12}-[0-9a-f]{8}$/;
const STAGING = /^staging-[0-9a-f-]{36}$/;
const POINTER = "active.json";
const POINTER_TEMP = /^active\.json\.[0-9a-f-]{36}\.tmp$/;

/** A fresh id for a pack folder: its rules' SHA-256 prefix plus a random suffix (never reused). */
export function newPackId(rulesSha256: string): string {
  return `p-${rulesSha256.slice(0, 12)}-${randomUUID().slice(0, 8)}`;
}

function validId(v: unknown): v is string | null {
  return v === null || (typeof v === "string" && PACK_ID.test(v));
}

export function pointerIds(p: PackPointer): Set<string> {
  return new Set([p.current, p.previous].filter((id): id is string => id !== null));
}

export class PackLayout {
  constructor(
    readonly dir: string,
    private readonly fs: PackFs = defaultPackFs,
  ) {}

  get packsDir(): string {
    return join(this.dir, "packs");
  }

  packDir(id: string): string {
    return join(this.packsDir, id);
  }

  async readPointer(): Promise<PointerRead> {
    let raw: string;
    try {
      raw = await this.fs.readFile(join(this.dir, POINTER), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { kind: "missing" };
      return { kind: "corrupt", reason: (err as Error).message };
    }
    try {
      const doc = JSON.parse(raw) as Partial<PackPointer> | null;
      const current = doc?.current ?? null;
      const previous = doc?.previous ?? null;
      if (!doc || typeof doc !== "object" || !validId(current) || !validId(previous)) {
        return { kind: "corrupt", reason: "it does not name a valid pack" };
      }
      return { kind: "ok", pointer: { current, previous } };
    } catch {
      return { kind: "corrupt", reason: "it is not valid JSON" };
    }
  }

  /**
   * Atomically replace the pointer, through atomicWrite: temp file + rename, with its retry on a
   * transient Windows lock (EPERM/EBUSY/EACCES from antivirus or an indexer holding the file). On
   * failure the old pointer is untouched and the temp is removed. The fs seam is passed through, so
   * a test can fail or lock any step.
   */
  async writePointer(pointer: PackPointer): Promise<void> {
    await this.fs.mkdir(this.dir, { recursive: true });
    await atomicWrite(join(this.dir, POINTER), JSON.stringify({ schema: 1, ...pointer }, null, 2) + "\n", {
      writeFile: (p, c) => this.fs.writeFile(p, typeof c === "string" ? c : Buffer.from(c).toString("utf8")),
      rename: (a, b) => this.fs.rename(a, b),
      unlink: (p) => this.fs.rm(p, { recursive: true, force: true }),
    });
  }

  /** The pack folders on disk (complete packs, named by id), whether or not the pointer names them. */
  async listPackIds(): Promise<string[]> {
    return (await this.list(this.packsDir)).filter((name) => PACK_ID.test(name));
  }

  /**
   * Write a pack's files to a staging folder and rename it to its id, so the folder under its final
   * name is always complete. On failure the staging folder is removed (or swept at the next start).
   */
  async writePack(id: string, files: Readonly<Record<string, string>>): Promise<void> {
    if (!PACK_ID.test(id)) throw new Error(`invalid pack id ${id}`);
    const staging = join(this.packsDir, `staging-${randomUUID()}`);
    await this.fs.mkdir(staging, { recursive: true });
    try {
      for (const [name, text] of Object.entries(files)) await this.fs.writeFile(join(staging, name), text);
      await this.fs.rename(staging, this.packDir(id));
    } catch (err) {
      await this.fs.rm(staging, { recursive: true, force: true }).catch(() => {});
      throw err;
    }
  }

  /** Best-effort removal of pack folders; one that cannot be removed now is swept at the next start. */
  async removePacks(ids: Iterable<string>): Promise<void> {
    for (const id of ids) {
      if (!PACK_ID.test(id)) continue;
      await this.fs.rm(this.packDir(id), { recursive: true, force: true }).catch(() => {});
    }
  }

  /**
   * Startup sweep: staging leftovers, pointer temp files, and pack folders the pointer does not name.
   * `keep` null means the pointer cannot be trusted — then only staging and temp files go, never a
   * pack folder, so nothing that might still be wanted is deleted. Returns what could not be removed.
   */
  async sweep(keep: ReadonlySet<string> | null): Promise<string[]> {
    const failed: string[] = [];
    const remove = async (path: string) => {
      await this.fs.rm(path, { recursive: true, force: true }).catch(() => failed.push(path));
    };
    for (const name of await this.list(this.packsDir)) {
      if (STAGING.test(name) || (keep && PACK_ID.test(name) && !keep.has(name))) {
        await remove(join(this.packsDir, name));
      }
    }
    for (const name of await this.list(this.dir)) {
      if (POINTER_TEMP.test(name)) await remove(join(this.dir, name));
    }
    return failed;
  }

  private async list(path: string): Promise<string[]> {
    try {
      return await this.fs.readdir(path);
    } catch {
      return [];
    }
  }
}
