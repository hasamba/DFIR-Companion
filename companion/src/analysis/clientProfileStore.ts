import { mkdir, readFile, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import { PROFILE_ID_RE, type ClientProfile } from "./clientProfile.js";

/**
 * Client profiles on disk (#2670): one JSON file per client in a folder BESIDE the cases root (like
 * incident-types/), never inside a case — a client outlives every hunt case. Writes are per-profile
 * serialised. Only the instance administrator edits a profile (the routes are admin-only, D3); case
 * readers see a client's earlier-hunt data only through cases they can already open.
 */
const lock = new StateLock();

export class ClientProfileStore {
  constructor(private readonly dir: string) {}

  private path(id: string): string {
    if (!PROFILE_ID_RE.test(id)) throw new Error(`invalid client profile id "${id}"`);
    return join(this.dir, `${id}.json`);
  }

  async get(id: string): Promise<ClientProfile | null> {
    if (!PROFILE_ID_RE.test(id)) return null;
    try {
      const p = JSON.parse(await readFile(this.path(id), "utf8")) as ClientProfile;
      return p && typeof p === "object" && p.id === id ? p : null;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || err instanceof SyntaxError) return null;
      throw err;
    }
  }

  async list(): Promise<ClientProfile[]> {
    let names: string[];
    try {
      names = await readdir(this.dir);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const out: ClientProfile[] = [];
    for (const n of names.filter((x) => x.endsWith(".json"))) {
      const p = await this.get(n.slice(0, -5)).catch(() => null);
      if (p) out.push(p);
    }
    return out.sort((a, b) => a.name.localeCompare(b.name));
  }

  async create(p: ClientProfile): Promise<ClientProfile> {
    await mkdir(this.dir, { recursive: true });
    await atomicWrite(this.path(p.id), JSON.stringify(p, null, 2));
    return p;
  }

  /** Read-modify-write one profile; null when it does not exist. */
  update(id: string, fn: (p: ClientProfile) => ClientProfile): Promise<ClientProfile | null> {
    return lock.runExclusive(id, async () => {
      const cur = await this.get(id);
      if (!cur) return null;
      const next = fn(cur);
      await atomicWrite(this.path(id), JSON.stringify(next, null, 2));
      return next;
    });
  }

  /**
   * Run `fn` under this profile's lock (#2941) — the lock update() and remove() hold. Linking a case
   * runs here, so a link and a delete of the same client can never interleave.
   */
  exclusive<T>(id: string, fn: () => Promise<T>): Promise<T> {
    return lock.runExclusive(id, fn);
  }

  /**
   * Delete one profile (#2941) under its lock. `guard` sees the current profile and returns a reason
   * to refuse (e.g. the cases still linked) or null to go ahead; check and delete are one locked step.
   */
  remove<R>(id: string, guard: (p: ClientProfile) => Promise<R | null>): Promise<RemoveResult<R>> {
    return lock.runExclusive(id, async (): Promise<RemoveResult<R>> => {
      const cur = await this.get(id);
      if (!cur) return { status: "missing" };
      const reason = await guard(cur);
      if (reason !== null) return { status: "refused", reason };
      await rm(this.path(id));
      return { status: "deleted", profile: cur };
    });
  }
}

export type RemoveResult<R> =
  { status: "missing" } | { status: "refused"; reason: R } | { status: "deleted"; profile: ClientProfile };
