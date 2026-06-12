import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import { normalizeHash } from "./nsrl.js";

// Persists the NSRL known-good hash set (issue #63). GLOBAL — shared across cases, like the IOC
// whitelist / TemplateStore / ArtifactBundleStore: a known-software corpus is environment-level and
// reused across investigations. Stored as a plain newline-delimited, normalized hash file (compact,
// fast to load into a Set) rather than JSON, because the set can be large (the RDS has millions of
// hashes). Auto-marking writes per-case legitimate markers, so the set itself stays case-agnostic.
//
// The in-memory Set is cached after first load and invalidated on every mutation, so the per-import
// auto-apply sweep doesn't re-read (and re-parse) the file each time.
export class NsrlStore {
  private cache: Set<string> | null = null;

  constructor(private readonly file: string) {}

  async load(): Promise<ReadonlySet<string>> {
    if (this.cache) return this.cache;
    try {
      const raw = await readFile(this.file, "utf8");
      const set = new Set<string>();
      // Re-validate on read so a hand-edited file can't inject a non-hash line into matching.
      for (const line of raw.split(/\r?\n/)) {
        const n = normalizeHash(line);
        if (n) set.add(n);
      }
      this.cache = set;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") this.cache = new Set();
      else throw err;
    }
    return this.cache;
  }

  async count(): Promise<number> {
    return (await this.load()).size;
  }

  private async persist(set: Set<string>): Promise<void> {
    // Create the parent dir only if missing. mkdir(recursive) on a drive root (e.g. C:\ when the
    // cases root is C:\cases) throws EPERM on Windows, so guard on exists (mirrors IocWhitelistStore).
    const dir = dirname(this.file);
    if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, set.size ? [...set].sort().join("\n") + "\n" : "");
    this.cache = set;
  }

  // Union new hashes into the set. Normalizes + dedups; only valid hashes are kept. Returns how many
  // were NEW and the resulting total. No-op write when nothing new (keeps re-imports cheap).
  async addMany(hashes: readonly string[]): Promise<{ added: number; total: number }> {
    const set = new Set(await this.load());
    let added = 0;
    for (const h of hashes) {
      const n = normalizeHash(h);
      if (n && !set.has(n)) {
        set.add(n);
        added++;
      }
    }
    if (added > 0) await this.persist(set);
    return { added, total: set.size };
  }

  // Wipe the set (e.g. to swap in a different RDS release).
  async clear(): Promise<void> {
    await this.persist(new Set());
  }

  // Sorted, newline-delimited dump for backup / sharing.
  async exportText(): Promise<string> {
    const set = await this.load();
    return set.size ? [...set].sort().join("\n") + "\n" : "";
  }
}
