import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import { parseKevJson, buildKevCatalog, type KevCatalog, type KevEntry } from "./kev.js";

// Persists the CISA KEV catalog (issue #99). GLOBAL — shared across cases, like the IOC
// whitelist / NSRL / TemplateStore / ArtifactBundleStore: the KEV catalog is environment-level
// (which CVEs are actively exploited) and reused across investigations.
//
// Stored as a compact JSON array of entries (not the full CISA feed — we keep only the fields
// we use) in kev/catalog.json next to cases/. The in-memory catalog Map is cached after first
// load and invalidated on every mutation so synthesis calls get the Map from memory.
//
// Same SUBDIR-not-sibling rationale as the whitelist and NSRL (prevents EPERM on a drive root).
export class KevStore {
  private cache: KevCatalog | null = null;

  constructor(private readonly file: string) {}

  // Load and cache the catalog. Returns an empty Map when the file doesn't exist yet.
  async loadCatalog(): Promise<KevCatalog> {
    if (this.cache) return this.cache;
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as unknown;
      const entries = Array.isArray(raw) ? parseKevJson(raw) : parseKevJson(raw);
      this.cache = buildKevCatalog(entries);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        this.cache = new Map();
      } else {
        throw err;
      }
    }
    return this.cache;
  }

  async count(): Promise<number> {
    return (await this.loadCatalog()).size;
  }

  private async persist(entries: KevEntry[]): Promise<void> {
    const dir = dirname(this.file);
    if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, JSON.stringify(entries, null, 2));
    this.cache = buildKevCatalog(entries);
  }

  // Ingest a KEV feed JSON (the CISA full feed object or a bare array). Replaces the stored
  // catalog (not union — a fresh download supersedes the old one). Returns total entry count.
  async ingestFromJson(json: unknown): Promise<{ total: number }> {
    const entries = parseKevJson(json);
    await this.persist(entries);
    return { total: entries.length };
  }

  // Wipe the catalog (e.g. before loading a new version).
  async clear(): Promise<void> {
    await this.persist([]);
  }

  // Metadata for the /kev/status route — reads the raw JSON to pull CISA's catalogVersion
  // and dateReleased without requiring a separate metadata file.
  async meta(): Promise<{ count: number; catalogVersion?: string; dateReleased?: string }> {
    const count = await this.count();
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as Record<string, unknown>;
      return {
        count,
        catalogVersion: raw.catalogVersion !== undefined ? String(raw.catalogVersion) : undefined,
        dateReleased: raw.dateReleased !== undefined ? String(raw.dateReleased) : undefined,
      };
    } catch {
      return { count };
    }
  }

  // Persist the raw CISA feed JSON (preserving catalogVersion / dateReleased for meta()) and
  // rebuild the catalog from it. Used by import-url / import-file where we have the full feed.
  async ingestRaw(raw: unknown): Promise<{ total: number }> {
    const entries = parseKevJson(raw);
    // Persist the raw feed (with CISA metadata) alongside the entry array so meta() can read it.
    const dir = dirname(this.file);
    if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, JSON.stringify(raw, null, 2));
    this.cache = buildKevCatalog(entries);
    return { total: entries.length };
  }
}
