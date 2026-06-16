// GLOBAL store of user-authored declarative importers — a folder beside `cases/` (mirrors
// IocWhitelistStore / NsrlStore). Each `*.json` file is one ImporterSpec; `config.json` holds the
// precedence setting. A malformed file is logged + skipped, NEVER fatal — one bad importer can't
// break startup or the others.
import { readFile, readdir, mkdir, unlink } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import { parseImporterSpec, type ImporterSpec, type SpecParseError } from "./importerSpec.js";
import { buildImporter, type ExternalImporter } from "./declarativeImporter.js";

export type ImporterPrecedence = "builtin-first" | "external-first";

export interface ImporterMeta { id: string; label: string; file: string; priority: number; }
export interface ImporterLoadError { file: string; errors: SpecParseError[]; }
export interface ImporterRegistry {
  importers: Map<string, ExternalImporter>;
  meta: ImporterMeta[];
  errors: ImporterLoadError[];
}

const CONFIG_FILE = "config.json";

export class ImporterStore {
  constructor(private readonly dir: string) {}

  private async ensureDir(): Promise<void> {
    if (!existsSync(this.dir)) await mkdir(this.dir, { recursive: true });
  }

  // Scan the folder, validate every *.json (except config.json), build the importer registry.
  async loadAll(): Promise<ImporterRegistry> {
    const importers = new Map<string, ExternalImporter>();
    const meta: ImporterMeta[] = [];
    const errors: ImporterLoadError[] = [];
    let files: string[] = [];
    try { files = await readdir(this.dir); } catch { return { importers, meta, errors }; }

    for (const file of files) {
      if (!file.endsWith(".json") || file === CONFIG_FILE) continue;
      let raw: unknown;
      try { raw = JSON.parse(await readFile(join(this.dir, file), "utf8")); }
      catch (err) { errors.push({ file, errors: [{ path: "(file)", message: `not valid JSON: ${(err as Error).message}` }] }); continue; }
      const parsed = parseImporterSpec(raw);
      if (!parsed.ok) { errors.push({ file, errors: parsed.errors }); continue; }
      if (importers.has(parsed.spec.id)) { errors.push({ file, errors: [{ path: "id", message: `duplicate id "${parsed.spec.id}"` }] }); continue; }
      importers.set(parsed.spec.id, buildImporter(parsed.spec));
      meta.push({ id: parsed.spec.id, label: parsed.spec.label, file, priority: parsed.spec.match.priority });
    }
    return { importers, meta, errors };
  }

  async save(spec: ImporterSpec): Promise<void> {
    await this.ensureDir();
    await atomicWrite(join(this.dir, `${spec.id}.json`), JSON.stringify(spec, null, 2));
  }

  async delete(id: string): Promise<boolean> {
    const file = join(this.dir, `${id}.json`);
    if (!existsSync(file)) return false;
    await unlink(file);
    return true;
  }

  async precedence(): Promise<ImporterPrecedence> {
    try {
      const cfg = JSON.parse(await readFile(join(this.dir, CONFIG_FILE), "utf8")) as { precedence?: string };
      return cfg.precedence === "external-first" ? "external-first" : "builtin-first";
    } catch { return "builtin-first"; }
  }

  async setPrecedence(p: ImporterPrecedence): Promise<void> {
    await this.ensureDir();
    await atomicWrite(join(this.dir, CONFIG_FILE), JSON.stringify({ precedence: p }, null, 2));
  }
}
