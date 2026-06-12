import { readFile, readdir, mkdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { atomicWrite } from "../storage/atomicWrite.js";
import {
  BUILT_IN_REPORT_TEMPLATES,
  normalizeReportTemplate,
  type ReportTemplate,
} from "./reportTemplate.js";

// Persistence for report templates (issue #60). Templates are GLOBAL — shared across cases, like
// case templates and triage bundles — so a firm authors its branded layout once and applies it to
// any case. Built-ins ship with the app; custom ones are saved as JSON in a global `report-templates/`
// dir beside `cases/`. Mirrors ArtifactBundleStore: a built-in is EDITABLE in place — saving under a
// built-in id writes an OVERRIDE file (flagged `customized`), and deleting that file resets the
// built-in to its shipped default. `builtIn`/`customized` are derived from the id, never trusted from
// input. Every read/write runs the value through `normalizeReportTemplate`, so a hand-edited or
// partial file can never produce a malformed template.

export interface StoredReportTemplate extends ReportTemplate {
  builtIn: boolean;
  customized: boolean; // a built-in with a saved override on disk (derived, not persisted)
}

export class ReportTemplateStore {
  constructor(private readonly root: string) {}

  private path(id: string): string {
    return join(this.root, `${id}.json`);
  }

  // True when an id belongs to a shipped built-in (vs. a purely custom template).
  isBuiltIn(id: string): boolean {
    return BUILT_IN_REPORT_TEMPLATES.some((t) => t.id === id);
  }

  private builtIn(id: string): ReportTemplate | undefined {
    return BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === id);
  }

  private async readSaved(id: string): Promise<ReportTemplate | null> {
    try {
      return normalizeReportTemplate(JSON.parse(await readFile(this.path(id), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  // All saved template files keyed by id (built-in overrides + custom). Malformed files are skipped.
  private async loadSavedMap(): Promise<Map<string, ReportTemplate>> {
    const map = new Map<string, ReportTemplate>();
    let entries: string[];
    try {
      entries = await readdir(this.root);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return map;
      throw err;
    }
    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      try {
        const raw = normalizeReportTemplate(JSON.parse(await readFile(join(this.root, entry), "utf8")));
        if (raw.id) map.set(raw.id, raw);
      } catch {
        // skip malformed files
      }
    }
    return map;
  }

  // Built-ins first (a saved override replaces the shipped default, flagged `customized`), then
  // purely custom templates.
  async list(): Promise<StoredReportTemplate[]> {
    const saved = await this.loadSavedMap();
    const out: StoredReportTemplate[] = [];
    for (const t of BUILT_IN_REPORT_TEMPLATES) {
      const override = saved.get(t.id);
      out.push(override
        ? { ...override, id: t.id, builtIn: true, customized: true }
        : { ...t, builtIn: true, customized: false });
    }
    for (const [id, t] of saved) {
      if (this.isBuiltIn(id)) continue; // already merged above as an override
      out.push({ ...t, builtIn: false, customized: false });
    }
    return out;
  }

  async get(id: string): Promise<StoredReportTemplate | null> {
    const saved = await this.readSaved(id);
    if (this.isBuiltIn(id)) {
      const builtin = this.builtIn(id)!;
      return saved
        ? { ...saved, id, builtIn: true, customized: true }
        : { ...builtin, builtIn: true, customized: false };
    }
    return saved ? { ...saved, builtIn: false, customized: false } : null;
  }

  // Save a template. A built-in id writes an OVERRIDE (the built-in becomes editable in place); any
  // other id creates/updates a custom template. The payload is normalized (sections get full
  // coverage, accent/colour validated); `builtIn`/`customized` are derived from the id.
  async save(input: unknown): Promise<StoredReportTemplate> {
    const normalized = normalizeReportTemplate(input);
    const id = normalized.id || randomUUID();
    const builtIn = this.isBuiltIn(id);
    const template: ReportTemplate = { ...normalized, id };
    await mkdir(this.root, { recursive: true });
    await atomicWrite(this.path(id), JSON.stringify(template, null, 2));
    return { ...template, builtIn, customized: builtIn };
  }

  // Remove the saved file: a custom template is deleted; a built-in's override is reset to the shipped
  // default. Returns true when a file was removed, false when there was nothing on disk (ENOENT).
  async delete(id: string): Promise<boolean> {
    try {
      await unlink(this.path(id));
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw err;
    }
  }
}
