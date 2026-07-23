import { readFile, readdir, mkdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { atomicWrite } from "../storage/atomicWrite.js";
import { storeFilePath } from "../storage/safeStoreId.js";
import {
  BUILT_IN_DASHBOARD_VIEWS,
  normalizeDashboardView,
  type DashboardView,
} from "./dashboardViews.js";

// Persistence for dashboard view presets (#142). Views are GLOBAL — shared across cases, like report
// templates / case templates / triage bundles — so an analyst authors a custom layout once and uses it
// on any case. Built-ins ship with the app; custom ones are saved as JSON in a global `dashboard-views/`
// dir beside `cases/`. Mirrors ReportTemplateStore: a built-in is EDITABLE in place — saving under a
// built-in id writes an OVERRIDE file (flagged `customized`), and deleting that file resets the built-in
// to its shipped default. `builtIn`/`customized` are derived from the id, never trusted from input.
// Every read/write runs the value through `normalizeDashboardView`, so a hand-edited or partial file can
// never produce a malformed view (bad section ids dropped, etc.).

export interface StoredDashboardView extends DashboardView {
  builtIn: boolean;
  customized: boolean; // a built-in with a saved override on disk (derived, not persisted)
}

export class DashboardViewStore {
  constructor(private readonly root: string) {}

  // Validates the id and guarantees containment beneath root (#213).
  private path(id: string): string {
    return storeFilePath(this.root, id);
  }

  isBuiltIn(id: string): boolean {
    return BUILT_IN_DASHBOARD_VIEWS.some((v) => v.id === id);
  }

  private builtIn(id: string): DashboardView | undefined {
    return BUILT_IN_DASHBOARD_VIEWS.find((v) => v.id === id);
  }

  private async readSaved(id: string): Promise<DashboardView | null> {
    try {
      return normalizeDashboardView(JSON.parse(await readFile(this.path(id), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  // All saved view files keyed by id (built-in overrides + custom). Malformed files are skipped.
  private async loadSavedMap(): Promise<Map<string, DashboardView>> {
    const map = new Map<string, DashboardView>();
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
        const raw = normalizeDashboardView(JSON.parse(await readFile(join(this.root, entry), "utf8")));
        if (raw.id) map.set(raw.id, raw);
      } catch {
        // skip malformed files
      }
    }
    return map;
  }

  // Built-ins first (a saved override replaces the shipped default, flagged `customized`), then purely
  // custom views.
  async list(): Promise<StoredDashboardView[]> {
    const saved = await this.loadSavedMap();
    const out: StoredDashboardView[] = [];
    for (const v of BUILT_IN_DASHBOARD_VIEWS) {
      const override = saved.get(v.id);
      out.push(override
        ? { ...override, id: v.id, builtIn: true, customized: true }
        : { ...v, builtIn: true, customized: false });
    }
    for (const [id, v] of saved) {
      if (this.isBuiltIn(id)) continue; // already merged above as an override
      out.push({ ...v, builtIn: false, customized: false });
    }
    return out;
  }

  async get(id: string): Promise<StoredDashboardView | null> {
    const saved = await this.readSaved(id);
    if (this.isBuiltIn(id)) {
      const builtin = this.builtIn(id)!;
      return saved
        ? { ...saved, id, builtIn: true, customized: true }
        : { ...builtin, builtIn: true, customized: false };
    }
    return saved ? { ...saved, builtIn: false, customized: false } : null;
  }

  // Save a view. A built-in id writes an OVERRIDE (the built-in becomes editable in place); any other id
  // creates/updates a custom view. The payload is normalized; `builtIn`/`customized` are derived.
  async save(input: unknown): Promise<StoredDashboardView> {
    const normalized = normalizeDashboardView(input);
    const id = normalized.id || randomUUID();
    const builtIn = this.isBuiltIn(id);
    const view: DashboardView = { ...normalized, id };
    await mkdir(this.root, { recursive: true });
    await atomicWrite(this.path(id), JSON.stringify(view, null, 2));
    return { ...view, builtIn, customized: builtIn };
  }

  // Remove the saved file: a custom view is deleted; a built-in's override is reset to the shipped
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
