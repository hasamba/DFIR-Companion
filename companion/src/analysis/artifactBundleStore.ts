import { readFile, readdir, mkdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { atomicWrite } from "../storage/atomicWrite.js";

// A "triage bundle" (a.k.a. blueprint / triage pack) is a named, reusable selection of Velociraptor
// CLIENT artifacts. The analyst picks one, runs it as a hunt, and the collected results auto-import +
// synthesize. Bundles are GLOBAL (shared across cases, like case templates), not per-case: built-ins
// ship with the app and custom ones are saved as JSON in a global bundles dir. Mirrors TemplateStore.

export interface ArtifactBundle {
  id: string;
  name: string;                 // e.g. "Fast Triage"
  description: string;
  builtIn: boolean;
  artifacts: string[];          // Velociraptor CLIENT artifact names
  defaultWaitMinutes?: number;  // optional per-bundle default collect delay
  customized?: boolean;         // a built-in that has a saved override on disk (so the UI can offer "reset to default"); derived, not persisted
}

// Two editable starters. Artifact lists are standard built-in Velociraptor artifacts; the analyst
// duplicates/edits these against their own server's artifact list via the dashboard's artifact picker.
export const BUILT_IN_BUNDLES: readonly ArtifactBundle[] = [
  {
    id: "fast-triage",
    name: "Fast Triage",
    description: "Quick host triage — running processes, network connections, services, autoruns, and recent execution. Light enough to fan out broadly.",
    builtIn: true,
    artifacts: [
      "Windows.System.Pslist",
      "Windows.Network.Netstat",
      "Windows.System.Services",
      "Windows.Sys.StartupItems",
      "Windows.Forensics.Prefetch",
    ],
    defaultWaitMinutes: 10,
  },
  {
    id: "full-triage",
    name: "Full Triage",
    description: "Broader host triage — adds event logs, USN journal, UserAssist, LNK files, scheduled tasks, and Amcache for a fuller execution/persistence picture. Heavier; prefer a label/OS scope.",
    builtIn: true,
    artifacts: [
      "Windows.System.Pslist",
      "Windows.Network.Netstat",
      "Windows.System.Services",
      "Windows.Sys.StartupItems",
      "Windows.Forensics.Prefetch",
      "Windows.EventLogs.Evtx",
      "Windows.Forensics.Usn",
      "Windows.Registry.UserAssist",
      "Windows.Forensics.Lnk",
      "Windows.System.TaskScheduler",
      "Windows.Detection.Amcache",
    ],
    defaultWaitMinutes: 15,
  },
];

export class ArtifactBundleStore {
  constructor(private readonly root: string) {}

  private path(id: string): string {
    return join(this.root, `${id}.json`);
  }

  // True when an id belongs to a shipped built-in (vs. a purely custom bundle). Built-ins are
  // editable: an edit saves an override file under the same id; deleting it resets to the default.
  isBuiltIn(id: string): boolean {
    return BUILT_IN_BUNDLES.some((b) => b.id === id);
  }

  // Read one saved bundle file (an override for a built-in, or a custom bundle), or null.
  private async readSaved(id: string): Promise<ArtifactBundle | null> {
    try {
      return JSON.parse(await readFile(this.path(id), "utf8")) as ArtifactBundle;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  // All saved bundle files keyed by id (overrides + custom). Malformed files are skipped.
  private async loadSavedMap(): Promise<Map<string, ArtifactBundle>> {
    const map = new Map<string, ArtifactBundle>();
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
        const raw = JSON.parse(await readFile(join(this.root, entry), "utf8")) as ArtifactBundle;
        if (raw && typeof raw.id === "string" && raw.id) map.set(raw.id, raw);
      } catch {
        // skip malformed files
      }
    }
    return map;
  }

  // Built-ins first (a saved override replaces the shipped default, flagged `customized`), then
  // purely custom bundles.
  async list(): Promise<ArtifactBundle[]> {
    const saved = await this.loadSavedMap();
    const out: ArtifactBundle[] = [];
    for (const b of BUILT_IN_BUNDLES) {
      const override = saved.get(b.id);
      out.push(override ? { ...override, id: b.id, builtIn: true, customized: true } : { ...b, customized: false });
    }
    for (const [id, b] of saved) {
      if (this.isBuiltIn(id)) continue;   // already merged above as an override
      out.push({ ...b, builtIn: false, customized: false });
    }
    return out;
  }

  async get(id: string): Promise<ArtifactBundle | null> {
    const saved = await this.readSaved(id);
    if (this.isBuiltIn(id)) {
      const builtin = BUILT_IN_BUNDLES.find((b) => b.id === id)!;
      return saved ? { ...saved, id, builtIn: true, customized: true } : { ...builtin, customized: false };
    }
    return saved ? { ...saved, builtIn: false, customized: false } : null;
  }

  // Save a bundle. A built-in id writes an OVERRIDE (the built-in becomes editable in place);
  // any other id creates/updates a custom bundle. `customized`/`builtIn` are derived from the id,
  // not trusted from input.
  async save(input: Omit<ArtifactBundle, "id" | "builtIn" | "customized"> & { id?: string }): Promise<ArtifactBundle> {
    const id = input.id && String(input.id).trim() ? String(input.id).trim() : randomUUID();
    const builtIn = this.isBuiltIn(id);
    const bundle: ArtifactBundle = {
      id,
      name: String(input.name ?? "").trim(),
      description: String(input.description ?? "").trim(),
      builtIn,
      artifacts: Array.isArray(input.artifacts) ? input.artifacts.map(String).map((a) => a.trim()).filter(Boolean) : [],
      defaultWaitMinutes: typeof input.defaultWaitMinutes === "number" ? input.defaultWaitMinutes : undefined,
    };
    await mkdir(this.root, { recursive: true });
    await atomicWrite(this.path(id), JSON.stringify(bundle, null, 2));
    return { ...bundle, customized: builtIn };
  }

  // Remove the saved file: a custom bundle is deleted; a built-in's override is reset to the shipped
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
