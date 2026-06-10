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

  // Built-ins first, then user-saved custom bundles.
  async list(): Promise<ArtifactBundle[]> {
    return [...BUILT_IN_BUNDLES, ...(await this.listCustom())];
  }

  private async listCustom(): Promise<ArtifactBundle[]> {
    let entries: string[];
    try {
      entries = await readdir(this.root);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const bundles: ArtifactBundle[] = [];
    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      try {
        const raw = JSON.parse(await readFile(join(this.root, entry), "utf8")) as ArtifactBundle;
        if (!raw.builtIn) bundles.push(raw);
      } catch {
        // skip malformed files
      }
    }
    return bundles;
  }

  async get(id: string): Promise<ArtifactBundle | null> {
    const builtin = BUILT_IN_BUNDLES.find((b) => b.id === id);
    if (builtin) return builtin;
    try {
      return JSON.parse(await readFile(this.path(id), "utf8")) as ArtifactBundle;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  async save(input: Omit<ArtifactBundle, "id" | "builtIn"> & { id?: string }): Promise<ArtifactBundle> {
    const bundle: ArtifactBundle = {
      id: input.id && String(input.id).trim() ? String(input.id).trim() : randomUUID(),
      name: String(input.name ?? "").trim(),
      description: String(input.description ?? "").trim(),
      builtIn: false,
      artifacts: Array.isArray(input.artifacts) ? input.artifacts.map(String).map((a) => a.trim()).filter(Boolean) : [],
      defaultWaitMinutes: typeof input.defaultWaitMinutes === "number" ? input.defaultWaitMinutes : undefined,
    };
    // Don't let a saved file shadow a built-in id (the built-in always wins in get()/list()).
    if (BUILT_IN_BUNDLES.some((b) => b.id === bundle.id)) {
      throw new Error(`cannot overwrite built-in bundle "${bundle.id}" — duplicate it under a new name instead`);
    }
    await mkdir(this.root, { recursive: true });
    await atomicWrite(this.path(bundle.id), JSON.stringify(bundle, null, 2));
    return bundle;
  }

  async delete(id: string): Promise<boolean> {
    if (BUILT_IN_BUNDLES.some((b) => b.id === id)) {
      throw new Error(`cannot delete built-in bundle "${id}"`);
    }
    try {
      await unlink(this.path(id));
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw err;
    }
  }
}
