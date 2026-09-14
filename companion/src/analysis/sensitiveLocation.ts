import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import { normaliseWinPath } from "./canonicalObjectAccess.js";

// A SENSITIVE LOCATION (#930 item 7): the analyst's declaration that a path on an endpoint (one
// host, or any host) holds sensitive material — an exact file, or a folder whose objects are. The
// declaration is classification: it says what matters, never what an object IS (a folder
// declaration does not make an object under it a file; the file rows do that). An evocative
// filename is never a rule.

export const SENSITIVE_LOCATIONS_MAX = 200;
const HOST_MAX = 200;
const PATH_MAX = 1024;
const NOTE_MAX = 2000;

export const sensitiveLocationSchema = z.object({
  id: z.string().min(1),
  /** "" = any host. */
  host: z.string().max(HOST_MAX),
  path: z.string().min(1).max(PATH_MAX),
  /** The comparison key of `path` (case-folded, separators unified). */
  key: z.string().min(1),
  kind: z.enum(["file", "folder"]),
  note: z.string().max(NOTE_MAX).optional(),
  declaredAt: z.string().min(1),
});
export type SensitiveLocation = z.infer<typeof sensitiveLocationSchema>;
const fileSchema = z.array(sensitiveLocationSchema);

export interface SensitiveLocationInput {
  host?: string;
  path: string;
  kind: "file" | "folder";
  note?: string;
}

const ABS = /^(?:[A-Za-z]:\\|\\\\[^\\]+\\)/;

/** Validate a declaration; every failure is named. */
export function validateSensitiveLocation(
  input: SensitiveLocationInput,
  now: string,
): { ok: true; location: SensitiveLocation } | { ok: false; error: string } {
  const host = String(input.host ?? "").trim();
  if (host.length > HOST_MAX) return { ok: false, error: `host is longer than ${HOST_MAX}` };
  const path = String(input.path ?? "")
    .trim()
    .replace(/\//g, "\\");
  if (!path) return { ok: false, error: "path is required" };
  if (path.length > PATH_MAX) return { ok: false, error: `path is longer than ${PATH_MAX}` };
  if (!ABS.test(path))
    return { ok: false, error: "path must be an absolute Windows path (C:\\… or \\\\server\\share\\…)" };
  const n = normaliseWinPath(path);
  if (!n || !("key" in n))
    return {
      ok: false,
      error: `path cannot be compared (${n && "unmappable" in n ? n.unmappable : "empty"})`,
    };
  const kind = input.kind === "file" || input.kind === "folder" ? input.kind : null;
  if (!kind) return { ok: false, error: "kind is 'file' or 'folder'" };
  const note = input.note === undefined ? undefined : String(input.note);
  if (note !== undefined && note.length > NOTE_MAX)
    return { ok: false, error: `note is longer than ${NOTE_MAX}` };
  return {
    ok: true,
    location: {
      id: `sn-${randomUUID().slice(0, 12)}`,
      host,
      path: path.replace(/\\+$/, "") || path,
      key: n.key,
      kind,
      ...(note ? { note } : {}),
      declaredAt: now,
    },
  };
}

const lock = new StateLock();

export class SensitiveLocationStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "sensitive-locations.json");
  }

  async load(caseId: string): Promise<SensitiveLocation[]> {
    try {
      return fileSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async declare(caseId: string, location: SensitiveLocation): Promise<SensitiveLocation | "full"> {
    return lock.runExclusive(caseId, async () => {
      const list = await this.load(caseId);
      if (list.length >= SENSITIVE_LOCATIONS_MAX) return "full";
      await atomicWrite(this.path(caseId), JSON.stringify([...list, location], null, 2));
      return location;
    });
  }

  async remove(caseId: string, id: string): Promise<boolean> {
    return lock.runExclusive(caseId, async () => {
      const list = await this.load(caseId);
      if (!list.some((l) => l.id === id)) return false;
      await atomicWrite(
        this.path(caseId),
        JSON.stringify(
          list.filter((l) => l.id !== id),
          null,
          2,
        ),
      );
      return true;
    });
  }
}
