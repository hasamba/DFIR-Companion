import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";

// A SERVED LOCATION (#930 item 4): the analyst's declaration that on web server H a URL prefix is
// served from a local root. A request path equals a local file only through such a declaration —
// virtual hosts, aliases and rewrites are server configuration the case does not hold, and
// nothing here guesses them. `public` is descriptive (a download area, a public backup): a
// resource under it is a negative control only when nothing declares it sensitive, and a
// sensitive resource under a public root is a surfaced conflict, never a suppressed one.
//
// Sensitivity is established only by the analyst (`sensitive`: relative paths confirmed) or by
// content identity (`sensitiveDigests`: sha256 of the sensitive document). An extension, a
// status, an unfamiliar client establish nothing.

export const LOCATIONS_PER_CASE_MAX = 50;
export const SENSITIVE_PER_LOCATION_MAX = 200;
export const INDEX_FILES_MAX = 10;
const HOST_MAX = 200;
const PATH_MAX = 1024;
const NOTE_MAX = 2000;
const VHOST_MAX = 253;
const INDEX_FILE_MAX = 255;

export const servedLocationSchema = z.object({
  id: z.string().min(1),
  host: z.string().min(1).max(HOST_MAX),
  vhost: z.string().max(253).optional(),
  /** "" is the root prefix (`/` normalised); otherwise `/segment[/…]` with no trailing slash. */
  urlPrefix: z.string().max(PATH_MAX),
  localRoot: z.string().min(1).max(PATH_MAX),
  /** Whole-segment comparison folds case; default on for a drive-letter root. */
  caseInsensitive: z.boolean(),
  /** A directory request maps only through these; none → directory requests are not mapped. */
  indexFiles: z.array(z.string().max(255)).max(INDEX_FILES_MAX),
  public: z.boolean(),
  /** Relative paths (below the root, `/`-separated) the analyst confirmed sensitive. */
  sensitive: z.array(z.string().max(PATH_MAX)).max(SENSITIVE_PER_LOCATION_MAX),
  sensitiveDigests: z.array(z.string().regex(/^[0-9a-f]{64}$/)).max(SENSITIVE_PER_LOCATION_MAX),
  note: z.string().max(NOTE_MAX).optional(),
  declaredAt: z.string().min(1),
});
export type ServedLocation = z.infer<typeof servedLocationSchema>;
const fileSchema = z.array(servedLocationSchema);

export interface ServedLocationInput {
  host: string;
  vhost?: string;
  urlPrefix: string;
  localRoot: string;
  caseInsensitive?: boolean;
  indexFiles?: string[];
  public?: boolean;
  sensitive?: string[];
  sensitiveDigests?: string[];
  note?: string;
}

const DRIVE_ROOT = /^[A-Za-z]:[\\/]/;
const ABS_ROOT = /^(?:[A-Za-z]:[\\/]|\/|\\\\[^\\]+\\)/;

/** A URL prefix as compared: leading `/`, no trailing `/` (the root prefix is ""), no query. */
export function normalisePrefix(raw: string): string | null {
  const p = raw.trim();
  if (!p.startsWith("/") || p.includes("?") || p.includes("#")) return null;
  const collapsed = p.replace(/\/{2,}/g, "/").replace(/\/+$/, "");
  return collapsed;
}

/** Validate a declaration; every failure is named. */
export function validateServedLocation(
  input: ServedLocationInput,
  now: string,
): { ok: true; location: ServedLocation } | { ok: false; error: string } {
  const host = String(input.host ?? "").trim();
  if (!host) return { ok: false, error: "host is required" };
  if (host.length > HOST_MAX) return { ok: false, error: `host is longer than ${HOST_MAX}` };
  const urlPrefix = normalisePrefix(String(input.urlPrefix ?? ""));
  if (urlPrefix === null) return { ok: false, error: "urlPrefix must start with '/' and carry no query" };
  if (urlPrefix.length > PATH_MAX) return { ok: false, error: `urlPrefix is longer than ${PATH_MAX}` };
  const localRoot = String(input.localRoot ?? "")
    .trim()
    .replace(/[\\/]+$/, "");
  if (!ABS_ROOT.test(localRoot + "/")) return { ok: false, error: "localRoot must be an absolute path" };
  if (localRoot.length > PATH_MAX) return { ok: false, error: `localRoot is longer than ${PATH_MAX}` };
  const vhost = input.vhost ? String(input.vhost).trim().toLowerCase() : "";
  if (vhost.length > VHOST_MAX) return { ok: false, error: `vhost is longer than ${VHOST_MAX}` };
  if (input.caseInsensitive !== undefined && typeof input.caseInsensitive !== "boolean")
    return { ok: false, error: "caseInsensitive must be a boolean" };
  const indexFiles = (input.indexFiles ?? []).map((f) => String(f).trim()).filter(Boolean);
  if (indexFiles.length > INDEX_FILES_MAX)
    return { ok: false, error: `at most ${INDEX_FILES_MAX} index files` };
  if (indexFiles.some((f) => /[\\/]/.test(f)))
    return { ok: false, error: "an index file is a bare filename" };
  if (indexFiles.some((f) => f.length > INDEX_FILE_MAX))
    return { ok: false, error: `an index file name is longer than ${INDEX_FILE_MAX}` };
  const sensitive = [
    ...new Set(
      (input.sensitive ?? [])
        .map((p) =>
          String(p)
            .trim()
            .replace(/^[\\/]+/, "")
            .replace(/\\/g, "/"),
        )
        .filter(Boolean),
    ),
  ];
  if (sensitive.length > SENSITIVE_PER_LOCATION_MAX)
    return { ok: false, error: `at most ${SENSITIVE_PER_LOCATION_MAX} sensitive paths` };
  if (sensitive.some((p) => p.length > PATH_MAX))
    return { ok: false, error: `a sensitive path is longer than ${PATH_MAX}` };
  const sensitiveDigests = [
    ...new Set((input.sensitiveDigests ?? []).map((d) => String(d).trim().toLowerCase())),
  ];
  if (sensitiveDigests.some((d) => !/^[0-9a-f]{64}$/.test(d)))
    return { ok: false, error: "a sensitive digest is a sha256 hex string" };
  if (sensitiveDigests.length > SENSITIVE_PER_LOCATION_MAX)
    return { ok: false, error: `at most ${SENSITIVE_PER_LOCATION_MAX} sensitive digests` };
  const note = input.note === undefined ? undefined : String(input.note);
  if (note !== undefined && note.length > NOTE_MAX)
    return { ok: false, error: `note is longer than ${NOTE_MAX}` };
  return {
    ok: true,
    location: {
      id: `sl-${randomUUID().slice(0, 12)}`,
      host,
      ...(vhost ? { vhost } : {}),
      urlPrefix,
      localRoot,
      caseInsensitive:
        typeof input.caseInsensitive === "boolean" ? input.caseInsensitive : DRIVE_ROOT.test(localRoot + "/"),
      indexFiles,
      public: input.public === true,
      sensitive,
      sensitiveDigests,
      ...(note ? { note } : {}),
      declaredAt: now,
    },
  };
}

const lock = new StateLock();

export class ServedLocationStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "served-locations.json");
  }

  async load(caseId: string): Promise<ServedLocation[]> {
    try {
      return fileSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async declare(caseId: string, location: ServedLocation): Promise<ServedLocation | "full"> {
    return lock.runExclusive(caseId, async () => {
      const list = await this.load(caseId);
      if (list.length >= LOCATIONS_PER_CASE_MAX) return "full";
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
