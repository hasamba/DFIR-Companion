// Reading a SigmaHQ release zip for the Sigma rule updater (#2204). Pure: bytes in, rule texts out.
//
// A release zip is downloaded from GitHub or handed over by the analyst, so it is untrusted input.
// Everything is bounded BEFORE it is trusted (Codex plan review): the archive size, the number of
// entries, every entry's inflated size (zipArchive.readZip, which now caps stored entries too), and
// every path — absolute, `..`, backslash or drive paths are refused, as are two entries that
// differ only in case and a name that is both a file and a folder. Only rule YAML under the three
// release folders and the release's version.txt are kept.

import { parse as parseYaml } from "yaml";
import { readZip } from "./zipArchive.js";
import { SIGMA_LOG_SOURCES, type SigmaLogSourceDef } from "./sigmaLogSources.js";
import { SIGMA_RULE_DIRS, type SigmaRuleFile } from "./sigmaRuleSet.js";
import type { SigmaLogsource } from "./sigmaRuleTypes.js";
import { createHash } from "node:crypto";

/** A full SigmaHQ release is ~3 MB; anything near this is not a rule release. */
export const SIGMA_RELEASE_MAX_ZIP_BYTES = 32 * 1024 * 1024;
export const SIGMA_RELEASE_MAX_ENTRIES = 10_000;
const MAX_ENTRY_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES = 96 * 1024 * 1024;

export interface SigmaReleaseContents {
  files: SigmaRuleFile[];
  /** `Label:` of version.txt — SigmaHQ's own build label, not necessarily the release tag. */
  versionLabel?: string;
  /** `Commit-Hash:` of version.txt, when it is a git hash. */
  commit?: string;
}

/** The central directory's entry count, read before anything is inflated. */
function entryCount(buf: Buffer): number {
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) return buf.readUInt16LE(i + 10);
  }
  throw new Error("the file is not a readable zip archive");
}

function safePath(path: string): boolean {
  if (!path || path.startsWith("/") || path.includes("\\") || /^[a-zA-Z]:/.test(path) || path.includes(":"))
    return false;
  return path.split("/").every((seg) => seg !== "" && seg !== "." && seg !== "..");
}

/** A single folder wrapping the whole archive (`sigma/rules/…`) is stripped. */
function wrapperPrefix(paths: readonly string[]): string {
  if (paths.some((p) => p.split("/")[0] === "rules")) return "";
  const tops = new Set(paths.map((p) => p.split("/")[0]));
  if (tops.size !== 1) return "";
  const top = [...tops][0];
  return paths.some((p) => p.startsWith(`${top}/rules/`)) ? `${top}/` : "";
}

function checkCollisions(paths: readonly string[]): void {
  const seen = new Map<string, string>();
  for (const p of paths) {
    const key = p.toLowerCase();
    const first = seen.get(key);
    if (first !== undefined) throw new Error(`the archive holds ${first} twice (paths differ only in case)`);
    seen.set(key, p);
  }
  for (const p of paths) {
    const parts = p.toLowerCase().split("/");
    for (let i = 1; i < parts.length; i++) {
      const dir = parts.slice(0, i).join("/");
      if (seen.has(dir)) throw new Error(`the archive uses ${seen.get(dir)} as both a file and a folder`);
    }
  }
}

/** Read a release zip into rule files. Throws an analyst-readable Error on anything it refuses. */
export function readSigmaReleaseZip(buf: Buffer): SigmaReleaseContents {
  if (buf.length > SIGMA_RELEASE_MAX_ZIP_BYTES)
    throw new Error(
      `the archive is larger than ${SIGMA_RELEASE_MAX_ZIP_BYTES / (1024 * 1024)} MB; a SigmaHQ release is a few MB`,
    );
  if (buf.length < 22 || entryCount(buf) > SIGMA_RELEASE_MAX_ENTRIES)
    throw new Error(
      `the archive holds more than ${SIGMA_RELEASE_MAX_ENTRIES} entries, or is not a readable zip archive`,
    );
  let entries: ReturnType<typeof readZip>;
  try {
    entries = readZip(buf, { maxEntryBytes: MAX_ENTRY_BYTES, maxTotalBytes: MAX_TOTAL_BYTES });
  } catch (error) {
    throw new Error(
      `the file is not a readable zip archive (${error instanceof Error ? error.message : String(error)})`,
    );
  }
  const files = entries.filter((e) => !e.path.endsWith("/"));
  for (const e of files)
    if (!safePath(e.path)) throw new Error(`the archive holds an unsafe path: ${e.path}`);
  checkCollisions(files.map((e) => e.path));
  const prefix = wrapperPrefix(files.map((e) => e.path));
  const inRelease = files
    .filter((e) => e.path.startsWith(prefix))
    .map((e) => ({ path: e.path.slice(prefix.length), data: e.data }));
  const rules = inRelease
    .filter((e) => /\.ya?ml$/i.test(e.path) && SIGMA_RULE_DIRS.some((d) => e.path.startsWith(`${d}/`)))
    .map((e) => ({ path: e.path, text: e.data.toString("utf8") }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  if (!rules.some((r) => r.path.startsWith("rules/")))
    throw new Error("the archive has no rules/ folder of Sigma rules; it is not a SigmaHQ release");
  const version = inRelease.find((e) => e.path === "version.txt")?.data.toString("utf8") ?? "";
  const label = /^Label:\s*(\S+)/m.exec(version)?.[1];
  const commit = /^Commit-Hash:\s*([0-9a-f]{7,40})\s*$/im.exec(version)?.[1];
  return { files: rules, ...(label ? { versionLabel: label } : {}), ...(commit ? { commit } : {}) };
}

// ── Diff ──────────────────────────────────────────────────────────────────────────────────────

export interface SigmaRuleBrief {
  id: string;
  title: string;
  path: string;
}

export interface SigmaReleaseDiff {
  added: SigmaRuleBrief[];
  changed: SigmaRuleBrief[];
  removed: SigmaRuleBrief[];
  /** Rules in the new release for log sources the engine does not grade — not compared. */
  otherSources: number;
}

interface Brief extends SigmaRuleBrief {
  hash: string;
  graded: boolean;
}

function brief(file: SigmaRuleFile, sources: readonly SigmaLogSourceDef[]): Brief | null {
  let doc: Record<string, unknown> | null;
  try {
    doc = parseYaml(file.text, { maxAliasCount: 0 }) as Record<string, unknown> | null;
  } catch {
    return null;
  }
  if (!doc || typeof doc !== "object") return null;
  const ls = (doc.logsource ?? {}) as Record<string, unknown>;
  const logsource: SigmaLogsource = {
    ...(typeof ls.category === "string" ? { category: ls.category } : {}),
    ...(typeof ls.product === "string" ? { product: ls.product } : {}),
    ...(typeof ls.service === "string" ? { service: ls.service } : {}),
  };
  return {
    id: typeof doc.id === "string" ? doc.id : file.path,
    title: typeof doc.title === "string" ? doc.title : file.path,
    path: file.path,
    hash: createHash("sha256").update(file.text).digest("hex"),
    graded: sources.some((s) => s.matches(logsource)),
  };
}

const byId = (list: readonly (Brief | null)[]): Map<string, Brief> => {
  const out = new Map<string, Brief>();
  for (const b of list) if (b && b.graded && !out.has(b.id)) out.set(b.id, b);
  return out;
};

const strip = ({ id, title, path }: Brief): SigmaRuleBrief => ({ id, title, path });

/** What installing `after` would change for the graded log sources, compared with `before`. */
export function diffSigmaReleases(
  before: readonly SigmaRuleFile[],
  after: readonly SigmaRuleFile[],
  sources: readonly SigmaLogSourceDef[] = SIGMA_LOG_SOURCES,
): SigmaReleaseDiff {
  const afterBriefs = after.map((f) => brief(f, sources));
  const old = byId(before.map((f) => brief(f, sources)));
  const neu = byId(afterBriefs);
  return {
    added: [...neu.values()].filter((b) => !old.has(b.id)).map(strip),
    changed: [...neu.values()].filter((b) => old.has(b.id) && old.get(b.id)?.hash !== b.hash).map(strip),
    removed: [...old.values()].filter((b) => !neu.has(b.id)).map(strip),
    otherSources: afterBriefs.filter((b) => b && !b.graded).length,
  };
}
