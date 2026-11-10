// The Suzaku project's own Sigma rules — AWS CloudTrail (#2499), Microsoft 365 and Azure Activity
// (#2500) — bundled verbatim in data/sigma-suzaku
// beside the SigmaHQ release (data/sigma). They join the SigmaHQ rules in ONE rule set — so the
// inventory, the disabled list, exclusions, re-grade lookups and the provenance token cover both —
// but carry their own origin: their own status filter (DFIR_SIGMA_SUZAKU_STATUSES), their own
// switch (DFIR_SIGMA_SUZAKU_RULES), and their own name and link on every match (DRL 1.1).
//
// Bundled only: installing, previewing or rolling back a SigmaHQ release never touches them.
// A missing or unreadable folder is a problem sentence, never an error an import can see, and never
// stops the SigmaHQ rules from loading.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  sigmaSuzakuEnabled,
  sigmaSuzakuMinLevelFromEnv,
  sigmaSuzakuStatusesFromEnv,
} from "./sigmaSettings.js";
import type { SigmaRuleFile, SigmaRuleOrigin } from "./sigmaRuleSet.js";

/** The origin key on every Suzaku file, and the name shown on its matches. */
export const SUZAKU_ORIGIN_KEY = "suzaku";
export const SUZAKU_NAME = "Suzaku";
export const SUZAKU_URL_BASE = "https://github.com/Yamato-Security/suzaku-rules/blob";
/** Rule paths are the upstream repo's own (suzaku/aws/cloudtrail/x.yml, suzaku/m365/x.yml), so the link is exact. */
export const SUZAKU_PATH_PREFIX = "suzaku/";
const MAX_FILE_BYTES = 128 * 1024;

export interface SuzakuLoad {
  files: SigmaRuleFile[];
  /** Present when files were read; absent when switched off or missing. */
  origin?: SigmaRuleOrigin;
  problems: string[];
}

const isDir = (p: string): boolean => {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
};

/** The folder the Suzaku rules ship in, or undefined when it is missing. */
export function bundledSuzakuDir(): string | undefined {
  const dirs: string[] = [];
  try {
    dirs.push(fileURLToPath(new URL("../../data/sigma-suzaku", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers)
  }
  try {
    dirs.push(join(dirname(process.execPath), "data", "sigma-suzaku"));
  } catch {
    // ignore
  }
  return dirs.find((d) => isDir(join(d, "rules")));
}

/** release.json's release label and commit; "unknown" / "main" when unreadable. */
export function readSuzakuMeta(dir: string): { release: string; commit: string } {
  try {
    const raw = JSON.parse(readFileSync(join(dir, "release.json"), "utf8")) as Record<string, unknown>;
    const release = typeof raw.release === "string" ? raw.release : "unknown";
    const commit =
      typeof raw.commit === "string" && /^[0-9a-f]{7,40}$/i.test(raw.commit) ? raw.commit : "main";
    return { release, commit };
  } catch {
    return { release: "unknown", commit: "main" };
  }
}

/** Every rule file under `<dir>/rules`, paths prefixed `suzaku/`, at most `cap` of them. */
export function suzakuRuleFiles(dir: string, cap: number): { files: SigmaRuleFile[]; overflow: boolean } {
  const root = join(dir, "rules");
  const files: SigmaRuleFile[] = [];
  let overflow = false;
  const walk = (d: string): void => {
    for (const name of readdirSync(d).sort()) {
      if (overflow) return;
      const full = join(d, name);
      const stat = statSync(full);
      if (stat.isDirectory()) walk(full);
      else if (/\.ya?ml$/i.test(name)) {
        if (files.length >= cap) {
          overflow = true;
          return;
        }
        const path = SUZAKU_PATH_PREFIX + relative(root, full).split(sep).join("/");
        const text = stat.size > MAX_FILE_BYTES ? "" : readFileSync(full, "utf8");
        files.push({ path, text, origin: SUZAKU_ORIGIN_KEY });
      }
    }
  };
  walk(root);
  return { files, overflow };
}

/** The Suzaku origin for a folder's metadata and the current status setting. */
export function suzakuOrigin(
  meta: { release: string; commit: string },
  env: NodeJS.ProcessEnv = process.env,
): SigmaRuleOrigin {
  return {
    name: SUZAKU_NAME,
    release: meta.release,
    commit: meta.commit,
    urlBase: SUZAKU_URL_BASE,
    statuses: sigmaSuzakuStatusesFromEnv(env).statuses,
    minLevel: sigmaSuzakuMinLevelFromEnv(env).level,
  };
}

/**
 * The Suzaku files and origin to add to a rule set, honouring DFIR_SIGMA_SUZAKU_RULES. `cap` is what
 * is left of the shared file cap once the SigmaHQ files are counted.
 */
export function loadSuzakuRules(
  dir: string | undefined,
  cap: number,
  env: NodeJS.ProcessEnv = process.env,
): SuzakuLoad {
  if (!sigmaSuzakuEnabled(env)) return { files: [], problems: [] };
  if (!dir)
    return { files: [], problems: ["no bundled Suzaku rules folder (data/sigma-suzaku/rules) was found"] };
  try {
    const { files, overflow } = suzakuRuleFiles(dir, Math.max(0, cap));
    return {
      files,
      origin: suzakuOrigin(readSuzakuMeta(dir), env),
      problems: overflow ? ["too many rule files; some Suzaku rules were not read"] : [],
    };
  } catch (error) {
    return {
      files: [],
      problems: [
        `the bundled Suzaku rules could not be read: ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }
}

/** The origins map a rule set needs for a Suzaku load (empty when nothing was read). */
export const suzakuOrigins = (load: SuzakuLoad): Map<string, SigmaRuleOrigin> =>
  load.origin ? new Map([[SUZAKU_ORIGIN_KEY, load.origin]]) : new Map();

/** The Suzaku rules a rule set should load right now — files, problems and cache identity together (#2508). */
export interface SuzakuActive {
  /** Changes whenever the effective folder changes (install, roll back, fallback). */
  key: string;
  dir: string | undefined;
  problems: string[];
}

/** What SigmaRuleStore needs from a Suzaku rule source: the bundled folder, or the installed one. */
export interface SuzakuSource {
  activeSource(): SuzakuActive;
}

/** A source that is always the bundled folder; `null` = looked for and missing (#2499). */
export const bundledSuzakuSource = (dir: string | null): SuzakuSource => ({
  activeSource: () => ({ key: "bundled", dir: dir ?? undefined, problems: [] }),
});
