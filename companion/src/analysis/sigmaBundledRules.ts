// Reads the Sigma rules shipped in companion/data/sigma (#2202) into a rule set. The only file in
// the Sigma engine that touches the disk; everything it reads is handed to sigmaRuleSet.ts as text.
//
// Located like the bundled ATT&CK matrix (attackMatrixData.ts): relative to this module in dev and
// tsc builds, next to the binary in the single-executable build. A missing or unreadable folder is
// not an error the import path can see — it yields an empty rule set and a `problem` sentence the
// server logs, so an install without the folder imports exactly as it did before #2202.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import {
  SIGMA_RULE_DIRS,
  buildSigmaRuleSet,
  type SigmaReleaseMeta,
  type SigmaRuleFile,
  type SigmaRuleSet,
  type SigmaRuleSetOptions,
} from "./sigmaRuleSet.js";

/** Most rule files read from one folder; a release has ~3,300 rules in all. */
export const SIGMA_MAX_RULE_FILES = 10_000;
/** Bigger files are refused unread; the parser's own cap is 64 KB. */
const MAX_FILE_BYTES = 128 * 1024;

export interface BundledSigmaLoad {
  set: SigmaRuleSet;
  dir?: string;
  problem?: string;
}

function candidateDirs(): string[] {
  const dirs: string[] = [];
  try {
    dirs.push(fileURLToPath(new URL("../../data/sigma", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers)
  }
  try {
    dirs.push(join(dirname(process.execPath), "data", "sigma"));
  } catch {
    // ignore
  }
  return dirs;
}

const isDir = (p: string): boolean => {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
};

/** Every rule file under the release folders, or `overflow` when there are more than the cap. */
export function ruleFiles(root: string): { files: SigmaRuleFile[]; overflow: boolean } {
  const files: SigmaRuleFile[] = [];
  let overflow = false;
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir).sort()) {
      if (overflow) return;
      const full = join(dir, name);
      const stat = statSync(full);
      if (stat.isDirectory()) walk(full);
      else if (/\.ya?ml$/i.test(name)) {
        if (files.length >= SIGMA_MAX_RULE_FILES) {
          overflow = true;
          return;
        }
        const path = relative(root, full).split(sep).join("/");
        files.push({ path, text: stat.size > MAX_FILE_BYTES ? "" : readFileSync(full, "utf8") });
      }
    }
  };
  for (const dir of SIGMA_RULE_DIRS) if (isDir(join(root, dir))) walk(join(root, dir));
  return { files, overflow };
}

export function readMeta(root: string): SigmaReleaseMeta {
  try {
    const raw = JSON.parse(readFileSync(join(root, "release.json"), "utf8")) as Record<string, unknown>;
    const release = typeof raw.release === "string" ? raw.release : "unknown";
    const commit =
      typeof raw.commit === "string" && /^[0-9a-f]{7,40}$/i.test(raw.commit) ? raw.commit : "master";
    return { release, commit };
  } catch {
    return { release: "unknown", commit: "master" };
  }
}

/** The shipped disabled list: rule id → reason. A malformed entry is skipped, never fatal. */
export function readDisabledList(text: string): Map<string, string> {
  const out = new Map<string, string>();
  const doc = parseYaml(text) as { rules?: unknown } | null;
  const rules = Array.isArray(doc?.rules) ? doc.rules : [];
  for (const r of rules as Record<string, unknown>[]) {
    if (typeof r?.id === "string" && r.id.trim())
      out.set(r.id.trim(), typeof r.reason === "string" ? r.reason : "disabled");
  }
  return out;
}

/** Load one Sigma folder (release.json, disabled.yml, rules/**). */
export function loadSigmaRuleDir(root: string, options: SigmaRuleSetOptions = {}): SigmaRuleSet {
  let disabled = new Map<string, string>();
  try {
    disabled = readDisabledList(readFileSync(join(root, "disabled.yml"), "utf8"));
  } catch {
    // no disabled list: every rule is eligible
  }
  const { files, overflow } = ruleFiles(root);
  const set = buildSigmaRuleSet(files, readMeta(root), {
    ...options,
    disabled: new Map([...disabled, ...(options.disabled ?? [])]),
  });
  return overflow
    ? {
        ...set,
        problems: [...set.problems, `more than ${SIGMA_MAX_RULE_FILES} rule files; the rest were not read`],
      }
    : set;
}

/** The folder the bundled rules ship in, or undefined when it is missing. */
export function bundledSigmaDir(): string | undefined {
  return candidateDirs().find((d) => isDir(join(d, "rules")));
}

/** The bundled rules, or an empty set with the reason when the folder is missing or unreadable. */
export function loadBundledSigmaRuleSet(options: SigmaRuleSetOptions = {}): BundledSigmaLoad {
  const dir = bundledSigmaDir();
  if (!dir) {
    return {
      set: buildSigmaRuleSet([], { release: "none", commit: "master" }, options),
      problem: "no bundled Sigma rules folder (data/sigma/rules) was found",
    };
  }
  try {
    return { set: loadSigmaRuleDir(dir, options), dir };
  } catch (error) {
    return {
      set: buildSigmaRuleSet([], { release: "none", commit: "master" }, options),
      dir,
      problem: `the bundled Sigma rules could not be read: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}
