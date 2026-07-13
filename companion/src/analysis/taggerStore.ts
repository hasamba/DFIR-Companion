// I/O for the content-based event tagger: resolve, read, validate, and persist the rule file. The
// PURE rule logic lives in taggerRules.ts (compile/match) and tagger.ts (run) — this module only
// touches the filesystem.
//
// Active-ruleset precedence, most-specific first:
//   1. TAGGER_RULES_FILE env  — an explicit operator override (read-only from our side).
//   2. the user-edited file    — written by PUT /tagger/rules (dashboard rule editor).
//   3. the bundled default     — companion/data/tags.yaml, shipped with the app.
// Invalid YAML / an invalid ruleset THROWS (never a partial load): the manual-run route surfaces the
// error; the auto-run pipeline hook catches it and skips (a broken hand-edit must not break imports).

import { readFile, access } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { atomicWrite } from "../storage/atomicWrite.js";
import { compileRuleset, type CompiledRuleset } from "./taggerRules.js";

export type RulesSource = "env" | "user" | "default";

export interface ActiveRules {
  text: string;
  source: RulesSource;
  path: string;
}

// Candidate locations of the bundled default, most-likely first (mirrors countryCentroids.ts):
// dev/tsc resolve relative to this module; the SEA EXE ships data/ next to the binary.
function defaultCandidatePaths(): string[] {
  const paths: string[] = [];
  try {
    paths.push(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers) — fall through to the execPath candidate.
  }
  try {
    paths.push(join(dirname(process.execPath), "data", "tags.yaml"));
  } catch {
    // ignore
  }
  return paths;
}

async function exists(path: string): Promise<boolean> {
  try { await access(path); return true; } catch { return false; }
}

export class TaggerStore {
  /**
   * @param userRulesPath  writable path for dashboard-edited rules (e.g. `<dataRoot>/tagger-rules.yaml`)
   * @param defaultPaths   bundled-default candidates; defaults to the shipped data/tags.yaml locations
   *                       (injectable for tests)
   */
  constructor(
    private readonly userRulesPath: string,
    private readonly defaultPaths: string[] = defaultCandidatePaths(),
  ) {}

  private envPath(): string | undefined {
    const p = process.env.TAGGER_RULES_FILE?.trim();
    return p ? p : undefined;
  }

  private resolveDefaultPath(): string | undefined {
    for (const p of this.defaultPaths) {
      try { readFileSync(p); return p; } catch { /* next candidate */ }
    }
    return undefined;
  }

  /** The active rule file's raw YAML text + where it came from. Empty ruleset when none is found. */
  async readActive(): Promise<ActiveRules> {
    const env = this.envPath();
    if (env) return { text: await readFile(env, "utf8"), source: "env", path: env };
    if (await exists(this.userRulesPath)) {
      return { text: await readFile(this.userRulesPath, "utf8"), source: "user", path: this.userRulesPath };
    }
    const def = this.resolveDefaultPath();
    if (def) return { text: await readFile(def, "utf8"), source: "default", path: def };
    return { text: "", source: "default", path: this.userRulesPath };
  }

  /** Load + compile the active ruleset. Throws (YAML/validation error) rather than partially load. */
  async load(): Promise<CompiledRuleset & { source: RulesSource }> {
    const active = await this.readActive();
    const compiled = compileText(active.text);
    return { ...compiled, source: active.source };
  }

  /**
   * Validate + persist new rule YAML to the user file (via atomicWrite — the codebase's
   * "never a bare writeFile" invariant). Throws BEFORE writing if the YAML or ruleset is invalid,
   * so a bad edit never overwrites a working file. Returns the compiled ruleset.
   */
  async save(yamlText: string): Promise<CompiledRuleset> {
    const compiled = compileText(yamlText); // throws on invalid — nothing is written
    await atomicWrite(this.userRulesPath, yamlText);
    return compiled;
  }
}

/** Parse YAML text and compile it into a ruleset. Empty/whitespace text → an empty ruleset. */
export function compileText(text: string): CompiledRuleset {
  if (!text.trim()) return { rules: [] };
  const doc = parseYaml(text);
  if (doc === null || doc === undefined) return { rules: [] };
  return compileRuleset(doc);
}
