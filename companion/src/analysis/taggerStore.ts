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

import { readFile, access, rm, mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import { compileRuleset, type CompiledRuleset } from "./taggerRules.js";

// Thrown when a whole-document save carries a revision that no longer matches the file on disk —
// somebody else changed the rules while this editor was open. A distinct type so the route can
// answer 409 (you are out of date, reload) instead of 400 (your YAML is wrong), which are very
// different instructions to give an analyst.
export class TaggerRulesConflictError extends Error {
  constructor(readonly currentRevision: string) {
    super("the rules changed since this editor was opened; reload before saving");
    this.name = "TaggerRulesConflictError";
  }
}

// A revision is just a digest of the active rule text. It needs to change whenever the file does and
// be cheap to compare — not to be unguessable — so a truncated sha256 is enough.
export function rulesRevision(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

export type RulesSource = "env" | "user" | "default";

export interface ActiveRules {
  text: string;
  source: RulesSource;
  path: string;
  /** Digest of `text`. The editor sends it back on save so a stale submission can be rejected. */
  revision: string;
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
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/** Append `_2`, `_3`, … to `base` until it is not in `taken`. */
function uniqueKey(base: string, taken: ReadonlySet<string>): string {
  if (!taken.has(base)) return base;
  for (let i = 2; ; i++) {
    const candidate = `${base}_${i}`;
    if (!taken.has(candidate)) return candidate;
  }
}

// Keyed by the rules file path rather than a case id: this store is GLOBAL, and the path is what is
// actually being contended for.
const rulesLock = new StateLock();

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
      try {
        readFileSync(p);
        return p;
      } catch {
        /* next candidate */
      }
    }
    return undefined;
  }

  /** The active rule file's raw YAML text + where it came from. Empty ruleset when none is found. */
  async readActive(): Promise<ActiveRules> {
    const active = await this.readActiveText();
    return { ...active, revision: rulesRevision(active.text) };
  }

  private async readActiveText(): Promise<Omit<ActiveRules, "revision">> {
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
  // A whole-document save REPLACES the file, so on its own it is last-write-wins: an editor
  // submission that lands after somebody else added a rule silently deletes that rule. The lock
  // alone could never fix that — it makes the two writes atomic with respect to each other, which is
  // a different problem. `expectedRevision` is what fixes it: the editor sends back the revision it
  // loaded, and a mismatch is refused rather than applied.
  //
  // The comparison happens INSIDE the lock, which is the whole point. Checking outside would leave
  // exactly the race it is meant to close — read the current revision, another writer lands, then
  // overwrite anyway.
  //
  // Omitting `expectedRevision` keeps the old last-write-wins behaviour. That is deliberate: a
  // script or curl caller with the full ruleset in hand is stating intent, and the dashboard editor
  // (the client that can actually be stale) always sends one.
  async save(yamlText: string, expectedRevision?: string): Promise<CompiledRuleset & { revision: string }> {
    return rulesLock.runExclusive(this.userRulesPath, async () => {
      if (expectedRevision !== undefined) {
        const current = rulesRevision((await this.readActiveText()).text);
        if (current !== expectedRevision) throw new TaggerRulesConflictError(current);
      }
      const compiled = await this.persist(yamlText);
      return { ...compiled, revision: rulesRevision(yamlText) };
    });
  }

  // The unlocked body of save(). StateLock is NOT reentrant — a runExclusive nested inside another
  // on the same key waits on a tail that is waiting on it — so the structural edits below, which
  // already hold the lock, must persist through here rather than calling save().
  private async persist(yamlText: string): Promise<CompiledRuleset> {
    const compiled = compileText(yamlText); // throws on invalid — nothing is written
    await mkdir(dirname(this.userRulesPath), { recursive: true }); // atomicWrite won't create parents
    await atomicWrite(this.userRulesPath, yamlText);
    return compiled;
  }

  /** True when an operator env override (TAGGER_RULES_FILE) owns the ruleset (read-only from our side). */
  isEnvOverride(): boolean {
    return this.envPath() !== undefined;
  }

  /** Parse the active ruleset into its raw id → rule map (for structural edits). Empty → {}. */
  private async loadRawMap(): Promise<Record<string, unknown>> {
    const active = await this.readActive();
    if (!active.text.trim()) return {};
    const doc = parseYaml(active.text);
    return doc && typeof doc === "object" && !Array.isArray(doc) ? (doc as Record<string, unknown>) : {};
  }

  private assertEditable(): void {
    if (this.isEnvOverride()) {
      throw new Error("rules are managed by an operator override (TAGGER_RULES_FILE); editing is disabled");
    }
  }

  // Every write to the rules file — the three structural edits below AND the whole-document save()
  // the rules editor PUTs — runs under one lock (follow-up to #682).
  //
  // This was deliberately unlocked, on the reasoning that a single-analyst local tool did not need
  // it. Team mode is what changed that: the rules file is GLOBAL, shared by everyone on the
  // deployment, so two analysts editing rules is now ordinary rather than impossible. The cost of
  // losing one is also worse here than a lost row. A rule that silently never landed does not
  // announce itself, and the tagger only grades evidence AT IMPORT — so nothing re-runs over what
  // is already in the case, and the gap looks like "that rule does not match" rather than "that
  // rule was never saved".

  /**
   * Merge one rule (a single-entry YAML map of id → rule) into the active ruleset. Validates the new
   * rule compiles, de-collides its id against existing ids, and persists via the validated save()
   * path. Returns the (possibly de-collided) id and the new total rule count.
   */
  async addRuleYaml(singleEntryText: string): Promise<{ id: string; ruleCount: number }> {
    this.assertEditable();
    const doc = parseYaml(singleEntryText);
    if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
      throw new Error("expected a single rule (a YAML map of id → rule)");
    }
    const entries = Object.entries(doc as Record<string, unknown>);
    if (entries.length !== 1) throw new Error(`expected exactly one rule, got ${entries.length}`);
    const [rawId, rule] = entries[0];
    compileRuleset({ [rawId]: rule }); // throws on an invalid rule BEFORE we touch the file
    return rulesLock.runExclusive(this.userRulesPath, async () => {
      const map = await this.loadRawMap();
      const id = uniqueKey(rawId, new Set(Object.keys(map)));
      const compiled = await this.persist(stringifyYaml({ ...map, [id]: rule }));
      return { id, ruleCount: compiled.rules.length };
    });
  }

  /** Remove one rule by id. Returns removed=false (and the unchanged count) when the id is absent. */
  async removeRule(id: string): Promise<{ removed: boolean; ruleCount: number }> {
    this.assertEditable();
    return rulesLock.runExclusive(this.userRulesPath, async () => {
      const map = await this.loadRawMap();
      if (!Object.hasOwn(map, id)) {
        const current = await this.load();
        return { removed: false, ruleCount: current.rules.length };
      }
      const { [id]: _removed, ...next } = map;
      // An empty map serializes to "{}"; persist "" instead so the store reads back an empty ruleset.
      const text = Object.keys(next).length ? stringifyYaml(next) : "";
      const compiled = await this.persist(text);
      return { removed: true, ruleCount: compiled.rules.length };
    });
  }

  /** Delete the user rule file so the active ruleset falls back to the bundled default. No-op if absent. */
  async resetToDefault(): Promise<{ ruleCount: number }> {
    this.assertEditable();
    return rulesLock.runExclusive(this.userRulesPath, async () => {
      await rm(this.userRulesPath, { force: true });
      const compiled = await this.load();
      return { ruleCount: compiled.rules.length };
    });
  }
}

/** Parse YAML text and compile it into a ruleset. Empty/whitespace text → an empty ruleset. */
export function compileText(text: string): CompiledRuleset {
  if (!text.trim()) return { rules: [] };
  const doc = parseYaml(text);
  if (doc === null || doc === undefined) return { rules: [] };
  return compileRuleset(doc);
}
