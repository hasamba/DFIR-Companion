// I/O for the content-based event tagger: resolve, read, validate, and persist the rule file. The
// PURE rule logic lives in taggerRules.ts (compile/match) and tagger.ts (run) — this module only
// touches the filesystem.
//
// Active-ruleset precedence, most-specific first:
//   1. TAGGER_RULES_FILE env  — an explicit operator override (read-only from our side).
//   2. the user-edited file    — written by PUT /tagger/rules (dashboard rule editor).
//   3. the installed rule pack — a `rules-*` release installed from Content tagger → Rule pack
//                                (#2349, rulePackStore.ts), while it is not superseded by the app.
//   4. the bundled default     — companion/data/tags.yaml, shipped with the app.
//
// The UPSTREAM of an edited copy (#2344) is the newest non-user source: the installed pack when one
// is in use, else the bundled default. So a pack installed under an edited copy is offered through
// the same merge review, and the analyst's edits are kept. The copy's base record is read under the
// pack's id, falling back to the built-in one — a copy made from the bundled rules and never merged
// with a pack still has an exact base (the pack is the same rule lineage, only newer).
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
import {
  applyRuleUpdates,
  diffRuleSets,
  ruleSetRevision,
  snapshotBase,
  type RuleBase,
  type RuleChoice,
  type RuleMap,
  type RuleUpdateReport,
} from "./taggerRulesMerge.js";
import {
  BUILTIN_UPSTREAM,
  readDismissedRevision,
  readRuleBase,
  removeRuleBase,
  writeDismissedRevision,
  writeRuleBase,
} from "./taggerRulesBase.js";

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
// Thrown when a merge's upstream — the bundled set or the installed rule pack — is no longer the one
// the analyst reviewed (#2344/#2349): a pack was installed or rolled back, or the app was upgraded,
// after the review opened. The copy may be untouched, so TaggerRulesConflictError's check alone
// would let a reviewed "accept" write a rule definition nobody saw. Answered 409 like that error.
export class TaggerUpstreamChangedError extends Error {
  constructor(
    readonly currentUpstreamId: string | null,
    readonly currentUpstreamRevision: string | null,
  ) {
    super("the rules your copy is compared with changed since this review was opened; reload the review");
    this.name = "TaggerUpstreamChangedError";
  }
}

/** What a merge was reviewed against: the copy's revision and the upstream's id and content revision. */
export interface ReviewedRevisions {
  revision: string;
  upstreamId: string;
  upstreamRevision: string;
}

export function rulesRevision(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

export type RulesSource = "env" | "user" | "pack" | "default";

/** The installed rule pack, as the store sees it (#2349). Injected, so this file knows no downloads. */
export interface PackRulesProvider {
  /** The pack's rules while one is installed and in use; null otherwise. */
  activeRules(): Promise<{ text: string; path: string; id: string; label: string } | null>;
}

interface Upstream {
  id: string;
  label: string;
  map: Record<string, unknown>;
}

/** The active copy compared with the built-in set (#2344). `report` is null for the built-in source. */
export interface RuleUpdatesView {
  source: RulesSource;
  /** Revision of the active text — sent back on apply, like the editor's save. */
  revision: string;
  /** True for a TAGGER_RULES_FILE source: review and export only, never written. */
  readOnly: boolean;
  report: RuleUpdateReport | null;
  /** The notice was dismissed at the current built-in revision. */
  dismissed: boolean;
  /** What the copy is compared with: the built-in set or an installed rule pack (#2349), and the
   *  ruleSetRevision() of its rules — sent back with apply/export so a changed upstream is refused. */
  upstream: { id: string; label: string; revision: string } | null;
}

export interface RuleUpdatesApplied {
  ruleCount: number;
  revision: string;
  applied: string[];
  kept: string[];
  /** The copy had no base record; this apply recorded one at the current built-in set. */
  baseEstablished: boolean;
}

// An apply asked of the built-in source. Merging into the bundled default would mean CREATING the
// user copy, which nobody asked for — it is refused (400) instead.
export class NothingToMergeError extends Error {
  constructor() {
    super("nothing to merge: the built-in rules are active");
    this.name = "NothingToMergeError";
  }
}

/** Parse rule YAML into its raw id → rule map. Empty/non-map → {}. Throws on invalid YAML. */
function parseRuleMap(text: string): Record<string, unknown> {
  if (!text.trim()) return {};
  const doc = parseYaml(text);
  return doc && typeof doc === "object" && !Array.isArray(doc) ? (doc as Record<string, unknown>) : {};
}

function stringifyRuleMap(map: RuleMap): string {
  // An empty map serializes to "{}"; persist "" instead so the store reads back an empty ruleset.
  return Object.keys(map).length ? stringifyYaml(map) : "";
}

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
    private readonly opts: { pack?: PackRulesProvider; appVersion?: string } = {},
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
    const pack = await this.activePack();
    if (pack) return { text: pack.text, source: "pack", path: pack.path };
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
  //
  // Every write of the user copy passes here, so this is where the base record (#2344) is kept: a
  // merge passes the base it computed; otherwise, when no copy existed before this write, the copy
  // was taken from the built-in set as it is now, and that is recorded. An existing copy keeps the
  // base it already has — re-basing on a later save would hide every built-in change since.
  private async persist(yamlText: string, nextBase?: RuleBase): Promise<CompiledRuleset> {
    const compiled = compileText(yamlText); // throws on invalid — nothing is written
    const hadCopy = await exists(this.userRulesPath);
    await mkdir(dirname(this.userRulesPath), { recursive: true }); // atomicWrite won't create parents
    const upstream = await this.upstream();
    const base = nextBase ?? (hadCopy || !upstream ? undefined : snapshotBase(upstream.map));
    // The copy first, the base after. A base that lands without its copy would mark rules as
    // decided that the copy never got — they would silently stop being offered. A base write that
    // fails after the copy only offers those rules again, which is the safe direction.
    await atomicWrite(this.userRulesPath, yamlText);
    if (base && upstream) await writeRuleBase(this.baseRecordPath(), upstream.id, base);
    return compiled;
  }

  /** Where the base record for the user copy lives (a sidecar next to it). */
  baseRecordPath(): string {
    return `${this.userRulesPath}.base.json`;
  }

  private dismissRecordPath(): string {
    return `${this.userRulesPath}.updates.json`;
  }

  /** The installed pack while it is in use; a pack that cannot be read is skipped (bundled wins). */
  private async activePack(): Promise<Awaited<ReturnType<PackRulesProvider["activeRules"]>>> {
    if (!this.opts.pack) return null;
    try {
      return await this.opts.pack.activeRules();
    } catch {
      return null;
    }
  }

  private bundledLabel(): string {
    return `bundled with the app${this.opts.appVersion ? ` (${this.opts.appVersion})` : ""}`;
  }

  /** What an edited copy is compared with: the pack in use, else the bundled default. */
  async upstream(): Promise<Upstream | null> {
    const pack = await this.activePack();
    if (pack) return { id: pack.id, label: pack.label, map: parseRuleMap(pack.text) };
    const def = this.resolveDefaultPath();
    if (!def) return null;
    return {
      id: BUILTIN_UPSTREAM,
      label: this.bundledLabel(),
      map: parseRuleMap(await readFile(def, "utf8")),
    };
  }

  /** The bundled default's raw rule map (for Roll back → bundled previews), or null. */
  async bundledRules(): Promise<Record<string, unknown> | null> {
    const def = this.resolveDefaultPath();
    return def ? parseRuleMap(await readFile(def, "utf8")) : null;
  }

  // The copy's base under the upstream's id, else the built-in one (see the header).
  private async readBaseRecord(upstreamId: string): Promise<RuleBase | null> {
    const own = await readRuleBase(this.baseRecordPath(), upstreamId);
    if (own || upstreamId === BUILTIN_UPSTREAM) return own;
    return readRuleBase(this.baseRecordPath(), BUILTIN_UPSTREAM);
  }

  /**
   * One line naming the rules that grade an import, for the analysis-run ledger and the report
   * (#2349) — the tagger's counterpart of the Sigma release stamp.
   */
  async provenance(): Promise<string> {
    const active = await this.readActiveText();
    if (active.source === "env") return "operator rules file (TAGGER_RULES_FILE)";
    if (active.source === "default") return this.bundledLabel();
    const upstream = await this.upstream();
    if (active.source === "pack") return upstream?.label ?? "rule pack";
    return `analyst-edited rules (based on ${upstream?.label ?? "the bundled rules"})`;
  }

  /** Compare the active copy with the built-in set. Throws when the active YAML does not parse. */
  async ruleUpdates(): Promise<RuleUpdatesView> {
    const active = await this.readActive();
    const view = { source: active.source, revision: active.revision, readOnly: active.source === "env" };
    // The pack or the bundled default IS the upstream: there is nothing to merge into it.
    const upstream = active.source === "default" || active.source === "pack" ? null : await this.upstream();
    if (!upstream) return { ...view, report: null, dismissed: false, upstream: null };
    // A TAGGER_RULES_FILE source never has a base record: it is not a copy this server wrote.
    const base = active.source === "user" ? await this.readBaseRecord(upstream.id) : null;
    const report = diffRuleSets({ upstream: upstream.map, mine: parseRuleMap(active.text), base });
    const dismissedAt = await readDismissedRevision(this.dismissRecordPath(), upstream.id);
    return {
      ...view,
      report,
      dismissed: dismissedAt === report.upstreamRevision,
      upstream: { id: upstream.id, label: upstream.label, revision: report.upstreamRevision },
    };
  }

  /**
   * The current upstream, provided it is still the one the review was made against (#2344/#2349).
   * Throws TaggerUpstreamChangedError otherwise. The returned snapshot is the ONE used for both the
   * merge and the new base record, so a reviewed choice can never write an unseen definition.
   */
  private async reviewedUpstream(reviewed: ReviewedRevisions): Promise<Upstream> {
    const upstream = await this.upstream();
    const revision = upstream ? ruleSetRevision(upstream.map) : null;
    if (!upstream || upstream.id !== reviewed.upstreamId || revision !== reviewed.upstreamRevision) {
      throw new TaggerUpstreamChangedError(upstream?.id ?? null, revision);
    }
    return upstream;
  }

  /**
   * Bring chosen built-in rules into the user copy. Same lock and stale-revision check as save():
   * the compare runs INSIDE the lock, and the reviewed revisions are required — a merge is always
   * made from a review the analyst looked at, of this copy AND this upstream, so it is never
   * last-write-wins.
   */
  async applyRuleUpdates(
    choices: Readonly<Record<string, RuleChoice>>,
    reviewed: ReviewedRevisions,
  ): Promise<RuleUpdatesApplied> {
    this.assertEditable();
    return rulesLock.runExclusive(this.userRulesPath, async () => {
      const active = await this.readActiveText();
      const current = rulesRevision(active.text);
      if (current !== reviewed.revision) throw new TaggerRulesConflictError(current);
      if (active.source !== "user") throw new NothingToMergeError();
      const upstream = await this.reviewedUpstream(reviewed);
      const base = await this.readBaseRecord(upstream.id);
      const out = applyRuleUpdates({
        upstream: upstream.map,
        mine: parseRuleMap(active.text),
        base,
        choices,
      });
      const text = stringifyRuleMap(out.rules);
      const compiled = await this.persist(text, out.base);
      return {
        ruleCount: compiled.rules.length,
        revision: rulesRevision(text),
        applied: out.applied,
        kept: out.kept,
        baseEstablished: base === null,
      };
    });
  }

  /**
   * The merged YAML the given choices would produce — for a TAGGER_RULES_FILE source. Writes nothing,
   * but checks the same reviewed revisions as apply, so a download never carries unseen rules.
   */
  async exportMergedRules(
    choices: Readonly<Record<string, RuleChoice>>,
    reviewed: ReviewedRevisions,
  ): Promise<string> {
    const active = await this.readActiveText();
    const current = rulesRevision(active.text);
    if (current !== reviewed.revision) throw new TaggerRulesConflictError(current);
    if (active.source === "default" || active.source === "pack") throw new NothingToMergeError();
    const upstream = await this.reviewedUpstream(reviewed);
    const mine = parseRuleMap(active.text);
    const base = active.source === "user" ? await this.readBaseRecord(upstream.id) : null;
    return stringifyRuleMap(applyRuleUpdates({ upstream: upstream.map, mine, base, choices }).rules);
  }

  /** Hide the notice until the built-in set changes again. Per server; never touches the rules. */
  async dismissRuleUpdates(upstreamRevision: string): Promise<void> {
    const id = (await this.upstream())?.id ?? BUILTIN_UPSTREAM;
    await writeDismissedRevision(this.dismissRecordPath(), id, upstreamRevision);
  }

  /** True when an operator env override (TAGGER_RULES_FILE) owns the ruleset (read-only from our side). */
  isEnvOverride(): boolean {
    return this.envPath() !== undefined;
  }

  /** Parse the active ruleset into its raw id → rule map (for structural edits). Empty → {}. */
  private async loadRawMap(): Promise<Record<string, unknown>> {
    return parseRuleMap((await this.readActive()).text);
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
      const compiled = await this.persist(stringifyRuleMap(next));
      return { removed: true, ruleCount: compiled.rules.length };
    });
  }

  /**
   * Delete the user rule file so the active ruleset falls back to the installed rule pack, or the
   * bundled default when none is in use. No-op if absent.
   */
  async resetToDefault(): Promise<{ ruleCount: number }> {
    this.assertEditable();
    return rulesLock.runExclusive(this.userRulesPath, async () => {
      await rm(this.userRulesPath, { force: true });
      await removeRuleBase(this.baseRecordPath()); // no copy, no base — the next copy records a fresh one
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
