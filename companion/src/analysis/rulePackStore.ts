// Which detection-rule pack is installed (#2349), and the analyst's controls over it: stage a pack
// for review (downloaded and verified, or from a file), install a staged pack, roll back to the
// previous pack or to the rules bundled with the app.
//
// LAYOUT, under <dataRoot>/tagger/pack/ (rulePackLayout.ts): one immutable folder per installed
// pack, and a small pointer file naming the current pack and the previous one (for Roll back).
// Install writes the new pack's folder completely, then atomically replaces the pointer; Roll back
// only replaces the pointer. A reader therefore always resolves the old pack or the new one — there
// is never a moment with no pack — and a failure at any step leaves the pack in use unchanged. A
// folder is removed only after the pointer stopped naming it; leftovers from a crash are swept by
// recover() at startup. The record carries the rules file's SHA-256 and a pack whose bytes no longer
// match it is not used (the bundled rules win and the status says why). A pointer that cannot be read
// is reported the same way — visibly, never as a silent "no pack".
//
// WHERE A PACK SITS. The tagger store's precedence is TAGGER_RULES_FILE > analyst-edited copy >
// installed pack > bundled (taggerStore.ts). This store only answers "which pack is in use";
// TaggerStore reads it through PackRulesProvider. A pack whose minimum app version is older than
// the running app is "superseded" (rulePackManifest.ts) and is not used: the app's bundled rules
// already contain it, so an app upgrade never runs older rules.
//
// Nothing installs without install(token): check and file previews only stage, in memory.

import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { StateLock } from "./stateLock.js";
import {
  PackLayout,
  defaultPackFs,
  newPackId,
  pointerIds,
  type PackFs,
  type PackPointer,
} from "./rulePackLayout.js";
import { compileText, type PackRulesProvider } from "./taggerStore.js";
import { RULE_PACK_UPSTREAM } from "./taggerRulesBase.js";
import { sha256Hex } from "./githubReleaseDownload.js";
import { comparePackVersions } from "./rulePackManifest.js";
import {
  RULE_PACK_MAX_RULES_BYTES,
  needsNewerAppMessage,
  packFit,
  verifyRulesAgainstManifest,
  type RulePackManifest,
} from "./rulePackManifest.js";

export type PackOrigin = "downloaded" | "file";

export interface InstalledPack {
  /** `rules-YYYY.MM.DD[.N]`, or `file-<sha12>` for a rules file installed without a manifest. */
  version: string;
  origin: PackOrigin;
  /** True only for a download checked against GitHub's published SHA-256. */
  verifiedByGitHub: boolean;
  rulesSha256: string;
  ruleCount: number;
  minAppVersion?: string;
  sources: Array<{ name: string; commit: string; date: string }>;
  fileName?: string;
  htmlUrl?: string;
  stagedAt: string;
  installedAt?: string;
}

export interface StagedPack {
  token: string;
  pack: InstalledPack;
  rulesText: string;
}

export interface PackStatus {
  appVersion: string;
  installed: InstalledPack | null;
  previous: InstalledPack | null;
  /** True when an installed pack is not used because this app's bundled rules are newer. */
  superseded: boolean;
  /** Why an installed pack is not used, when it is not (superseded, or its file no longer matches). */
  problem?: string;
  /** "pack" when the installed pack is the pack in use, else "bundled". */
  inUse: "pack" | "bundled";
  lastCheck?: RulePackCheckRecord;
}

export interface RulePackCheckRecord {
  at: string;
  status: "update" | "current" | "superseded" | "none" | "needs-newer-app" | "error";
  message: string;
  latest?: string;
}

/**
 * #2389: the last check, read against what is installed NOW. An "update" found before the pack was
 * installed is current once that pack (or a newer one) is in use; it was shown as "available" next
 * to "installed and current". A roll back to the bundled rules makes it an update again.
 */
export function checkAsOfNow(check: RulePackCheckRecord, installed: string | null): RulePackCheckRecord {
  if ((check.status !== "update" && check.status !== "current") || !check.latest) return check;
  // A "current" check goes stale the other way: install, check, then roll back (Codex review).
  if (!installed || comparePackVersions(check.latest, installed) > 0)
    return {
      ...check,
      status: "update",
      message: `Rule pack ${check.latest} is available (installed: ${installed ?? "the bundled rules"}).`,
    };
  return { ...check, status: "current", message: `Rule pack ${installed} is installed and current.` };
}

export class RulePackError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
    this.name = "RulePackError";
  }
}

const STAGE_TTL_MS = 60 * 60 * 1000;
const MAX_STAGED = 5;
const lock = new StateLock();

export interface StageInput {
  rulesText: string;
  manifest?: RulePackManifest;
  origin: PackOrigin;
  verifiedByGitHub: boolean;
  fileName?: string;
  htmlUrl?: string;
}

interface PackRead {
  pack: InstalledPack;
  text: string;
  path: string;
}

/** The pointer as resolved: the current pack's files, or why there is none. */
interface Resolved {
  /** null when the pointer cannot be trusted (corrupt). */
  pointer: PackPointer | null;
  current: PackRead | null;
  /** Set when the pointer names a pack that cannot be used for a reason other than its content. */
  problem?: string;
  /** There is no pointer file at all (a fresh install — or a lost record, when pack folders exist). */
  noPointer?: boolean;
}

const NO_PACK: PackPointer = { current: null, previous: null };
const RESOLVE_RETRIES = 3;

export class RulePackStore implements PackRulesProvider {
  private readonly staged = new Map<string, StagedPack & { expires: number }>();
  private readonly layout: PackLayout;
  private recovered?: Promise<string[]>;
  lastCheck?: RulePackCheckRecord;

  constructor(
    private readonly dir: string,
    readonly appVersion: string,
    /** The fs seam: tests fail or delay a single step through it. */
    private readonly fs: PackFs = defaultPackFs,
  ) {
    this.layout = new PackLayout(dir, fs);
  }

  private async readPack(id: string): Promise<PackRead | null> {
    const folder = this.layout.packDir(id);
    try {
      const pack = JSON.parse(await this.fs.readFile(join(folder, "pack.json"), "utf8")) as InstalledPack;
      const path = join(folder, "tags.yaml");
      const text = await this.fs.readFile(path, "utf8");
      if (!pack || typeof pack.version !== "string" || typeof pack.rulesSha256 !== "string") return null;
      return { pack, text, path };
    } catch {
      return null; // absent or unreadable
    }
  }

  /**
   * Resolve the pointer to the current pack. A folder that vanished under a reader (a later install
   * cleaned it up after the pointer moved on) is retried against the new pointer, so a concurrent
   * reader never mistakes a switch for "no pack".
   */
  private async resolve(): Promise<Resolved> {
    for (let attempt = 0; ; attempt++) {
      const read = await this.layout.readPointer();
      if (read.kind === "missing") return { pointer: NO_PACK, current: null, noPointer: true };
      if (read.kind === "corrupt") {
        return {
          pointer: null,
          current: null,
          problem: `the record of the installed rule pack (active.json) is unreadable — ${read.reason}; the bundled rules are used until a pack is installed or rolled back`,
        };
      }
      const { pointer } = read;
      if (!pointer.current) return { pointer, current: null };
      const current = await this.readPack(pointer.current);
      if (current) return { pointer, current };
      const again = await this.layout.readPointer();
      const moved = again.kind !== "ok" || again.pointer.current !== pointer.current;
      if (moved && attempt < RESOLVE_RETRIES) continue;
      return {
        pointer,
        current: null,
        problem: `the installed rule pack's files are missing or unreadable; the bundled rules are used`,
      };
    }
  }

  /**
   * Startup recovery, once per store: sweep staging leftovers, pointer temp files and pack folders
   * the pointer no longer names. With a missing or unreadable pointer no pack folder is touched.
   * Returns the paths that could not be removed (retried at the next start). Never throws.
   */
  recover(): Promise<string[]> {
    this.recovered ??= lock
      .runExclusive(this.dir, async () => {
        const read = await this.layout.readPointer();
        // Only a readable pointer says which folders are unwanted. Missing or corrupt, no pack folder
        // is touched: they may be the installed pack whose record was lost (status() says so).
        return this.layout.sweep(read.kind === "ok" ? pointerIds(read.pointer) : null);
      })
      .catch((err: Error) => [`${this.dir}: ${err.message}`]);
    return this.recovered;
  }

  /** Switch the pointer, then remove the folders it no longer names. A failed switch changes nothing. */
  private async activate(before: PackPointer | null, next: PackPointer): Promise<void> {
    await this.layout.writePointer(next);
    if (!before) return; // an untrusted old pointer: leave its folders to recovery, never guess
    const keep = pointerIds(next);
    await this.layout.removePacks([...pointerIds(before)].filter((id) => !keep.has(id)));
  }

  /** Why the installed pack is not used, or undefined when it is. */
  private unusable(slot: PackRead): string | undefined {
    if (sha256Hex(slot.text) !== slot.pack.rulesSha256)
      return `the installed rule pack's file no longer matches its recorded SHA-256; the bundled rules are used`;
    if (slot.pack.minAppVersion && packFit(slot.pack.minAppVersion, this.appVersion) === "superseded")
      return `rule pack ${slot.pack.version} is older than the rules bundled with this app (${this.appVersion}); the bundled rules are used`;
    return undefined;
  }

  /** PackRulesProvider: the installed pack's rules while it is in use. */
  async activeRules(): Promise<{ text: string; path: string; id: string; label: string } | null> {
    const { current } = await this.resolve();
    if (!current || this.unusable(current)) return null;
    return { text: current.text, path: current.path, id: RULE_PACK_UPSTREAM, label: packLabel(current.pack) };
  }

  /** A missing pointer beside pack folders is a lost record, not "no pack" — say so, never silently. */
  private async lostPointerProblem(): Promise<string | undefined> {
    const n = (await this.layout.listPackIds()).length;
    if (n === 0) return undefined;
    return `no record of which pack is installed; ${n} pack folder${n === 1 ? "" : "s"} found; the bundled rules are in use until a pack is installed`;
  }

  async status(): Promise<PackStatus> {
    const res = await this.resolve();
    const prev = res.pointer?.previous ? await this.readPack(res.pointer.previous) : null;
    const lost = res.noPointer ? await this.lostPointerProblem() : undefined;
    const problem = res.problem ?? lost ?? (res.current ? this.unusable(res.current) : undefined);
    return {
      appVersion: this.appVersion,
      installed: res.current?.pack ?? null,
      previous: prev?.pack ?? null,
      superseded: !!problem && /older than the rules bundled/.test(problem),
      ...(problem ? { problem } : {}),
      inUse: res.current && !problem ? "pack" : "bundled",
      ...(this.lastCheck
        ? {
            lastCheck: checkAsOfNow(
              this.lastCheck,
              res.current && !problem ? res.current.pack.version : null,
            ),
          }
        : {}),
    };
  }

  /** Validate a pack and hold it for review. Throws a RulePackError saying what is wrong. */
  stage(input: StageInput): StagedPack {
    if (Buffer.byteLength(input.rulesText) > RULE_PACK_MAX_RULES_BYTES)
      throw new RulePackError(
        `the rules file is larger than ${RULE_PACK_MAX_RULES_BYTES / (1024 * 1024)} MB`,
      );
    const m = input.manifest;
    if (m) {
      if (packFit(m.minAppVersion, this.appVersion) === "needs-newer-app")
        throw new RulePackError(needsNewerAppMessage(m.version, m.minAppVersion, this.appVersion), 422);
      try {
        verifyRulesAgainstManifest(m, input.rulesText);
      } catch (err) {
        throw new RulePackError((err as Error).message, 422);
      }
    }
    let ruleCount: number;
    try {
      ruleCount = compileText(input.rulesText).rules.length;
    } catch (err) {
      throw new RulePackError(`the pack's rules do not load: ${(err as Error).message}`, 422);
    }
    if (ruleCount === 0) throw new RulePackError("the pack holds no rules", 422);
    const rulesSha256 = sha256Hex(input.rulesText);
    const pack: InstalledPack = {
      version: m?.version ?? `file-${rulesSha256.slice(0, 12)}`,
      origin: input.origin,
      verifiedByGitHub: input.verifiedByGitHub,
      rulesSha256,
      ruleCount,
      ...(m ? { minAppVersion: m.minAppVersion } : {}),
      sources: m?.sources ?? [],
      ...(input.fileName ? { fileName: input.fileName.slice(0, 200) } : {}),
      ...(input.htmlUrl ? { htmlUrl: input.htmlUrl } : {}),
      stagedAt: new Date().toISOString(),
    };
    this.expire();
    // Room for the new review: only staging evicts the oldest, so a lookup never drops a review.
    while (this.staged.size >= MAX_STAGED) this.staged.delete(this.staged.keys().next().value as string);
    const token = randomUUID();
    const staged = { token, pack, rulesText: input.rulesText };
    this.staged.set(token, { ...staged, expires: Date.now() + STAGE_TTL_MS });
    return staged;
  }

  getStaged(token: string): StagedPack | undefined {
    this.expire();
    const s = this.staged.get(token);
    return s ? { token: s.token, pack: s.pack, rulesText: s.rulesText } : undefined;
  }

  private expire(): void {
    const now = Date.now();
    for (const [k, v] of this.staged) if (v.expires < now) this.staged.delete(k);
  }

  /** Make a staged pack the installed one; the pack it replaces becomes the previous one. */
  async install(token: string): Promise<InstalledPack> {
    const s = this.getStaged(token);
    if (!s)
      throw new RulePackError("that review has expired; check for updates or choose the file again", 410);
    await this.recover();
    return lock.runExclusive(this.dir, async () => {
      const pack: InstalledPack = { ...s.pack, installedAt: new Date().toISOString() };
      const before = await this.resolve();
      const id = newPackId(pack.rulesSha256);
      await this.layout.writePack(id, {
        "tags.yaml": s.rulesText,
        "pack.json": JSON.stringify(pack, null, 2) + "\n",
      });
      // A current pack that cannot be read is dropped, not kept for Roll back; the previous stays.
      const previous = before.current ? before.pointer!.current : (before.pointer?.previous ?? null);
      try {
        await this.activate(before.pointer, { current: id, previous });
      } catch (err) {
        await this.layout.removePacks([id]); // the pointer never named it; recovery sweeps it if this fails
        throw err;
      }
      this.staged.delete(token);
      return pack;
    });
  }

  /**
   * "previous": the previous pack becomes the installed one, and the one it replaces becomes the
   * previous (so the step can be undone). "bundled": no pack is installed; the removed one becomes
   * the previous. Returns the installed pack afterwards, or null for the bundled rules. Only the
   * pointer changes, so a failure leaves the pack in use as it was.
   */
  async rollback(to: "previous" | "bundled"): Promise<InstalledPack | null> {
    await this.recover();
    return lock.runExclusive(this.dir, async () => {
      const before = await this.resolve();
      const currentId = before.current ? before.pointer!.current : null;
      if (to === "bundled") {
        if (!currentId) throw new RulePackError("no rule pack is installed; the bundled rules are in use");
        await this.activate(before.pointer, { current: null, previous: currentId });
        return null;
      }
      const prevId = before.pointer?.previous ?? null;
      const prev = prevId ? await this.readPack(prevId) : null;
      if (!prevId || !prev) throw new RulePackError("there is no previous rule pack to roll back to");
      await this.activate(before.pointer, { current: prevId, previous: currentId });
      return prev.pack;
    });
  }
}

/** How a pack is named in the UI, the analysis-run ledger and the report. */
export function packLabel(pack: InstalledPack): string {
  if (pack.origin === "file")
    return `rule pack ${pack.version} (installed from a file, not checked against GitHub, sha256 ${pack.rulesSha256.slice(0, 12)})`;
  return `rule pack ${pack.version} (downloaded from GitHub)`;
}
