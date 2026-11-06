// Which detection-rule pack is installed (#2349), and the analyst's controls over it: stage a pack
// for review (downloaded and verified, or from a file), install a staged pack, roll back to the
// previous pack or to the rules bundled with the app.
//
// LAYOUT, under <dataRoot>/tagger/pack/:
//   current/tags.yaml + current/pack.json    the installed pack and its record
//   previous/tags.yaml + previous/pack.json  the pack it replaced, for Roll back
// A new pack is written to a fresh staging folder first and renamed into place, so a failed write
// never leaves a half-installed pack; the record carries the rules file's SHA-256 and a pack whose
// bytes no longer match it is not used (the bundled rules win and the status says why).
//
// WHERE A PACK SITS. The tagger store's precedence is TAGGER_RULES_FILE > analyst-edited copy >
// installed pack > bundled (taggerStore.ts). This store only answers "which pack is in use";
// TaggerStore reads it through PackRulesProvider. A pack whose minimum app version is older than
// the running app is "superseded" (rulePackManifest.ts) and is not used: the app's bundled rules
// already contain it, so an app upgrade never runs older rules.
//
// Nothing installs without install(token): check and file previews only stage, in memory.

import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { StateLock } from "./stateLock.js";
import { compileText, type PackRulesProvider } from "./taggerStore.js";
import { RULE_PACK_UPSTREAM } from "./taggerRulesBase.js";
import { sha256Hex } from "./githubReleaseDownload.js";
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

export class RulePackStore implements PackRulesProvider {
  private readonly staged = new Map<string, StagedPack & { expires: number }>();
  lastCheck?: RulePackCheckRecord;

  constructor(
    private readonly dir: string,
    readonly appVersion: string,
  ) {}

  private slot(name: "current" | "previous"): string {
    return join(this.dir, name);
  }

  private async readSlot(
    name: "current" | "previous",
  ): Promise<{ pack: InstalledPack; text: string } | null> {
    try {
      const pack = JSON.parse(await readFile(join(this.slot(name), "pack.json"), "utf8")) as InstalledPack;
      const text = await readFile(join(this.slot(name), "tags.yaml"), "utf8");
      if (!pack || typeof pack.version !== "string" || typeof pack.rulesSha256 !== "string") return null;
      return { pack, text };
    } catch {
      return null; // absent or unreadable: no pack in that slot
    }
  }

  /** Why the installed pack is not used, or undefined when it is. */
  private unusable(slot: { pack: InstalledPack; text: string }): string | undefined {
    if (sha256Hex(slot.text) !== slot.pack.rulesSha256)
      return `the installed rule pack's file no longer matches its recorded SHA-256; the bundled rules are used`;
    if (slot.pack.minAppVersion && packFit(slot.pack.minAppVersion, this.appVersion) === "superseded")
      return `rule pack ${slot.pack.version} is older than the rules bundled with this app (${this.appVersion}); the bundled rules are used`;
    return undefined;
  }

  /** PackRulesProvider: the installed pack's rules while it is in use. */
  async activeRules(): Promise<{ text: string; path: string; id: string; label: string } | null> {
    const cur = await this.readSlot("current");
    if (!cur || this.unusable(cur)) return null;
    return {
      text: cur.text,
      path: join(this.slot("current"), "tags.yaml"),
      id: RULE_PACK_UPSTREAM,
      label: packLabel(cur.pack),
    };
  }

  async status(): Promise<PackStatus> {
    const cur = await this.readSlot("current");
    const prev = await this.readSlot("previous");
    const problem = cur ? this.unusable(cur) : undefined;
    return {
      appVersion: this.appVersion,
      installed: cur?.pack ?? null,
      previous: prev?.pack ?? null,
      superseded: !!problem && /older than the rules bundled/.test(problem),
      ...(problem ? { problem } : {}),
      inUse: cur && !problem ? "pack" : "bundled",
      ...(this.lastCheck ? { lastCheck: this.lastCheck } : {}),
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
    return lock.runExclusive(this.dir, async () => {
      const pack: InstalledPack = { ...s.pack, installedAt: new Date().toISOString() };
      const stagingDir = join(this.dir, `staging-${randomUUID()}`);
      await mkdir(stagingDir, { recursive: true });
      try {
        await writeFile(join(stagingDir, "tags.yaml"), s.rulesText);
        await writeFile(join(stagingDir, "pack.json"), JSON.stringify(pack, null, 2) + "\n");
        await this.shiftCurrentToPrevious();
        await rename(stagingDir, this.slot("current"));
      } finally {
        await rm(stagingDir, { recursive: true, force: true });
      }
      this.staged.delete(token);
      return pack;
    });
  }

  private async shiftCurrentToPrevious(): Promise<void> {
    if (!(await this.readSlot("current"))) {
      await rm(this.slot("current"), { recursive: true, force: true });
      return;
    }
    await rm(this.slot("previous"), { recursive: true, force: true });
    await rename(this.slot("current"), this.slot("previous"));
  }

  /**
   * "previous": the previous pack becomes the installed one, and the one it replaces becomes the
   * previous (so the step can be undone). "bundled": no pack is installed; the removed one becomes
   * the previous. Returns the installed pack afterwards, or null for the bundled rules.
   */
  async rollback(to: "previous" | "bundled"): Promise<InstalledPack | null> {
    return lock.runExclusive(this.dir, async () => {
      if (to === "bundled") {
        if (!(await this.readSlot("current")))
          throw new RulePackError("no rule pack is installed; the bundled rules are in use");
        await this.shiftCurrentToPrevious();
        return null;
      }
      const prev = await this.readSlot("previous");
      if (!prev) throw new RulePackError("there is no previous rule pack to roll back to");
      const swap = join(this.dir, `swap-${randomUUID()}`);
      const hadCurrent = !!(await this.readSlot("current"));
      if (hadCurrent) await rename(this.slot("current"), swap);
      else await rm(this.slot("current"), { recursive: true, force: true });
      await rename(this.slot("previous"), this.slot("current"));
      if (hadCurrent) await rename(swap, this.slot("previous"));
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
