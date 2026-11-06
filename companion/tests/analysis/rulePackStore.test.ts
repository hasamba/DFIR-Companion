import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { RulePackStore, RulePackError } from "../../src/analysis/rulePackStore.js";
import { parseRulePackManifest } from "../../src/analysis/rulePackManifest.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { readRuleBase } from "../../src/analysis/taggerRulesBase.js";

// The installed detection-rule pack (#2349): staging never installs, install / roll back move the
// pack, and the tagger store's precedence is TAGGER_RULES_FILE > edited copy > pack > bundled.

const r = (id: string, sev = "Low") =>
  `${id}:\n  description: ${id} rule\n  any:\n    - { field: message, contains: ['${id}'] }\n  tags: ['t']\n  severity: ${sev}\n`;

const manifest = (rules: string, version: string, minAppVersion = "0.45.0") => {
  return parseRulePackManifest(
    JSON.stringify({
      schema: 1,
      kind: "dfir-companion-rule-pack",
      version,
      minAppVersion,
      createdAt: "2026-11-06T00:00:00Z",
      ruleCount: 1,
      sources: [],
      files: [
        { name: "tags.yaml", sha256: createHash("sha256").update(rules).digest("hex"), bytes: rules.length },
      ],
    }),
  );
};

let dir: string;
let defaultPath: string;
let packs: RulePackStore;
let tagger: TaggerStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-rulepack-"));
  defaultPath = join(dir, "default-tags.yaml");
  await writeFile(defaultPath, r("one") + r("two"));
  delete process.env.TAGGER_RULES_FILE;
  packs = new RulePackStore(join(dir, "tagger", "pack"), "0.45.0");
  tagger = new TaggerStore(join(dir, "tagger", "tags.yaml"), [defaultPath], {
    pack: packs,
    appVersion: "0.45.0",
  });
});

afterEach(async () => {
  delete process.env.TAGGER_RULES_FILE;
  await rm(dir, { recursive: true, force: true });
});

const downloaded = (rules: string, version: string, min = "0.45.0") =>
  packs.stage({
    rulesText: rules,
    manifest: manifest(rules, version, min),
    origin: "downloaded",
    verifiedByGitHub: true,
  });

describe("rule pack store", () => {
  it("looking a review up never evicts it; only a new review makes room", () => {
    const tokens = [1, 2, 3, 4, 5].map((n) => downloaded(r("one") + r(`n${n}`), `rules-2026.11.0${n}`).token);
    expect(packs.getStaged(tokens[0])).toBeDefined();
    expect(packs.getStaged(tokens[0])).toBeDefined();
    downloaded(r("one") + r("n6"), "rules-2026.11.06");
    expect(packs.getStaged(tokens[0])).toBeUndefined();
    expect(packs.getStaged(tokens[1])).toBeDefined();
  });

  it("staging changes nothing; install makes the pack the active rules", async () => {
    const rules = r("one", "High") + r("two") + r("three", "High");
    const staged = downloaded(rules, "rules-2026.11.05");
    expect((await tagger.readActive()).source).toBe("default");
    await packs.install(staged.token);
    const active = await tagger.readActive();
    expect(active.source).toBe("pack");
    expect(active.text).toBe(rules);
    expect((await packs.status()).installed?.version).toBe("rules-2026.11.05");
    expect(await tagger.provenance()).toMatch(/rule pack rules-2026\.11\.05 \(downloaded from GitHub\)/);
  });

  it("refuses a pack that needs a newer app, a SHA mismatch and rules that do not load — nothing installed", async () => {
    expect(() => downloaded(r("one"), "rules-2026.11.05", "0.46.0")).toThrow(/needs DFIR Companion 0\.46\.0/);
    expect(() =>
      packs.stage({
        rulesText: r("one"),
        manifest: manifest(r("two"), "rules-2026.11.05"),
        origin: "file",
        verifiedByGitHub: false,
      }),
    ).toThrow(/does not match the SHA-256/);
    expect(() =>
      packs.stage({
        rulesText: "bad:\n  any: [ { field: nope, contains: x } ]\n",
        origin: "file",
        verifiedByGitHub: false,
      }),
    ).toThrow(RulePackError);
    expect((await packs.status()).installed).toBeNull();
    expect((await tagger.readActive()).source).toBe("default");
  });

  it("a file install is marked not checked against GitHub and records the file's SHA-256", async () => {
    const rules = r("one") + r("filed");
    const staged = packs.stage({
      rulesText: rules,
      origin: "file",
      verifiedByGitHub: false,
      fileName: "tags.yaml",
    });
    const pack = await packs.install(staged.token);
    expect(pack.origin).toBe("file");
    expect(pack.verifiedByGitHub).toBe(false);
    expect(pack.version).toMatch(/^file-[0-9a-f]{12}$/);
    expect(await tagger.provenance()).toMatch(/not checked against GitHub, sha256 [0-9a-f]{12}/);
  });

  it("rolls back to the previous pack, and to the bundled rules", async () => {
    await packs.install(downloaded(r("one") + r("v1"), "rules-2026.11.01").token);
    await packs.install(downloaded(r("one") + r("v2"), "rules-2026.11.05").token);
    expect((await packs.status()).previous?.version).toBe("rules-2026.11.01");
    await packs.rollback("previous");
    expect((await packs.status()).installed?.version).toBe("rules-2026.11.01");
    expect((await packs.status()).previous?.version).toBe("rules-2026.11.05");
    await packs.rollback("bundled");
    expect((await packs.status()).installed).toBeNull();
    expect((await tagger.readActive()).source).toBe("default");
    await expect(packs.rollback("bundled")).rejects.toThrow(/no rule pack is installed/);
  });

  it("an installed pack built for an older app is superseded: the bundled rules are used", async () => {
    await packs.install(downloaded(r("one") + r("old"), "rules-2026.10.01").token);
    const upgraded = new RulePackStore(join(dir, "tagger", "pack"), "0.46.0");
    const t = new TaggerStore(join(dir, "tagger", "tags.yaml"), [defaultPath], { pack: upgraded });
    expect((await t.readActive()).source).toBe("default");
    const s = await upgraded.status();
    expect(s.superseded).toBe(true);
    expect(s.inUse).toBe("bundled");
  });

  it("a pack whose file was altered on disk is not used", async () => {
    await packs.install(downloaded(r("one") + r("x"), "rules-2026.11.05").token);
    await writeFile(join(dir, "tagger", "pack", "current", "tags.yaml"), r("tampered", "Critical"));
    expect((await tagger.readActive()).source).toBe("default");
    expect((await packs.status()).problem).toMatch(/no longer matches/);
  });

  it("precedence: TAGGER_RULES_FILE > edited copy > pack > bundled", async () => {
    await packs.install(downloaded(r("one") + r("p"), "rules-2026.11.05").token);
    expect((await tagger.readActive()).source).toBe("pack");
    await tagger.save(r("mine"));
    expect((await tagger.readActive()).source).toBe("user");
    const envFile = join(dir, "env.yaml");
    await writeFile(envFile, r("env"));
    process.env.TAGGER_RULES_FILE = envFile;
    expect((await tagger.readActive()).source).toBe("env");
    delete process.env.TAGGER_RULES_FILE;
    await tagger.resetToDefault();
    expect((await tagger.readActive()).source).toBe("pack"); // reset falls back to the pack
  });
});

describe("the #2344 merge review with a pack as upstream", () => {
  it("offers a pack's added and changed rules to an edited copy and keeps the analyst's edits", async () => {
    // A copy made from the bundled set (base recorded under "builtin"), with one analyst edit.
    await tagger.save(r("one") + r("two", "Critical") + r("mine"));
    await packs.install(
      downloaded(r("one", "High") + r("two") + r("three", "High"), "rules-2026.11.05").token,
    );
    const view = await tagger.ruleUpdates();
    expect(view.upstream?.id).toBe("rulepack");
    expect(view.report?.tracked).toBe(true); // the builtin base is used — no "unknown side" conflicts
    expect(view.report?.added.map((i) => i.key)).toEqual(["three"]);
    expect(view.report?.changed.map((i) => i.key)).toEqual(["one"]);
    expect(view.report?.analystEdited).toEqual(["two"]);
    expect(view.report?.conflicts).toEqual([]);
    const out = await tagger.applyRuleUpdates({ one: "upstream", three: "upstream" }, view.revision);
    expect(out.applied.sort()).toEqual(["one", "three"]);
    const text = await readFile(join(dir, "tagger", "tags.yaml"), "utf8");
    expect(text).toMatch(/two:[\s\S]*severity: Critical/);
    // The new base is recorded under the pack's id.
    expect(await readRuleBase(tagger.baseRecordPath(), "rulepack")).not.toBeNull();
    expect((await tagger.ruleUpdates()).report?.hasNews).toBe(false);
  });

  it("names the analyst-edited copy and the pack it is based on", async () => {
    await packs.install(downloaded(r("one") + r("p"), "rules-2026.11.05").token);
    await tagger.save(r("mine"));
    expect(await tagger.provenance()).toMatch(
      /^analyst-edited rules \(based on rule pack rules-2026\.11\.05/,
    );
  });
});
