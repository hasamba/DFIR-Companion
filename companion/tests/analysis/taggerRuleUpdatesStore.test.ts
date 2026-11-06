import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import {
  TaggerStore,
  TaggerRulesConflictError,
  TaggerUpstreamChangedError,
  type RuleUpdatesView,
} from "../../src/analysis/taggerStore.js";

// #2344 at the store seam: the base record is written with every write of the user copy, survives
// structural edits (stringifyYaml drops comments, so it is a sidecar, not a header), and the merge
// goes through the same lock and stale-revision check as the editor's save.

const r = (text: string, sev = "Low") =>
  `${text}:\n  description: ${text} rule\n  any:\n    - { field: message, contains: ['${text}'] }\n  tags: ['t']\n  severity: ${sev}\n`;

let dir: string;
let userPath: string;
let defaultPath: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-tagger-upd-"));
  userPath = join(dir, "tagger", "tags.yaml");
  defaultPath = join(dir, "default-tags.yaml");
  await writeFile(defaultPath, r("one") + r("two"));
  delete process.env.TAGGER_RULES_FILE;
});

afterEach(async () => {
  delete process.env.TAGGER_RULES_FILE;
  await rm(dir, { recursive: true, force: true });
});

const store = () => new TaggerStore(userPath, [defaultPath]);
const exists = (p: string) =>
  access(p).then(
    () => true,
    () => false,
  );

/** What the dashboard sends back with a merge: the copy and the upstream it reviewed. */
const reviewed = (view: RuleUpdatesView) => ({
  revision: view.revision,
  upstreamId: view.upstream!.id,
  upstreamRevision: view.upstream!.revision,
});

/** The built-in set gains a rule and changes one — an app upgrade. */
async function upgradeBuiltin(): Promise<void> {
  await writeFile(defaultPath, r("one", "High") + r("two") + r("three", "High"));
}

describe("rule updates against the built-in set", () => {
  it("shows nothing while the built-in rules are active", async () => {
    await upgradeBuiltin();
    const u = await store().ruleUpdates();
    expect(u.source).toBe("default");
    expect(u.report).toBeNull();
  });

  it("records the base when the copy is first written, and counts what is new after an upgrade", async () => {
    const s = store();
    await s.removeRule("two"); // a structural edit makes the user copy
    expect(await exists(s.baseRecordPath())).toBe(true);
    await upgradeBuiltin();
    const u = await s.ruleUpdates();
    expect(u.source).toBe("user");
    expect(u.report?.tracked).toBe(true);
    expect(u.report?.added.map((i) => i.key)).toEqual(["three"]);
    expect(u.report?.changed.map((i) => i.key)).toEqual(["one"]);
    expect(u.report?.removedByYou.map((i) => i.key)).toEqual(["two"]);
  });

  it("keeps the original base across later saves and AI-added rules", async () => {
    const s = store();
    await s.save(r("one") + r("two") + r("mine"));
    await upgradeBuiltin();
    await s.addRuleYaml(r("ai_rule")); // after the upgrade — must NOT re-base the copy
    const u = await s.ruleUpdates();
    expect(u.report?.added.map((i) => i.key)).toEqual(["three"]);
    expect(u.report?.analystAdded.sort()).toEqual(["ai_rule", "mine"]);
  });

  it("treats a copy with no base record as legacy", async () => {
    const s = store();
    await s.save(r("one") + r("two"));
    await rm(s.baseRecordPath());
    await upgradeBuiltin();
    const u = await s.ruleUpdates();
    expect(u.report?.tracked).toBe(false);
    expect(u.report?.added.map((i) => i.key)).toEqual(["three"]);
    expect(u.report?.conflicts.map((i) => i.key)).toEqual(["one"]);
  });

  it("applies the chosen rules under the revision check and keeps the analyst's own rules", async () => {
    const s = store();
    await s.save(r("one") + r("two") + r("mine", "Critical"));
    await upgradeBuiltin();
    const out = await s.applyRuleUpdates(
      { three: "upstream", one: "upstream" },
      reviewed(await s.ruleUpdates()),
    );
    expect(out.applied.sort()).toEqual(["one", "three"]);
    const doc = parseYaml(await readFile(userPath, "utf8"));
    expect(doc.three.severity).toBe("High");
    expect(doc.one.severity).toBe("High");
    expect(doc.mine.severity).toBe("Critical");
    expect((await s.ruleUpdates()).report?.hasNews).toBe(false);
  });

  it("refuses an apply with a stale revision and writes nothing", async () => {
    const s = store();
    await s.save(r("one") + r("two"));
    await upgradeBuiltin();
    const before = await readFile(userPath, "utf8");
    const stale = { ...reviewed(await s.ruleUpdates()), revision: "stale" };
    await expect(s.applyRuleUpdates({ three: "upstream" }, stale)).rejects.toBeInstanceOf(
      TaggerRulesConflictError,
    );
    expect(await readFile(userPath, "utf8")).toBe(before);
  });

  it("refuses to apply when the built-in rules are active — an apply never creates the copy", async () => {
    const s = store();
    const { revision } = await s.readActive();
    const asked = { revision, upstreamId: "builtin", upstreamRevision: "0000000000000000" };
    await expect(s.applyRuleUpdates({ one: "upstream" }, asked)).rejects.toThrow(/nothing to merge/);
    expect(await exists(userPath)).toBe(false);
  });

  it("never writes a TAGGER_RULES_FILE source, but exports the merged result", async () => {
    const envFile = join(dir, "operator.yaml");
    await writeFile(envFile, r("one"));
    process.env.TAGGER_RULES_FILE = envFile;
    await upgradeBuiltin();
    const s = store();
    const u = await s.ruleUpdates();
    expect(u.source).toBe("env");
    expect(u.readOnly).toBe(true);
    expect(u.report?.added.map((i) => i.key).sort()).toEqual(["three", "two"]);
    await expect(s.applyRuleUpdates({ three: "upstream" }, reviewed(u))).rejects.toThrow(/TAGGER_RULES_FILE/);
    const exported = await s.exportMergedRules({ three: "upstream" }, reviewed(u));
    expect(Object.keys(parseYaml(exported)).sort()).toEqual(["one", "three"]);
    expect(await readFile(envFile, "utf8")).toBe(r("one"));
    expect(await exists(userPath)).toBe(false);
  });

  it("refuses an apply or export reviewed against an older built-in set and writes nothing", async () => {
    const s = store();
    await s.save(r("one") + r("two"));
    await upgradeBuiltin();
    const view = await s.ruleUpdates();
    expect(view.upstream?.revision).toBe(view.report?.upstreamRevision);
    await writeFile(defaultPath, r("one", "High") + r("two") + r("three", "Critical")); // the app changed again
    const before = await readFile(userPath, "utf8");
    await expect(s.applyRuleUpdates({ three: "upstream" }, reviewed(view))).rejects.toBeInstanceOf(
      TaggerUpstreamChangedError,
    );
    await expect(s.exportMergedRules({ three: "upstream" }, reviewed(view))).rejects.toBeInstanceOf(
      TaggerUpstreamChangedError,
    );
    expect(await readFile(userPath, "utf8")).toBe(before);
  });

  it("remembers a dismiss until the built-in set changes again", async () => {
    const s = store();
    await s.save(r("one"));
    await upgradeBuiltin();
    const first = await s.ruleUpdates();
    expect(first.dismissed).toBe(false);
    await s.dismissRuleUpdates(first.report!.upstreamRevision);
    expect((await store().ruleUpdates()).dismissed).toBe(true);
    await writeFile(defaultPath, r("one", "High") + r("two") + r("three", "High") + r("four"));
    expect((await s.ruleUpdates()).dismissed).toBe(false);
  });

  it("drops the base record on reset", async () => {
    const s = store();
    await s.save(r("one"));
    await s.resetToDefault();
    expect(await exists(s.baseRecordPath())).toBe(false);
  });
});
