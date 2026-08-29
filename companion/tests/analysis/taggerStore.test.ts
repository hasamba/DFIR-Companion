import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TaggerStore, TaggerRulesConflictError, compileText } from "../../src/analysis/taggerStore.js";

const VALID = `svc:
  any:
    - { field: message, contains: ['7045'] }
  tags: ['win-service']
`;

describe("compileText", () => {
  it("returns an empty ruleset for empty/whitespace text", () => {
    expect(compileText("").rules).toEqual([]);
    expect(compileText("   \n").rules).toEqual([]);
  });

  it("parses YAML into compiled rules", () => {
    const rs = compileText(VALID);
    expect(rs.rules).toHaveLength(1);
    expect(rs.rules[0].id).toBe("svc");
  });

  it("throws on an invalid rule (unknown field)", () => {
    expect(() => compileText("bad:\n  any:\n    - { field: nope, contains: x }\n  tags: ['t']\n")).toThrow(
      /nope/,
    );
  });
});

describe("TaggerStore", () => {
  let dir: string;
  let userPath: string;
  let defaultPath: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "dfir-tagger-"));
    userPath = join(dir, "tagger-rules.yaml");
    defaultPath = join(dir, "default-tags.yaml");
    await writeFile(
      defaultPath,
      `default_rule:\n  any:\n    - { field: message, contains: def }\n  tags: ['d']\n`,
    );
    delete process.env.TAGGER_RULES_FILE;
  });

  afterEach(async () => {
    delete process.env.TAGGER_RULES_FILE;
    await rm(dir, { recursive: true, force: true });
  });

  it("falls back to the bundled default when no user file exists", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    const active = await store.readActive();
    expect(active.source).toBe("default");
    const loaded = await store.load();
    expect(loaded.source).toBe("default");
    expect(loaded.rules[0].id).toBe("default_rule");
  });

  it("save() validates then persists; load() then reads the user file", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    await store.save(VALID);
    expect(await readFile(userPath, "utf8")).toBe(VALID);
    const loaded = await store.load();
    expect(loaded.source).toBe("user");
    expect(loaded.rules[0].id).toBe("svc");
  });

  it("save() rejects an invalid ruleset WITHOUT writing the file", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    await expect(
      store.save("bad:\n  any:\n    - { field: nope, contains: x }\n  tags: ['t']\n"),
    ).rejects.toThrow();
    // user file must not exist — the bad edit never landed
    await expect(readFile(userPath, "utf8")).rejects.toThrow();
  });

  it("TAGGER_RULES_FILE env overrides both user file and default", async () => {
    const envPath = join(dir, "env-tags.yaml");
    await writeFile(envPath, `env_rule:\n  any:\n    - { field: message, contains: env }\n  tags: ['e']\n`);
    const store = new TaggerStore(userPath, [defaultPath]);
    await store.save(VALID); // user file present, but env should win
    process.env.TAGGER_RULES_FILE = envPath;
    const loaded = await store.load();
    expect(loaded.source).toBe("env");
    expect(loaded.rules[0].id).toBe("env_rule");
  });
});

describe("TaggerStore edits (add/remove/reset)", () => {
  let dir: string, userPath: string, defaultPath: string, store: TaggerStore;
  const DEFAULT = "svc:\n  any:\n    - { field: message, contains: ['7045'] }\n  tags: ['persistence']\n";

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "dfir-tagger-store-edit-"));
    userPath = join(dir, "user-tags.yaml");
    defaultPath = join(dir, "default-tags.yaml");
    await writeFile(defaultPath, DEFAULT);
    store = new TaggerStore(userPath, [defaultPath]);
    delete process.env.TAGGER_RULES_FILE;
  });
  afterEach(async () => {
    delete process.env.TAGGER_RULES_FILE;
    await rm(dir, { recursive: true, force: true });
  });

  it("addRuleYaml merges a new rule and returns the new count", async () => {
    const yaml = "logon:\n  any:\n    - { field: message, contains: 'logged on' }\n  tags: ['logon']\n";
    const res = await store.addRuleYaml(yaml);
    expect(res.id).toBe("logon");
    expect(res.ruleCount).toBe(2);
    const active = await store.load();
    expect(active.source).toBe("user");
    expect(active.rules.map((r) => r.id).sort()).toEqual(["logon", "svc"]);
  });

  it("addRuleYaml creates the rules directory if it does not exist", async () => {
    // point the store at a NESTED path whose parent dir is absent
    const nestedStore = new TaggerStore(join(dir, "missing-subdir", "tags.yaml"), [defaultPath]);
    const res = await nestedStore.addRuleYaml(
      "logon:\n  any:\n    - { field: message, contains: 'x' }\n  tags: ['t']\n",
    );
    expect(res.ruleCount).toBeGreaterThanOrEqual(1);
    expect((await nestedStore.load()).source).toBe("user");
  });

  it("addRuleYaml de-collides an id that already exists", async () => {
    const yaml = "svc:\n  any:\n    - { field: message, contains: 'x' }\n  tags: ['t']\n";
    const res = await store.addRuleYaml(yaml);
    expect(res.id).toBe("svc_2");
    expect(res.ruleCount).toBe(2);
  });

  it("addRuleYaml rejects an invalid rule without persisting", async () => {
    const bad = "bad:\n  any:\n    - { field: not_a_field, contains: 'x' }\n  tags: ['t']\n";
    await expect(store.addRuleYaml(bad)).rejects.toThrow(/not_a_field/);
    await expect(access(userPath)).rejects.toBeTruthy();
  });

  it("removeRule drops a rule and reports removed=true", async () => {
    await store.addRuleYaml("logon:\n  any:\n    - { field: message, contains: 'x' }\n  tags: ['t']\n");
    const res = await store.removeRule("svc");
    expect(res.removed).toBe(true);
    expect(res.ruleCount).toBe(1);
    const active = await store.load();
    expect(active.rules.map((r) => r.id)).toEqual(["logon"]);
  });

  it('removeRule on the last remaining rule empties the ruleset (persists "", not falls back to default)', async () => {
    const res = await store.removeRule("svc"); // svc is the only rule, no prior addRuleYaml
    expect(res.removed).toBe(true);
    expect(res.ruleCount).toBe(0);
    const active = await store.load();
    expect(active.source).toBe("user");
    expect(active.rules).toEqual([]);
  });

  it("removeRule on an absent id reports removed=false and leaves the count unchanged", async () => {
    const res = await store.removeRule("does-not-exist");
    expect(res.removed).toBe(false);
    expect(res.ruleCount).toBe(1);
  });

  it("removeRule treats a prototype-chain key (e.g. 'toString') as absent", async () => {
    const res = await store.removeRule("toString");
    expect(res.removed).toBe(false);
    expect(res.ruleCount).toBe(1); // 'svc' untouched
  });

  it("resetToDefault deletes the user file and falls back to the bundled default", async () => {
    await store.addRuleYaml("logon:\n  any:\n    - { field: message, contains: 'x' }\n  tags: ['t']\n");
    expect((await store.load()).source).toBe("user");
    const res = await store.resetToDefault();
    expect(res.ruleCount).toBe(1);
    expect((await store.load()).source).toBe("default");
  });

  it("resetToDefault is a no-op when no user file exists", async () => {
    const res = await store.resetToDefault();
    expect(res.ruleCount).toBe(1);
    expect((await store.load()).source).toBe("default");
  });

  it("refuses edits when TAGGER_RULES_FILE (operator override) is set", async () => {
    process.env.TAGGER_RULES_FILE = defaultPath;
    await expect(
      store.addRuleYaml("x:\n  any:\n    - { field: message, contains: 'x' }\n  tags: ['t']\n"),
    ).rejects.toThrow(/operator override/i);
    await expect(store.removeRule("svc")).rejects.toThrow(/operator override/i);
    await expect(store.resetToDefault()).rejects.toThrow(/operator override/i);
  });
});

// The rules file is GLOBAL and shared by every analyst on a team-mode deployment. Its methods
// load-modify-write the whole YAML document, so two edits arriving together keep only one — a rule
// the analyst watched get added is simply absent, and (per tagger semantics) nothing re-grades the
// evidence it was written for. The store used to say the missing lock was a deliberate choice for a
// single-analyst tool; team mode is what changed that.
describe("TaggerStore concurrency (follow-up to #682)", () => {
  let userPath: string;
  let defaultPath: string;
  let dir: string;

  const rule = (id: string) =>
    `${id}:\n  any:\n    - { field: message, contains: ['${id}'] }\n  tags: ['${id}']\n`;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "dfir-tagger-race-"));
    userPath = join(dir, "user-tags.yaml");
    defaultPath = join(dir, "default-tags.yaml");
    await writeFile(defaultPath, VALID, "utf8");
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("keeps every rule when many are added at once", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    await Promise.all(Array.from({ length: 12 }, (_, i) => store.addRuleYaml(rule(`r${i}`))));
    const ids = (await store.load()).rules.map((r) => r.id);
    // The bundled default's own rule rides along, so 12 added + 1 default.
    expect(ids).toHaveLength(13);
    expect(new Set(ids).size).toBe(13);
  });

  it("does not lose a concurrent add while another rule is removed", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    await store.addRuleYaml(rule("doomed"));
    await Promise.all([store.removeRule("doomed"), store.addRuleYaml(rule("kept"))]);
    const ids = (await store.load()).rules.map((r) => r.id);
    expect(ids).toContain("kept");
    expect(ids).not.toContain("doomed");
  });

  // A whole-document PUT from the rules editor must not land inside another edit's critical
  // section, so save() takes the same lock. save() is called from the route directly, and the
  // three structural edits call an unlocked persist underneath — StateLock is not reentrant, so
  // nesting the two would deadlock rather than serialize. The lock is FIFO by call order, so both
  // orderings below are deterministic rather than racy.
  it("lets a structural add merge onto a save that went first", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    await Promise.all([store.save(rule("from-editor")), store.addRuleYaml(rule("from-add"))]);
    const ids = (await store.load()).rules.map((r) => r.id);
    expect(ids).toContain("from-editor");
    expect(ids).toContain("from-add");
  });

  // The other ordering. A whole-document save REPLACES the file, so on its own it still discards a
  // structural edit that landed first — the lock makes the two writes atomic with respect to each
  // other, which is a different problem. A caller that sends no revision is opting into that.
  it("lets a revision-less save replace an edit that landed first (last-write-wins)", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    await Promise.all([store.addRuleYaml(rule("from-add")), store.save(rule("from-editor"))]);
    const ids = (await store.load()).rules.map((r) => r.id);
    expect(ids).toEqual(["from-editor"]);
  });

  // …and the fix for it. The editor sends back the revision it loaded, so the same submission is
  // REFUSED rather than applied, and the rule the other analyst added survives.
  it("refuses a save whose revision went stale, keeping the other analyst's rule", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    const opened = (await store.readActive()).revision; // what the editor loaded

    await store.addRuleYaml(rule("from-add")); // somebody else edits while the box is open

    await expect(store.save(rule("from-editor"), opened)).rejects.toBeInstanceOf(TaggerRulesConflictError);
    const ids = (await store.load()).rules.map((r) => r.id);
    expect(ids).toContain("from-add"); // not deleted
    expect(ids).not.toContain("from-editor"); // not applied
  });

  it("accepts a save whose revision is current, and hands back the new one", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    const opened = (await store.readActive()).revision;
    const saved = await store.save(rule("from-editor"), opened);
    expect(saved.revision).toBe((await store.readActive()).revision);
    expect((await store.load()).rules.map((r) => r.id)).toEqual(["from-editor"]);
    // The returned revision is immediately reusable, so a second save needs no reload.
    await expect(store.save(rule("again"), saved.revision)).resolves.toBeDefined();
  });

  // The comparison has to happen INSIDE the lock. Outside it, this is the exact race it exists to
  // close: read the current revision, another writer lands, overwrite anyway.
  it("compares the revision inside the lock, not before it", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    const opened = (await store.readActive()).revision;
    const [addResult, saveResult] = await Promise.allSettled([
      store.addRuleYaml(rule("from-add")),
      store.save(rule("from-editor"), opened),
    ]);
    expect(addResult.status).toBe("fulfilled");
    // The add went first and moved the revision on, so the save must be refused — even though it
    // was issued before the add completed.
    expect(saveResult.status).toBe("rejected");
    expect((await store.load()).rules.map((r) => r.id)).toContain("from-add");
  });

  it("reports the current revision on the conflict, so a client can resync without a second call", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    const opened = (await store.readActive()).revision;
    await store.addRuleYaml(rule("from-add"));
    await expect(store.save(rule("from-editor"), opened)).rejects.toMatchObject({
      currentRevision: (await store.readActive()).revision,
    });
  });

  it("still de-collides ids raced against each other", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    const results = await Promise.all(Array.from({ length: 5 }, () => store.addRuleYaml(rule("dupe"))));
    // Every add gets its own id; none silently overwrites another.
    expect(new Set(results.map((r) => r.id)).size).toBe(5);
    expect((await store.load()).rules.filter((r) => r.id.startsWith("dupe"))).toHaveLength(5);
  });

  it("does not let a reset race an add into a half-reset file", async () => {
    const store = new TaggerStore(userPath, [defaultPath]);
    await store.addRuleYaml(rule("before-reset"));
    await Promise.all([store.resetToDefault(), store.addRuleYaml(rule("after-reset"))]);
    // Either ordering is legitimate; the file must parse and reflect one of them cleanly.
    const ids = (await store.load()).rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
