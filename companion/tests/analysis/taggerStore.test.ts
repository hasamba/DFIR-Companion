import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TaggerStore, compileText } from "../../src/analysis/taggerStore.js";

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
    expect(() => compileText("bad:\n  any:\n    - { field: nope, contains: x }\n  tags: ['t']\n")).toThrow(/nope/);
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
    await writeFile(defaultPath, `default_rule:\n  any:\n    - { field: message, contains: def }\n  tags: ['d']\n`);
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
    await expect(store.save("bad:\n  any:\n    - { field: nope, contains: x }\n  tags: ['t']\n")).rejects.toThrow();
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

  it("removeRule on the last remaining rule empties the ruleset (persists \"\", not falls back to default)", async () => {
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
    await expect(store.addRuleYaml("x:\n  any:\n    - { field: message, contains: 'x' }\n  tags: ['t']\n")).rejects.toThrow(/operator override/i);
    await expect(store.removeRule("svc")).rejects.toThrow(/operator override/i);
    await expect(store.resetToDefault()).rejects.toThrow(/operator override/i);
  });
});
