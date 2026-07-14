import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
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
