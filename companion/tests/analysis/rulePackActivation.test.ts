import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fsp from "node:fs/promises";
import { mkdtemp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { RulePackStore } from "../../src/analysis/rulePackStore.js";
import { defaultPackFs, type PackFs } from "../../src/analysis/rulePackLayout.js";
import { parseRulePackManifest } from "../../src/analysis/rulePackManifest.js";

// #2349 follow-up: a pack is activated by atomically replacing a small pointer file, never by moving
// folders, so a reader always sees the old pack or the new one — never "no pack" — and a failure at
// any step leaves the previous pack in use. Faults are injected through the store's fs seam.

const r = (id: string, sev = "Low") =>
  `${id}:\n  description: ${id} rule\n  any:\n    - { field: message, contains: ['${id}'] }\n  tags: ['t']\n  severity: ${sev}\n`;

const manifest = (rules: string, version: string) =>
  parseRulePackManifest(
    JSON.stringify({
      schema: 1,
      kind: "dfir-companion-rule-pack",
      version,
      minAppVersion: "0.45.0",
      createdAt: "2026-11-06T00:00:00Z",
      ruleCount: 1,
      sources: [],
      files: [
        { name: "tags.yaml", sha256: createHash("sha256").update(rules).digest("hex"), bytes: rules.length },
      ],
    }),
  );

let dir: string;
let packDir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-rulepack-act-"));
  packDir = join(dir, "tagger", "pack");
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

/** A store whose fs calls can be made to fail or wait. */
function storeWith(fs: Partial<PackFs> = {}): RulePackStore {
  return new RulePackStore(packDir, "0.45.0", { ...defaultPackFs, ...fs });
}

async function installRules(store: RulePackStore, rules: string, version: string) {
  const staged = store.stage({
    rulesText: rules,
    manifest: manifest(rules, version),
    origin: "downloaded",
    verifiedByGitHub: true,
  });
  return store.install(staged.token);
}

const V1 = r("one") + r("v1");
const V2 = r("one") + r("v2");
const V3 = r("one") + r("v3");

/** Every entry under packs/ — pack folders and any staging leftovers. */
const packEntries = async () => [...(await readdir(join(packDir, "packs")).catch(() => []))].sort();

describe("pointer-based activation", () => {
  it("a reader racing several installs always sees one of the packs, never none", async () => {
    const store = storeWith();
    await installRules(store, V1, "rules-2026.11.01");
    const seen: Array<string | null> = [];
    let installing = true;
    const reader = (async () => {
      while (installing) seen.push((await store.activeRules())?.text ?? null);
    })();
    await installRules(store, V2, "rules-2026.11.02");
    await installRules(store, V3, "rules-2026.11.03");
    await store.rollback("previous");
    installing = false;
    await reader;
    expect(seen.length).toBeGreaterThan(0);
    for (const text of seen) expect([V1, V2, V3]).toContain(text);
  });

  it("a reader that resolved a pack just before it was cleaned up re-reads the pointer", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((res) => (release = res));
    let hold = false;
    const store = storeWith({
      readFile: async (p, enc) => {
        if (hold && p.endsWith("pack.json") && !p.endsWith("active.json")) {
          hold = false;
          await gate; // the reader has the old pointer; two installs now unreference its folder
        }
        return defaultPackFs.readFile(p, enc);
      },
    });
    await installRules(store, V1, "rules-2026.11.01");
    hold = true;
    const pending = store.activeRules();
    const writer = storeWith();
    await installRules(writer, V2, "rules-2026.11.02");
    await installRules(writer, V3, "rules-2026.11.03"); // V1 is now neither current nor previous
    release();
    expect((await pending)?.text).toBe(V3);
  });

  it("keeps an immutable folder per pack and only the current and previous ones", async () => {
    const store = storeWith();
    await installRules(store, V1, "rules-2026.11.01");
    await installRules(store, V2, "rules-2026.11.02");
    await installRules(store, V3, "rules-2026.11.03");
    expect(await packEntries()).toHaveLength(2);
    expect((await store.status()).previous?.version).toBe("rules-2026.11.02");
  });
});

describe("a failure at any step leaves the previous pack in use", () => {
  it("staging write fails: the old pack stays, no staging folder is left behind", async () => {
    const store = storeWith();
    await installRules(store, V1, "rules-2026.11.01");
    const before = await packEntries();
    const failing = storeWith({
      writeFile: async (p, data) => {
        if (p.endsWith("tags.yaml")) throw new Error("disk full");
        return defaultPackFs.writeFile(p, data);
      },
    });
    await expect(installRules(failing, V2, "rules-2026.11.02")).rejects.toThrow(/disk full/);
    expect((await store.activeRules())?.text).toBe(V1);
    expect(await packEntries()).toEqual(before);
  });

  it("pointer write fails: the old pack stays and the new pack's folder is cleaned up", async () => {
    const store = storeWith();
    await installRules(store, V1, "rules-2026.11.01");
    await installRules(store, V2, "rules-2026.11.02");
    const before = await packEntries();
    const failing = storeWith({
      rename: async (a, b) => {
        if (b.endsWith("active.json")) throw new Error("EPERM");
        return defaultPackFs.rename(a, b);
      },
    });
    await expect(installRules(failing, V3, "rules-2026.11.03")).rejects.toThrow(/EPERM/);
    const status = await store.status();
    expect(status.installed?.version).toBe("rules-2026.11.02");
    expect(status.previous?.version).toBe("rules-2026.11.01");
    expect((await store.activeRules())?.text).toBe(V2);
    expect(await packEntries()).toEqual(before);
    expect((await readdir(packDir)).filter((n) => n.endsWith(".tmp"))).toEqual([]);
  });

  it("a staged folder that could not be cleaned up is swept at the next start", async () => {
    const store = storeWith();
    await installRules(store, V1, "rules-2026.11.01");
    const failing = storeWith({
      rename: async (a, b) => {
        if (b.endsWith("active.json")) throw new Error("EPERM");
        return defaultPackFs.rename(a, b);
      },
      rm: async () => {
        throw new Error("EBUSY");
      },
    });
    await expect(installRules(failing, V2, "rules-2026.11.02")).rejects.toThrow(/EPERM/);
    expect((await store.activeRules())?.text).toBe(V1);
    expect((await packEntries()).length).toBeGreaterThan(1); // the orphan is still there
    const restarted = storeWith();
    await restarted.recover();
    expect(await packEntries()).toHaveLength(1);
    expect((await restarted.activeRules())?.text).toBe(V1);
  });

  it("rollback pointer write fails: the pack in use does not change", async () => {
    const store = storeWith();
    await installRules(store, V1, "rules-2026.11.01");
    await installRules(store, V2, "rules-2026.11.02");
    const failing = storeWith({
      writeFile: async (p, data) => {
        if (p.includes("active.json")) throw new Error("disk full");
        return defaultPackFs.writeFile(p, data);
      },
    });
    await expect(failing.rollback("previous")).rejects.toThrow(/disk full/);
    await expect(failing.rollback("bundled")).rejects.toThrow(/disk full/);
    const status = await store.status();
    expect(status.installed?.version).toBe("rules-2026.11.02");
    expect(status.previous?.version).toBe("rules-2026.11.01");
    expect(status.inUse).toBe("pack");
    expect(await packEntries()).toHaveLength(2);
  });
});

describe("startup recovery", () => {
  it("removes staging leftovers, unreferenced folders and pointer temp files; keeps the active pack", async () => {
    const store = storeWith();
    await installRules(store, V1, "rules-2026.11.01");
    await installRules(store, V2, "rules-2026.11.02");
    const kept = await packEntries();
    await mkdir(join(packDir, "packs", "staging-0b7c1f9e-0000-4000-8000-000000000000"), { recursive: true });
    await mkdir(join(packDir, "packs", "p-0123456789ab-deadbeef"), { recursive: true });
    await writeFile(join(packDir, "active.json.1b2c3d4e-0000-4000-8000-000000000000.tmp"), "{");
    const restarted = storeWith();
    await restarted.recover();
    expect(await packEntries()).toEqual(kept);
    expect((await readdir(packDir)).filter((n) => n.endsWith(".tmp"))).toEqual([]);
    expect((await restarted.activeRules())?.text).toBe(V2);
  });

  it("a corrupt pointer falls back to the bundled rules visibly, deletes nothing, and a new install recovers", async () => {
    const store = storeWith();
    await installRules(store, V1, "rules-2026.11.01");
    const kept = await packEntries();
    await writeFile(join(packDir, "active.json"), "{ not json");
    const restarted = storeWith();
    await restarted.recover();
    expect(await restarted.activeRules()).toBeNull();
    const status = await restarted.status();
    expect(status.inUse).toBe("bundled");
    expect(status.problem).toMatch(/record of the installed rule pack .* unreadable/);
    expect(await packEntries()).toEqual(kept); // nothing is deleted while the pointer cannot be trusted
    await installRules(restarted, V2, "rules-2026.11.02");
    expect((await restarted.activeRules())?.text).toBe(V2);
    expect((await restarted.status()).problem).toBeUndefined();
  });

  it("a pointer naming a folder that is gone says so instead of silently using the bundled rules", async () => {
    const store = storeWith();
    await installRules(store, V1, "rules-2026.11.01");
    for (const name of await packEntries()) await fsp.rm(join(packDir, "packs", name), { recursive: true });
    expect(await store.activeRules()).toBeNull();
    const status = await store.status();
    expect(status.inUse).toBe("bundled");
    expect(status.problem).toMatch(/files are missing/);
  });

  it("a lost pointer with pack folders present deletes no pack and says so in the status", async () => {
    const store = storeWith();
    await installRules(store, V1, "rules-2026.11.01");
    await installRules(store, V2, "rules-2026.11.02");
    const kept = await packEntries();
    await fsp.rm(join(packDir, "active.json"));
    await mkdir(join(packDir, "packs", "staging-0b7c1f9e-0000-4000-8000-000000000000"), { recursive: true });
    await writeFile(join(packDir, "active.json.1b2c3d4e-0000-4000-8000-000000000000.tmp"), "{");
    const restarted = storeWith();
    await restarted.recover();
    expect(await packEntries()).toEqual(kept); // staging goes, pack folders stay
    expect((await readdir(packDir)).filter((n) => n.endsWith(".tmp"))).toEqual([]);
    expect(await restarted.activeRules()).toBeNull();
    const status = await restarted.status();
    expect(status.inUse).toBe("bundled");
    expect(status.installed).toBeNull();
    expect(status.problem).toMatch(
      /no record of which pack is installed; 2 pack folders found; the bundled rules are in use/,
    );
    await installRules(restarted, V3, "rules-2026.11.03");
    expect((await restarted.status()).problem).toBeUndefined();
  });

  it("rides out a transient lock on the pointer file (Windows antivirus / indexer)", async () => {
    let busy = 1;
    const store = storeWith({
      rename: async (a, b) => {
        if (b.endsWith("active.json") && busy-- > 0)
          throw Object.assign(new Error("busy"), { code: "EBUSY" });
        return defaultPackFs.rename(a, b);
      },
    });
    await installRules(store, V1, "rules-2026.11.01");
    expect(busy).toBe(-1); // the first rename was refused and retried
    expect((await store.activeRules())?.text).toBe(V1);
    expect((await readdir(packDir)).filter((n) => n.endsWith(".tmp"))).toEqual([]);
  });

  it("no pointer at all is simply no pack installed — no problem shown", async () => {
    const store = storeWith();
    await store.recover();
    const status = await store.status();
    expect(status.installed).toBeNull();
    expect(status.problem).toBeUndefined();
    expect(await store.activeRules()).toBeNull();
  });
});
