import { mkdtemp, mkdir, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { bundledSigmaDir, ruleFiles } from "../../src/analysis/sigmaBundledRules.js";
import { createZip } from "../../src/analysis/zipArchive.js";
import { SigmaRuleStore } from "../../src/analysis/sigmaRuleStore.js";
import { sigmaPaths, writeManifest } from "../../src/analysis/sigmaReleaseFiles.js";

// The installed-rules store (#2204): preview → install → roll back, crash safety, stale previews,
// and the analyst's disabled-list overrides. Real bundled rules, temporary data folder.

const BUNDLED = bundledSigmaDir() as string;
const bundledFiles = ruleFiles(BUNDLED).files;
const NEW_RULE = `title: Brand New Rule\nid: 00000000-0000-0000-0000-00000000beef\nstatus: test\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  sel:\n    eventName: BrandNewCall\n  condition: sel\nlevel: high\n`;

function releaseZip(extra: Record<string, string> = {}, mutate = true): Buffer {
  const files = bundledFiles.map((f, i) => ({
    path: f.path,
    // Change one existing rule so the diff has a "changed" entry.
    text: mutate && i === 0 ? `${f.text}\n# changed upstream\n` : f.text,
  }));
  const entries = [
    ...files.map((f) => ({ path: f.path, data: Buffer.from(f.text) })),
    ...Object.entries(extra).map(([path, text]) => ({ path, data: Buffer.from(text) })),
    {
      path: "version.txt",
      data: Buffer.from("Label: r-next\nCommit-Hash: 1111111111111111111111111111111111111111\n"),
    },
  ];
  return createZip(entries);
}

async function store(env: NodeJS.ProcessEnv = {}): Promise<{ s: SigmaRuleStore; root: string }> {
  const root = await mkdtemp(join(tmpdir(), "dfir-sigma-store-"));
  const s = new SigmaRuleStore(root, BUNDLED, env);
  await s.init();
  return { s, root };
}

const file = { source: "file" as const, fileName: "sigma_all_rules.zip", verified: false };

describe("SigmaRuleStore", () => {
  it("starts on the bundled rules", async () => {
    const { s } = await store();
    expect(s.active()).toMatchObject({ id: "bundled", release: "r2026-07-01", source: "bundled" });
    expect(s.activeRuleSet().release).toBe("r2026-07-01");
  });

  it("previews without installing, then installs and rolls back to the bundled rules", async () => {
    const { s } = await store();
    const p = await s.preview(releaseZip({ "rules/cloud/aws/new.yml": NEW_RULE }), file);
    expect(p.diff.added.map((r) => r.id)).toEqual(["00000000-0000-0000-0000-00000000beef"]);
    expect(p.diff.changed).toHaveLength(1);
    expect(p.diff.removed).toEqual([]);
    expect(p.release).toMatchObject({
      release: "file sigma_all_rules.zip",
      verified: false,
      versionLabel: "r-next",
    });
    expect(s.active().id).toBe("bundled");

    const installed = await s.install(p.token);
    expect(installed.release).toBe("file sigma_all_rules.zip");
    expect(s.activeRuleSet().release).toBe("file sigma_all_rules.zip");
    expect(s.previous()?.id).toBe("bundled");

    const back = await s.rollback();
    expect(back.id).toBe("bundled");
    expect(s.previous()?.id).toBe(installed.id);
  });

  it("refuses a preview whose baseline changed, a reused token, and a stale or unknown token", async () => {
    const { s } = await store();
    const first = await s.preview(releaseZip(), file);
    await s.install(first.token);
    await expect(s.install(first.token)).rejects.toThrow(/preview the release again/);
    const second = await s.preview(releaseZip({ "rules/cloud/aws/new.yml": NEW_RULE }), file);
    await s.rollback();
    await expect(s.install(second.token)).rejects.toThrow(/changed since this preview/);
  });

  it("refuses a release with no rule for a graded log source", async () => {
    const { s } = await store();
    const win = `title: W\nid: w1\nstatus: test\nlogsource:\n  product: windows\n  service: security\ndetection:\n  sel:\n    EventID: 4624\n  condition: sel\nlevel: high\n`;
    const p = await s.preview(createZip([{ path: "rules/windows/w.yml", data: Buffer.from(win) }]), file);
    expect(p.usable).toBe(false);
    await expect(s.install(p.token)).rejects.toThrow(/no rule in this release loads/);
  });

  it("survives a crash between writing the release and switching to it", async () => {
    const { s, root } = await store();
    const p = await s.preview(releaseZip(), file);
    // Simulate the crash: the staged release exists, the manifest was never written.
    const fresh = new SigmaRuleStore(root, BUNDLED, {});
    await fresh.init();
    expect(fresh.active().id).toBe("bundled");
    expect(await readdir(sigmaPaths(root).staging)).toEqual([]);
    expect(p.token).toBeTruthy();
  });

  it("says so, instead of silently using the bundled rules, when the active release cannot be read", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-sigma-store-"));
    await writeManifest(root, { active: "gone-123", previous: null, generation: 3 });
    const s = new SigmaRuleStore(root, BUNDLED, {});
    await s.init();
    expect(s.active().id).toBe("bundled");
    expect(s.activeRuleSet().problems.join(" ")).toMatch(/gone-123 could not be read/);
  });

  it("re-enables a shipped default and disables a loaded rule, latest action winning", async () => {
    const { s } = await store();
    const shippedId = "4f77e1d7-3982-4ee0-8489-abf2d6b75284";
    const loadedId = s.inventory().find((e) => e.outcome === "loaded")!.id;
    expect(s.inventory().find((e) => e.id === shippedId)).toMatchObject({
      outcome: "disabled",
      disabledBy: "shipped",
    });
    await s.setRuleDisabled(shippedId, false);
    expect(s.inventory().find((e) => e.id === shippedId)?.outcome).toBe("loaded");
    await s.setRuleDisabled(loadedId, true, "noisy in this tenant");
    expect(s.inventory().find((e) => e.id === loadedId)).toMatchObject({
      outcome: "disabled",
      disabledBy: "analyst",
      reasons: ["noisy in this tenant"],
    });
    await s.setRuleDisabled(shippedId, true, "back off");
    expect(s.inventory().find((e) => e.id === shippedId)?.reasons).toEqual(["back off"]);
    // Persisted: a new store reads the same overrides.
    const again = new SigmaRuleStore((s as unknown as { dataRoot: string }).dataRoot, BUNDLED, {});
    await again.init();
    expect(again.inventory().find((e) => e.id === loadedId)?.outcome).toBe("disabled");
  });

  it("rebuilds when the status setting changes", async () => {
    const env: NodeJS.ProcessEnv = {};
    const { s } = await store(env);
    const before = s.activeRuleSet().inventory.filter((e) => e.outcome === "loaded").length;
    env.DFIR_SIGMA_RULE_STATUSES = "stable,test,experimental";
    const after = s.activeRuleSet().inventory.filter((e) => e.outcome === "loaded").length;
    expect(after).toBeGreaterThan(before);
    expect(s.activeRuleSet().statuses).toEqual(["stable", "test", "experimental"]);
  });

  it("removes leftover staging and unreferenced releases at startup", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-sigma-store-"));
    await mkdir(join(sigmaPaths(root).releases, "orphan"), { recursive: true });
    await mkdir(join(sigmaPaths(root).staging, "old"), { recursive: true });
    await writeFile(join(sigmaPaths(root).releases, "orphan", "release.json"), "{}");
    const s = new SigmaRuleStore(root, BUNDLED, {});
    await s.init();
    expect(await readdir(sigmaPaths(root).releases)).toEqual([]);
    expect(await readdir(sigmaPaths(root).staging)).toEqual([]);
  });
});
