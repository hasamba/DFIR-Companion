import { mkdtemp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
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

  // #2218: per-rule exclusions, persisted beside disabled.yml.
  describe("exclusions (#2218)", () => {
    const ARN = "arn:aws:iam::111122223333:role/BackupService";
    const cloudTrailRule = (s: SigmaRuleStore) =>
      s.inventory().find((e) => e.outcome === "loaded" && e.source === "aws-cloudtrail")!.id;

    it("adds an exclusion, shows it on the rule, rebuilds the rule set and persists it", async () => {
      const { s, root } = await store();
      const id = cloudTrailRule(s);
      const before = s.activeRuleSet();
      expect(before.exclusionsHash).toBe("none");
      await s.setRuleExclusion(id, "userIdentity.arn", ARN, "nightly backup");
      const after = s.activeRuleSet();
      expect(after).not.toBe(before);
      expect(after.exclusionsHash).toMatch(/^[0-9a-f]{8}$/);
      expect(s.inventory().find((e) => e.id === id)?.exclusions).toEqual([
        { field: "userIdentity.arn", value: ARN, reason: "nightly backup" },
      ]);
      const again = new SigmaRuleStore(root, BUNDLED, {});
      await again.init();
      expect(again.inventory().find((e) => e.id === id)?.exclusions).toHaveLength(1);
      expect(again.activeRuleSet().exclusionsHash).toBe(after.exclusionsHash);
    });

    it("removes an exclusion, and removing one that is not there changes nothing", async () => {
      const { s } = await store();
      const id = cloudTrailRule(s);
      await s.setRuleExclusion(id, "userIdentity.arn", ARN, "");
      await s.removeRuleExclusion(id, "USERIDENTITY.ARN", ARN.toUpperCase());
      expect(s.inventory().find((e) => e.id === id)?.exclusions).toBeUndefined();
      expect(s.activeRuleSet().exclusionsHash).toBe("none");
      await s.removeRuleExclusion(id, "userIdentity.arn", "nothing");
      expect(s.activeRuleSet().exclusionsHash).toBe("none");
    });

    it("replaces the reason when the same exclusion is added again", async () => {
      const { s } = await store();
      const id = cloudTrailRule(s);
      await s.setRuleExclusion(id, "userIdentity.arn", ARN, "first");
      await s.setRuleExclusion(id, "userIdentity.arn", ARN, "second");
      expect(s.inventory().find((e) => e.id === id)?.exclusions).toEqual([
        { field: "userIdentity.arn", value: ARN, reason: "second" },
      ]);
    });

    it("refuses a field the rule's log source cannot read (422) and an unknown rule (404)", async () => {
      const { s } = await store();
      const id = cloudTrailRule(s);
      await expect(s.setRuleExclusion(id, "TargetFilename", "x", "")).rejects.toMatchObject({
        status: 422,
        message: expect.stringMatching(/TargetFilename is not available in AWS CloudTrail/),
      });
      await expect(s.setRuleExclusion("no-such-rule", "eventName", "x", "")).rejects.toMatchObject({
        status: 404,
      });
      await expect(s.setRuleExclusion(id, "eventName", "   ", "")).rejects.toMatchObject({ status: 422 });
    });

    it("loads a malformed exclusions.yml as empty without failing startup", async () => {
      const root = await mkdtemp(join(tmpdir(), "dfir-sigma-store-"));
      await mkdir(sigmaPaths(root).root, { recursive: true });
      await writeFile(sigmaPaths(root).exclusions, "exclusions: [unclosed");
      const s = new SigmaRuleStore(root, BUNDLED, {});
      await s.init();
      expect(s.activeRuleSet().exclusionsHash).toBe("none");
    });
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

  it("falls back to the bundled rules, and says so, when an installed release lost its rules (Codex review)", async () => {
    const { s: st, root } = await store();
    const p = await st.preview(releaseZip(), file);
    const installed = await st.install(p.token);
    await rm(join(sigmaPaths(root).releases, installed.id, "rules"), { recursive: true, force: true });
    const fresh = new SigmaRuleStore(root, BUNDLED, {});
    await fresh.init();
    expect(fresh.active().id).toBe("bundled");
    const set = fresh.activeRuleSet();
    expect(set.release).toBe("r2026-07-01");
    expect(set.problems.join(" ")).toMatch(new RegExp(`${installed.id} could not be read`));
    expect(set.inventory.some((e) => e.outcome === "loaded")).toBe(true);
  });

  it("refuses to roll back to a release that lost its rules", async () => {
    const { s: st, root } = await store();
    const first = await st.install((await st.preview(releaseZip(), file)).token);
    await st.install((await st.preview(releaseZip({ "rules/cloud/aws/new.yml": NEW_RULE }), file)).token);
    await rm(join(sigmaPaths(root).releases, first.id, "rules"), { recursive: true, force: true });
    await expect(st.rollback()).rejects.toThrow(/can no longer be read/);
  });
});
