// AI Agent Forensics (#2690): the separate AI-agent rule pack — build, verify, stage, install, roll
// back. GitHub is mocked; nothing here touches the network.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildAiPack,
  isAiPackUnchanged,
  nextAiPackVersion,
  readRuleFolder,
} from "../../scripts/buildAiAgentPack.mjs";
import {
  AiAgentPackError,
  AiAgentPackStore,
  diffAiAgentRuleSets,
  isAiPackTag,
  parseAiPackManifest,
  verifyAiPackBundle,
} from "../../src/analysis/aiAgentPack.js";
import { bundledAiAgentRulesDir, loadAiAgentRuleSet } from "../../src/analysis/aiAgentRuleSet.js";
import { activeAiAgentRuleSet, setActiveAiAgentRulesDir } from "../../src/analysis/aiAgentActiveRules.js";
import { isRulePackTag } from "../../src/analysis/rulePackManifest.js";
import { isAppReleaseTag } from "../../src/analysis/updateCheck.js";

const files = readRuleFolder(bundledAiAgentRulesDir());
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const pack = (over: Partial<Parameters<typeof buildAiPack>[0]> = {}) =>
  buildAiPack({
    files,
    appVersion: "0.47.0",
    version: "aiagent-rules-2026.11.20",
    createdAt: "2026-11-20T00:00:00Z",
    ...over,
  });

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "aiagent-pack-"));
});
afterEach(() => {
  setActiveAiAgentRulesDir(null);
  rmSync(root, { recursive: true, force: true });
});

describe("AI-agent pack: build", () => {
  it("builds a manifest naming the upstream commit, the rule count and every file's hash", () => {
    const { bundle, manifest } = pack();
    expect(manifest.upstream).toEqual({
      name: "ai-dfir-toolkit",
      commit: "5960308d7d8e9bbf838f31ca0e783373fc8a2ae7",
      date: "2026-11-18",
    });
    expect(manifest.ruleCount).toBe(26);
    expect(manifest.contents).toHaveLength(files.length);
    expect(manifest.files[0]).toMatchObject({ name: "ai-agent-rules.json", sha256: sha(bundle) });
  });

  it("numbers a second pack on one day and skips an unchanged one", () => {
    expect(nextAiPackVersion("2026-11-20", ["aiagent-rules-2026.11.20"])).toBe("aiagent-rules-2026.11.20.2");
    const { manifest } = pack();
    expect(isAiPackUnchanged(manifest, pack({ version: "aiagent-rules-2026.11.21" }).manifest)).toBe(true);
    const changed = pack({
      files: files.map((f) => (f.path === "disabled.yml" ? { ...f, text: f.text + "# x\n" } : f)),
    });
    expect(isAiPackUnchanged(manifest, changed.manifest)).toBe(false);
  });

  it("refuses to build without the upstream commit line", () => {
    expect(() => pack({ files: files.filter((f) => f.path !== "UPSTREAM") })).toThrow(/upstream commit/);
  });
});

describe("AI-agent pack: a tag family older apps never see", () => {
  it("is not a detection rule pack tag nor an app release tag", () => {
    expect(isAiPackTag("aiagent-rules-2026.11.20.2")).toBe(true);
    expect(isRulePackTag("aiagent-rules-2026.11.20")).toBe(false);
    expect(isAppReleaseTag("aiagent-rules-2026.11.20")).toBe(false);
    expect(isAiPackTag("rules-2026.11.20")).toBe(false);
  });
});

describe("AI-agent pack: verify", () => {
  it("accepts the bundle it was built with and refuses a tampered or path-escaping one", () => {
    const { bundle, manifest } = pack();
    const m = parseAiPackManifest(JSON.stringify(manifest));
    expect(verifyAiPackBundle(bundle, m)).toHaveLength(files.length);
    const tampered = bundle.replace(
      "MCP_Tool_Poisoning_Hidden_Instructions",
      "MCP_Tool_Poisoning_Hidden_Instructionz",
    );
    expect(() => verifyAiPackBundle(tampered, m)).toThrow(AiAgentPackError);
    const evilFiles = [{ path: "../escape.yar", text: "x" }];
    const evil = JSON.stringify({ schema: 1, files: evilFiles });
    const em = { ...m, bundleSha256: sha(evil), contents: [{ path: "../escape.yar", sha256: sha("x") }] };
    expect(() => verifyAiPackBundle(evil, em)).toThrow(/unsafe path/);
  });

  it("refuses a manifest of another kind", () => {
    expect(() =>
      parseAiPackManifest(JSON.stringify({ ...pack().manifest, kind: "dfir-companion-rule-pack" })),
    ).toThrow(/missing a required field/);
  });
});

describe("AI-agent pack: stage, install, roll back", () => {
  const moved = files.map((f) =>
    f.path === "UPSTREAM"
      ? { ...f, text: f.text.replace("5960308d7d8e9bbf838f31ca0e783373fc8a2ae7", "a".repeat(40)) }
      : f,
  );

  it("loads a staged pack before install, shows its changes, and switches the next run's rules", async () => {
    const store = new AiAgentPackStore(root, "0.47.0");
    const withoutPickle = moved.filter((f) => !f.path.includes("pickle_malicious_opcodes"));
    const staged = await store.stage("aiagent-rules-2026.11.20", withoutPickle);
    const diff = diffAiAgentRuleSets(loadAiAgentRuleSet(), staged);
    expect(diff.removed).toContain("yara:Pickle_Dangerous_Imports");
    expect(diff.added).toEqual([]);
    await store.install("aiagent-rules-2026.11.20");
    expect(activeAiAgentRuleSet().version).toBe("ai-dfir-toolkit @ aaaaaaa (2026-11-18)");
    expect(await store.pointer()).toEqual({ active: "aiagent-rules-2026.11.20", previous: null });
    await store.rollback("bundled");
    expect(activeAiAgentRuleSet().version).toBe("ai-dfir-toolkit @ 5960308 (2026-11-18)");
    await expect(new AiAgentPackStore(join(root, "fresh"), "0.47.0").rollback("previous")).rejects.toThrow(
      /no previous/,
    );
  });

  it("never stages a pack that does not load", async () => {
    const store = new AiAgentPackStore(root, "0.47.0");
    await expect(
      store.stage(
        "aiagent-rules-2026.11.20",
        files.filter((f) => f.path !== "scope-map.yaml"),
      ),
    ).rejects.toThrow(/does not load/);
  });

  it("restores the installed pack at startup", async () => {
    const store = new AiAgentPackStore(root, "0.47.0");
    await store.stage("aiagent-rules-2026.11.20", moved);
    await store.install("aiagent-rules-2026.11.20");
    setActiveAiAgentRulesDir(null);
    expect(await new AiAgentPackStore(root, "0.47.0").restore()).toBe("aiagent-rules-2026.11.20");
    expect(activeAiAgentRuleSet().version).toContain("aaaaaaa");
  });
});

describe("AI-agent pack: check against GitHub (mocked)", () => {
  const base = "https://github.com/hasamba/DFIR-Companion/releases/download/aiagent-rules-2026.11.20";
  function github(manifestOver: Record<string, unknown> = {}) {
    const { bundle, manifest } = pack({
      files: files.map((f) => (f.path === "disabled.yml" ? { ...f, text: f.text + "# re-sync\n" } : f)),
    });
    const manifestText = JSON.stringify({ ...manifest, ...manifestOver });
    const assets: Record<string, string> = {
      [`${base}/ai-agent-rules.json`]: bundle,
      [`${base}/ai-agent-pack-manifest.json`]: manifestText,
    };
    const releases = [
      { tag_name: "v0.47.0", assets: [] },
      { tag_name: "rules-2026.11.19", assets: [] },
      {
        tag_name: "aiagent-rules-2026.11.20",
        assets: Object.entries(assets).map(([url, text]) => ({
          name: url.split("/").pop(),
          browser_download_url: url,
          digest: `sha256:${sha(text)}`,
        })),
      },
    ];
    const fetchFn = (async () => new Response(JSON.stringify(releases))) as unknown as typeof fetch;
    const fetchAsset = async (url: string) => ({
      response: new Response(assets[url]),
      url: new URL(url),
      dispose: async () => {},
    });
    return { fetchFn, fetchAsset };
  }

  it("finds, verifies and stages the newest AI-agent pack, ignoring other release families", async () => {
    const { fetchFn, fetchAsset } = github();
    const out = await new AiAgentPackStore(root, "0.47.0").check(fetchFn, fetchAsset);
    expect(out).toMatchObject({ status: "found", version: "aiagent-rules-2026.11.20" });
    expect(out.diff).toEqual({ added: [], removed: [], changedFiles: [] });
  });

  it("refuses a pack that needs a newer app, and says so", async () => {
    const { fetchFn, fetchAsset } = github({ minAppVersion: "9.0.0" });
    const out = await new AiAgentPackStore(root, "0.47.0").check(fetchFn, fetchAsset);
    expect(out.status).toBe("none");
    expect(out.message).toContain("9.0.0");
  });
});
