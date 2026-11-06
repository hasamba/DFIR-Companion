import { createHash } from "node:crypto";
import type { ReleaseAssetFetch } from "../../src/analysis/githubReleaseDownload.js";

// Shared fixtures for the rule-pack client, store and route tests (#2349). No network.

export const sha = (s: string | Buffer): string => createHash("sha256").update(s).digest("hex");

export const RULES_V1 = [
  "pack_rule_a:",
  "  description: rule A",
  "  any:",
  "    - { field: message, contains: 'alpha' }",
  "  tags: ['a']",
  "  severity: High",
  "",
].join("\n");

export const RULES_V2 =
  RULES_V1 +
  [
    "pack_rule_b:",
    "  description: rule B",
    "  any:",
    "    - { field: message, contains: 'bravo' }",
    "  tags: ['b']",
    "",
  ].join("\n");

export function manifestFor(rules: string, version: string, minAppVersion = "0.45.0"): string {
  return JSON.stringify({
    schema: 1,
    kind: "dfir-companion-rule-pack",
    version,
    minAppVersion,
    createdAt: "2026-11-06T00:00:00Z",
    ruleCount: 1,
    sources: [{ name: "Example", commit: "a".repeat(40), date: "2026-10-26" }],
    files: [{ name: "tags.yaml", sha256: sha(rules), bytes: Buffer.byteLength(rules) }],
  });
}

const base = "https://github.com/hasamba/DFIR-Companion/releases/download";

export interface FakeRelease {
  tag: string;
  rules: string;
  manifest: string;
  /** Override the digest GitHub "publishes" for the rules asset. */
  rulesDigest?: string;
  rulesUrl?: string;
}

export function releaseJson(r: FakeRelease) {
  return {
    tag_name: r.tag,
    html_url: `https://github.com/hasamba/DFIR-Companion/releases/tag/${r.tag}`,
    assets: [
      {
        name: "tags.yaml",
        browser_download_url: r.rulesUrl ?? `${base}/${r.tag}/tags.yaml`,
        digest: `sha256:${r.rulesDigest ?? sha(r.rules)}`,
      },
      {
        name: "rule-pack-manifest.json",
        browser_download_url: `${base}/${r.tag}/rule-pack-manifest.json`,
        digest: `sha256:${sha(r.manifest)}`,
      },
    ],
  };
}

/** A fetch for the release list, and an asset fetch serving the releases' files by URL. */
export function fakeGitHub(releases: FakeRelease[], extra: unknown[] = []) {
  const files = new Map<string, string>();
  for (const r of releases) {
    files.set(r.rulesUrl ?? `${base}/${r.tag}/tags.yaml`, r.rules);
    files.set(`${base}/${r.tag}/rule-pack-manifest.json`, r.manifest);
  }
  const fetchFn = (async () =>
    new Response(JSON.stringify([...extra, ...releases.map(releaseJson)]), {
      status: 200,
    })) as unknown as typeof fetch;
  const fetched: string[] = [];
  const fetchAsset: ReleaseAssetFetch = async (url) => {
    fetched.push(url);
    const body = files.get(url);
    return {
      response: body === undefined ? new Response("nope", { status: 404 }) : new Response(body),
      url: new URL(url),
      dispose: async () => {},
    };
  };
  return { fetchFn, fetchAsset, fetched };
}
