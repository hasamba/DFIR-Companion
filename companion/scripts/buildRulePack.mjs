/**
 * Build the detection-rule pack (#2349): the built-in tagger rules released separately from the app.
 *
 *   node companion/scripts/buildRulePack.mjs --out <dir> [--previous-manifest <file>] [--taken <tags>]
 *                                            [--date YYYY-MM-DD] [--commit <sha>] [--force]
 *
 * Writes <dir>/tags.yaml and <dir>/rule-pack-manifest.json, and (under GitHub Actions) `changed`,
 * `version` and `out` to $GITHUB_OUTPUT. The manifest names:
 *   - the pack version, `rules-YYYY.MM.DD`, or `rules-YYYY.MM.DD.N` when that day already has a pack;
 *   - the minimum app version that can load it — the companion/package.json version at build time;
 *   - each upstream source with the commit its port was taken from ("# <name> upstream commit:
 *     <sha> (<date>)" lines in the tags.yaml headers, the lines the #2343 check reads);
 *   - the SHA-256 and size of every file.
 *
 * A pack whose rules and sources equal the previous pack's is NOT built (`changed=false`) unless
 * --force is given: a push that does not change the rules publishes nothing.
 *
 * Plain .mjs with node built-ins only, so the workflow runs it with no `npm ci`; buildRulePack.d.mts
 * carries the types for the tests. Everything above main() is pure.
 */
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const PACK_SCHEMA = 1;
export const PACK_KIND = "dfir-companion-rule-pack";
export const RULES_ASSET = "tags.yaml";
export const MANIFEST_ASSET = "rule-pack-manifest.json";

const SOURCE_LINE = /^#\s*(.+?) upstream commit:\s*([0-9a-f]{40})\s*\((\d{4}-\d{2}-\d{2})\)/gm;

export const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** Every "# <name> upstream commit: <sha> (<date>)" header line, first-seen order, one per name. */
export function parseUpstreamSources(tagsYaml) {
  const seen = new Map();
  for (const m of tagsYaml.matchAll(SOURCE_LINE)) {
    if (!seen.has(m[1])) seen.set(m[1], { name: m[1], commit: m[2], date: m[3] });
  }
  return [...seen.values()];
}

/** Top-level rule ids in the rules file (unindented `key:` lines). */
export function countRules(tagsYaml) {
  return tagsYaml.split(/\r?\n/).filter((l) => /^[A-Za-z0-9_][A-Za-z0-9_.-]*:/.test(l)).length;
}

/** `rules-YYYY.MM.DD`, or the next free `.N` (from 2) when that tag is already taken. */
export function nextPackVersion(date, taken = []) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(`date must be YYYY-MM-DD, got "${date}"`);
  const base = `rules-${date.replace(/-/g, ".")}`;
  const set = new Set(taken);
  if (!set.has(base)) return base;
  for (let n = 2; ; n++) if (!set.has(`${base}.${n}`)) return `${base}.${n}`;
}

/** The manifest for one pack. */
export function buildManifest({ tagsYaml, appVersion, version, createdAt, commit }) {
  if (!/^\d+\.\d+\.\d+/.test(appVersion ?? "")) throw new Error(`invalid app version "${appVersion}"`);
  const ruleCount = countRules(tagsYaml);
  if (ruleCount === 0) throw new Error("tags.yaml has no rules; refusing to build an empty pack");
  return {
    schema: PACK_SCHEMA,
    kind: PACK_KIND,
    version,
    minAppVersion: appVersion,
    createdAt,
    ...(commit ? { commit } : {}),
    ruleCount,
    sources: parseUpstreamSources(tagsYaml),
    files: [{ name: RULES_ASSET, sha256: sha256(tagsYaml), bytes: Buffer.byteLength(tagsYaml) }],
  };
}

/** True when the new pack's rules file and sources equal the previous pack's — nothing to publish. */
export function isUnchanged(previous, next) {
  if (!previous || typeof previous !== "object") return false;
  const file = (m) => (Array.isArray(m.files) ? m.files.find((f) => f && f.name === RULES_ASSET) : null);
  const a = file(previous);
  const b = file(next);
  if (!a || !b || a.sha256 !== b.sha256) return false;
  return JSON.stringify(previous.sources ?? []) === JSON.stringify(next.sources ?? []);
}

function argValue(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
}

function readPrevious(path) {
  if (!path) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null; // no previous pack, or an unreadable one: build
  }
}

function main(argv) {
  const here = fileURLToPath(new URL(".", import.meta.url));
  const out = resolve(argValue(argv, "--out") ?? "rule-pack");
  const tagsYaml = readFileSync(join(here, "..", "data", "tags.yaml"), "utf8");
  const appVersion = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")).version;
  const taken = (argValue(argv, "--taken") ?? "").split(/[\s,]+/).filter(Boolean);
  const date = argValue(argv, "--date") ?? new Date().toISOString().slice(0, 10);
  const manifest = buildManifest({
    tagsYaml,
    appVersion,
    version: nextPackVersion(date, taken),
    createdAt: new Date().toISOString(),
    commit: argValue(argv, "--commit"),
  });
  const output = (line) =>
    process.env.GITHUB_OUTPUT && appendFileSync(process.env.GITHUB_OUTPUT, `${line}\n`);
  if (
    !argv.includes("--force") &&
    isUnchanged(readPrevious(argValue(argv, "--previous-manifest")), manifest)
  ) {
    console.log("The rules and their sources equal the latest pack's; nothing to publish.");
    output("changed=false");
    return;
  }
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, RULES_ASSET), tagsYaml);
  writeFileSync(join(out, MANIFEST_ASSET), JSON.stringify(manifest, null, 2) + "\n");
  console.log(`Built ${manifest.version}: ${manifest.ruleCount} rules, app ${appVersion}+, in ${out}`);
  output("changed=true");
  output(`version=${manifest.version}`);
  output(`out=${out}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2));
}
