/**
 * Build the AI-agent rule pack (#2690): companion/data/ai-agent-rules released separately from the
 * app, under its OWN tag family so older apps never see it.
 *
 *   node companion/scripts/buildAiAgentPack.mjs --out <dir> [--previous-manifest <file>]
 *                                               [--taken <tags>] [--date YYYY-MM-DD] [--commit <sha>] [--force]
 *
 * Writes <dir>/ai-agent-rules.json (every file of the rule folder, as text) and
 * <dir>/ai-agent-pack-manifest.json, and (under GitHub Actions) `changed`, `version` and `out` to
 * $GITHUB_OUTPUT. The tag is `aiagent-rules-YYYY.MM.DD[.N]`: it does not match the detection rule
 * pack's `^rules-YYYY.MM.DD` (rulePackManifest.ts), so the tagger's pack check skips it, and it does
 * not start with `v`, so no app-release workflow and no app update notice reacts to it.
 *
 * Plain .mjs with node built-ins only, so the workflow runs it with no `npm ci`. Everything above
 * main() is pure.
 */
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const AI_PACK_SCHEMA = 1;
export const AI_PACK_KIND = "dfir-companion-ai-agent-rule-pack";
export const AI_PACK_BUNDLE_ASSET = "ai-agent-rules.json";
export const AI_PACK_MANIFEST_ASSET = "ai-agent-pack-manifest.json";
export const AI_PACK_TAG_PREFIX = "aiagent-rules-";
const UPSTREAM_LINE = /^# ai-dfir-toolkit upstream commit: ([0-9a-f]{40}) \((\d{4}-\d{2}-\d{2})\)\s*$/m;

export const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const lf = (s) => s.replace(/\r\n/g, "\n");

/** Every file under the rule folder, sorted, as { path, text } with LF line endings. */
export function readRuleFolder(dir) {
  const out = [];
  const walk = (d) => {
    for (const name of readdirSync(d).sort()) {
      const full = join(d, name);
      if (statSync(full).isDirectory()) walk(full);
      else out.push({ path: relative(dir, full).split(sep).join("/"), text: lf(readFileSync(full, "utf8")) });
    }
  };
  walk(dir);
  return out;
}

/** `aiagent-rules-YYYY.MM.DD`, or the next free `.N` (from 2) when that tag is already taken. */
export function nextAiPackVersion(date, taken = []) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(`date must be YYYY-MM-DD, got "${date}"`);
  const base = `${AI_PACK_TAG_PREFIX}${date.replace(/-/g, ".")}`;
  const set = new Set(taken);
  if (!set.has(base)) return base;
  for (let n = 2; ; n++) if (!set.has(`${base}.${n}`)) return `${base}.${n}`;
}

/** The bundle text and the manifest for one pack. */
export function buildAiPack({ files, appVersion, version, createdAt, commit }) {
  if (!/^\d+\.\d+\.\d+/.test(appVersion ?? "")) throw new Error(`invalid app version "${appVersion}"`);
  const upstreamFile = files.find((f) => f.path === "UPSTREAM");
  const m = upstreamFile ? UPSTREAM_LINE.exec(upstreamFile.text) : null;
  if (!m) throw new Error("UPSTREAM has no ai-dfir-toolkit upstream commit line; refusing to build");
  const ruleCount = files
    .filter((f) => /^yara\/.*\.yara?$/.test(f.path))
    .reduce((n, f) => n + (f.text.match(/^\s*(?:private\s+|global\s+)*rule\s+\w+/gm) ?? []).length, 0);
  if (ruleCount === 0) throw new Error("the rule folder has no YARA rule; refusing to build an empty pack");
  const bundle = JSON.stringify({ schema: AI_PACK_SCHEMA, files });
  const manifest = {
    schema: AI_PACK_SCHEMA,
    kind: AI_PACK_KIND,
    version,
    minAppVersion: appVersion,
    createdAt,
    ...(commit ? { commit } : {}),
    upstream: { name: "ai-dfir-toolkit", commit: m[1], date: m[2] },
    ruleCount,
    files: [{ name: AI_PACK_BUNDLE_ASSET, sha256: sha256(bundle), bytes: Buffer.byteLength(bundle) }],
    contents: files.map((f) => ({ path: f.path, sha256: sha256(f.text) })),
  };
  return { bundle, manifest };
}

/** True when the new pack holds the same files as the previous one — nothing to publish. */
export function isAiPackUnchanged(previous, next) {
  if (!previous || typeof previous !== "object" || !Array.isArray(previous.contents)) return false;
  return JSON.stringify(previous.contents) === JSON.stringify(next.contents);
}

function argValue(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
}

function main(argv) {
  const companion = resolve(fileURLToPath(new URL("..", import.meta.url)));
  const out = resolve(argValue(argv, "--out") ?? join(companion, "dist-ai-agent-pack"));
  const date = argValue(argv, "--date") ?? new Date().toISOString().slice(0, 10);
  const taken = (argValue(argv, "--taken") ?? "").split(/\s+/).filter(Boolean);
  const appVersion = JSON.parse(readFileSync(join(companion, "package.json"), "utf8")).version;
  const files = readRuleFolder(join(companion, "data", "ai-agent-rules"));
  const version = nextAiPackVersion(date, taken);
  const { bundle, manifest } = buildAiPack({
    files,
    appVersion,
    version,
    createdAt: new Date().toISOString(),
    commit: argValue(argv, "--commit"),
  });
  let previous = null;
  try {
    const p = argValue(argv, "--previous-manifest");
    previous = p ? JSON.parse(readFileSync(p, "utf8")) : null;
  } catch {
    previous = null;
  }
  const changed = argv.includes("--force") || !isAiPackUnchanged(previous, manifest);
  if (changed) {
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, AI_PACK_BUNDLE_ASSET), bundle);
    writeFileSync(join(out, AI_PACK_MANIFEST_ASSET), JSON.stringify(manifest, null, 2) + "\n");
  }
  console.log(
    changed ? `built ${version} (${manifest.ruleCount} YARA rules)` : "rules unchanged; no pack built",
  );
  if (process.env.GITHUB_OUTPUT)
    appendFileSync(process.env.GITHUB_OUTPUT, `changed=${changed}\nversion=${version}\nout=${out}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main(process.argv.slice(2));
