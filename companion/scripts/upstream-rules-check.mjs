/**
 * Weekly upstream rule-list check (#2343) — the I/O half. The diff logic is in upstreamRulesDiff.mjs.
 *
 *   node companion/scripts/upstream-rules-check.mjs --dry-run
 *       print the per-list added/removed/changed diff and write nothing
 *   node companion/scripts/upstream-rules-check.mjs --body-file <path>
 *       also write the issue body to <path>, and `changed` / `title` to $GITHUB_OUTPUT
 *
 * Fetches through `gh api`, so it is authenticated (GH_TOKEN in the workflow, the local gh login
 * otherwise) and is not held to the anonymous rate limit. Any failed fetch — a renamed or deleted
 * upstream file, an API error — exits non-zero. It never reports "no change" for a list it could
 * not read.
 */
import { execFile } from "node:child_process";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { promisify } from "node:util";
import {
  UPSTREAM_GROUPS,
  compareGroup,
  groupChanged,
  hasChanges,
  issueTitle,
  readRecordedCommit,
  renderReport,
} from "./upstreamRulesDiff.mjs";

const run = promisify(execFile);
const TAGS_YAML = new URL("../data/tags.yaml", import.meta.url);
const MAX_BUFFER = 32 * 1024 * 1024;

async function gh(args) {
  try {
    const { stdout } = await run("gh", ["api", ...args], { maxBuffer: MAX_BUFFER });
    return stdout;
  } catch (err) {
    const detail =
      err && typeof err === "object" && "stderr" in err ? String(err.stderr).trim() : String(err);
    throw new Error(`gh api ${args.join(" ")} failed: ${detail}`);
  }
}

/** Newest upstream commit touching the group's watched path. */
async function latestCommit(group) {
  const path = encodeURIComponent(group.watchPath);
  const sha = (await gh([`repos/${group.repo}/commits?path=${path}&per_page=1`, "--jq", ".[0].sha"])).trim();
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new Error(
      `${group.repo}: no commit found for path "${group.watchPath}" (got "${sha}") — was it moved?`,
    );
  }
  return sha;
}

async function fetchFile(repo, path, ref) {
  const text = await gh([
    "-H",
    "Accept: application/vnd.github.raw",
    `repos/${repo}/contents/${path}?ref=${ref}`,
  ]);
  if (text.trim() === "") throw new Error(`${repo}/${path}@${ref}: empty response`);
  return text;
}

/** Every blob under `dir` at `ref` (path → blob sha), from one recursive tree read. */
async function listFiles(repo, dir, ref) {
  const tree = JSON.parse(await gh([`repos/${repo}/git/trees/${ref}?recursive=1`]));
  // A truncated tree would silently drop event files and read as "removed upstream".
  if (tree.truncated) throw new Error(`${repo}@${ref}: the git tree is truncated — cannot list ${dir}/`);
  const prefix = `${dir}/`;
  return new Map(
    (tree.tree ?? [])
      .filter((entry) => entry.type === "blob" && String(entry.path).startsWith(prefix))
      .map((entry) => [entry.path, entry.sha]),
  );
}

/** The files directly in `dir` at `ref` (path → blob sha), from the contents API — one level only. */
async function listDir(repo, dir, ref) {
  const path = dir.split("/").map(encodeURIComponent).join("/");
  const entries = JSON.parse(await gh([`repos/${repo}/contents/${path}?ref=${ref}`]));
  if (!Array.isArray(entries)) throw new Error(`${repo}/${dir}@${ref}: not a directory`);
  // The contents API lists at most 1,000 entries; a folder that size cannot be read completely.
  if (entries.length >= 1000) throw new Error(`${repo}/${dir}@${ref}: too many entries to list`);
  return new Map(entries.filter((e) => e.type === "file").map((e) => [String(e.path), String(e.sha)]));
}

function summarise(result) {
  const head = `${result.group.name}: ${result.base.slice(0, 7)}..${result.head.slice(0, 7)}`;
  if (result.lists.length === 0) return `${head} — recorded commit is upstream's newest, nothing to compare`;
  const lines = result.lists.map(({ path, diff }) =>
    hasChanges(diff)
      ? `  ${path}: +${diff.added.length} -${diff.removed.length} ~${diff.changed.length}${diff.headerChanged ? " (columns changed)" : ""}`
      : `  ${path}: no change`,
  );
  return [head, ...lines].join("\n");
}

function parseArgs(argv) {
  const dryRun = argv.includes("--dry-run");
  const idx = argv.indexOf("--body-file");
  const bodyFile = idx >= 0 ? argv[idx + 1] : undefined;
  if (idx >= 0 && !bodyFile) throw new Error("--body-file needs a path");
  return { dryRun, bodyFile };
}

async function main() {
  const { dryRun, bodyFile } = parseArgs(process.argv.slice(2));
  const tagsYaml = readFileSync(TAGS_YAML, "utf8");
  const results = [];
  for (const group of UPSTREAM_GROUPS) {
    const { sha: base } = readRecordedCommit(tagsYaml, group.marker);
    const head = await latestCommit(group);
    results.push(await compareGroup(group, base, head, fetchFile, listFiles, listDir));
  }
  for (const result of results) console.log(summarise(result));

  const changed = results.some(groupChanged);
  if (changed) console.log(`\n${renderReport(results)}`);
  else console.log("\nNo entries changed upstream — no issue needed.");
  if (dryRun) return;

  if (bodyFile && changed) writeFileSync(bodyFile, renderReport(results));
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `changed=${changed}\n`);
    if (changed) appendFileSync(process.env.GITHUB_OUTPUT, `title=${issueTitle(results)}\n`);
  }
}

main().catch((err) => {
  console.error(`[upstream-rules-check] FAILED: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
