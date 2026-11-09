/**
 * Pure logic for the weekly upstream rule-list check (#2343).
 *
 * Some built-in tagger rules in data/tags.yaml are HAND-PORTED from upstream lists — the five
 * Microsoft-Analyzer-Suite blacklists (#2306), the TrailDiscover AWS event files (#2345) and the
 * Panther and Sentinel GCP rule folders (#2346). A port is a judgment call (what to leave out,
 * what grade to give), so the check never edits rules: it compares the upstream lists at the commit
 * the port came from with the lists at upstream's newest commit, and the workflow files ONE issue
 * listing what was added, removed or changed per list. A person then re-ports with the same
 * judgment and moves the recorded commit forward in the same PR.
 *
 * Everything here is pure — no network, no filesystem — so it is unit-tested directly. Fetching
 * lives in upstream-rules-check.mjs and is handed in as a function (`fetchFile`). It is plain .mjs
 * so the workflow runs it under bare `node` with no `npm ci`; upstreamRulesDiff.d.mts carries the
 * types for the tests.
 *
 * Adding a source: append one entry to UPSTREAM_GROUPS and put a matching
 * "<marker>: <sha> (<date>)" line in that port's tags.yaml header — or, for a rule folder bundled
 * verbatim rather than ported (#2499, Suzaku), in the file named by the group's `markerFile`
 * (relative to companion/; default data/tags.yaml). A group is one of three kinds:
 *   "csv-lists"   (the default) a fixed set of CSV files, each diffed entry by entry (first column = key);
 *   "event-files" one JSON file per entry under `watchPath` (TrailDiscover's events/<Service>/<Event>.json),
 *                 listed at both commits with `listFiles`. Only the fields the port used are compared
 *                 (the operation, usedInWild and the ATT&CK ids): a new incident link or a reworded
 *                 description is not a change, a flipped usedInWild flag or a new technique is.
 *   "rule-files"  every file directly in `watchPath` (a Panther or Sentinel rule folder), listed at both
 *                 commits with `listDir` (path -> content hash, the git blob sha). A rule is code or a
 *                 query, so nothing is parsed: a file added, removed or whose content hash changed is
 *                 reported, and a person reads the upstream diff.
 */

/** Matches "<marker>: <40-hex sha> (<YYYY-MM-DD>)" on a `#` comment line of tags.yaml. */
export function recordedCommitPattern(marker) {
  const escaped = marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^#\\s*${escaped}:\\s*([0-9a-f]{40})\\s*\\((\\d{4}-\\d{2}-\\d{2})\\)`, "m");
}

/** The upstream sources whose lists are hand-ported into tags.yaml. */
export const UPSTREAM_GROUPS = Object.freeze([
  Object.freeze({
    id: "analyzer-suite",
    kind: "csv-lists",
    name: "Microsoft-Analyzer-Suite",
    repo: "evild3ad/Microsoft-Analyzer-Suite",
    marker: "Microsoft-Analyzer-Suite upstream commit",
    // Head is the newest commit touching this path, so unrelated upstream commits never move it.
    watchPath: "Blacklists",
    files: Object.freeze([
      "Blacklists/Operation-Blacklist.csv",
      "Blacklists/MoveToFolder-Blacklist.csv",
      "Blacklists/ApplicationPermission-Blacklist.csv",
      "Blacklists/DelegatedPermission-Blacklist.csv",
      "Blacklists/UserAgent-Blacklist.csv",
    ]),
  }),
  Object.freeze({
    id: "traildiscover",
    kind: "event-files",
    name: "TrailDiscover",
    repo: "adanalvarez/TrailDiscover",
    marker: "TrailDiscover upstream commit",
    // The event files are the source; docs/events.json is a generated copy that can lag behind them.
    watchPath: "events",
    files: Object.freeze([]),
  }),
  // GCP (#2346). Read as directory listings, not a recursive tree: Azure-Sentinel's tree is too large.
  Object.freeze({
    id: "panther-gcp",
    kind: "rule-files",
    name: "Panther GCP audit rules",
    repo: "panther-labs/panther-analysis",
    marker: "Panther upstream commit",
    watchPath: "rules/gcp_audit_rules",
    files: Object.freeze([]),
  }),
  Object.freeze({
    id: "sentinel-gcp-audit",
    kind: "rule-files",
    name: "Sentinel GCP Audit Logs analytic rules",
    repo: "Azure/Azure-Sentinel",
    marker: "Sentinel GCP Audit Logs upstream commit",
    watchPath: "Solutions/Google Cloud Platform Audit Logs/Analytic Rules",
    files: Object.freeze([]),
  }),
  Object.freeze({
    id: "sentinel-gcp-iam",
    kind: "rule-files",
    name: "Sentinel GCP IAM analytic rules",
    repo: "Azure/Azure-Sentinel",
    marker: "Sentinel GCP IAM upstream commit",
    watchPath: "Solutions/GoogleCloudPlatformIAM/Analytic Rules",
    files: Object.freeze([]),
  }),
  // #2499: bundled verbatim in data/sigma-suzaku, not ported — so its marker lives beside the rules,
  // not in tags.yaml (buildRulePack reads tags.yaml markers as the rule pack's own sources).
  Object.freeze({
    id: "suzaku-aws",
    kind: "rule-files",
    name: "Suzaku CloudTrail rules",
    repo: "Yamato-Security/suzaku-rules",
    marker: "Suzaku rules upstream commit",
    markerFile: "data/sigma-suzaku/UPSTREAM",
    watchPath: "suzaku/aws/cloudtrail",
    files: Object.freeze([]),
  }),
]);

/** The file, relative to companion/, that records a group's upstream commit. */
export const markerFileOf = (group) => group.markerFile ?? "data/tags.yaml";

/** Read the recorded port commit for one group from its marker file's text, or throw. */
export function readRecordedCommit(tagsYaml, marker, fileName = "tags.yaml") {
  const match = recordedCommitPattern(marker).exec(tagsYaml);
  if (!match) {
    throw new Error(
      `${fileName} has no "# ${marker}: <40-hex sha> (<YYYY-MM-DD>)" line — the check cannot know which upstream commit the port came from.`,
    );
  }
  return { sha: match[1], date: match[2] };
}

/**
 * RFC 4180 CSV: quoted fields, "" escapes, commas and newlines inside quotes, a UTF-8 BOM, CRLF or
 * LF line ends, and a missing final newline. Blank lines are skipped. Throws on an unclosed quote.
 */
export function parseCsv(text) {
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  let i = 0;
  const endRow = () => {
    row.push(field);
    if (!(row.length === 1 && row[0] === "")) rows.push(row);
    row = [];
    field = "";
  };
  while (i < src.length) {
    const ch = src[i];
    if (inQuotes) {
      if (ch === '"' && src[i + 1] === '"') {
        field += '"';
        i += 2;
        continue;
      }
      if (ch === '"') inQuotes = false;
      else field += ch;
      i += 1;
      continue;
    }
    if (ch === '"') inQuotes = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\r" && src[i + 1] === "\n") {
      endRow();
      i += 1;
    } else if (ch === "\n" || ch === "\r") endRow();
    else field += ch;
    i += 1;
  }
  if (inQuotes) throw new Error("CSV has an unclosed quoted field");
  if (field !== "" || row.length > 0) endRow();
  return rows;
}

/** Header + rows keyed by the first column. A list with no header row is an error, never empty. */
export function parseList(text, label) {
  const rows = parseCsv(text);
  if (rows.length === 0 || rows[0].every((cell) => cell.trim() === "")) {
    throw new Error(`${label}: empty or headerless CSV — refusing to treat it as "no entries"`);
  }
  const [header, ...body] = rows;
  const entries = new Map();
  for (const cells of body) {
    const key = cells[0] ?? "";
    if (key.trim() !== "") entries.set(key, cells);
  }
  return { header, entries };
}

const sameCells = (a, b) => a.length === b.length && a.every((cell, idx) => cell === b[idx]);

/** Per-list diff of two CSV texts: added, removed and changed (same key, other columns differ). */
export function diffList(baseText, headText, label = "list") {
  return diffEntries(parseList(baseText, `${label} (base)`), parseList(headText, `${label} (head)`));
}

/** Diff two `{ header, entries }` maps (key → cells): added, removed and changed. */
export function diffEntries(base, head) {
  const added = [...head.entries.keys()].filter((k) => !base.entries.has(k));
  const removed = [...base.entries.keys()].filter((k) => !head.entries.has(k));
  const changed = [...head.entries.keys()]
    .filter((k) => base.entries.has(k) && !sameCells(base.entries.get(k), head.entries.get(k)))
    .map((key) => ({ key, before: base.entries.get(key), after: head.entries.get(key) }));
  return {
    added: added.map((key) => ({ key, cells: head.entries.get(key) })),
    removed: removed.map((key) => ({ key, cells: base.entries.get(key) })),
    changed,
    headerChanged: !sameCells(base.header, head.header),
    baseHeader: base.header,
    headHeader: head.header,
  };
}

export function hasChanges(diff) {
  return diff.headerChanged || diff.added.length > 0 || diff.removed.length > 0 || diff.changed.length > 0;
}

/**
 * Compare every file of one group at `base` and `head`. `fetchFile(repo, path, ref)` must resolve
 * to the file text or reject; a rejection (a renamed or deleted upstream file) propagates — the
 * check fails loudly rather than reporting "no change".
 */
export async function compareGroup(group, base, head, fetchFile, listFiles, listDir) {
  if (base === head) return { group, base, head, lists: [] };
  if (group.kind === "rule-files") {
    if (typeof listDir !== "function") throw new Error(`${group.name}: a rule-files group needs listDir`);
    const diff = await diffRuleFiles(group, base, head, listDir);
    return { group, base, head, lists: [{ path: `${group.watchPath}/`, diff }] };
  }
  if (group.kind === "event-files") {
    if (typeof listFiles !== "function")
      throw new Error(`${group.name}: an event-files group needs listFiles`);
    const diff = await diffEventFiles(group, base, head, fetchFile, listFiles);
    return { group, base, head, lists: [{ path: `${group.watchPath}/`, diff }] };
  }
  const lists = [];
  for (const path of group.files) {
    const [baseText, headText] = await Promise.all([
      fetchFile(group.repo, path, base),
      fetchFile(group.repo, path, head),
    ]);
    lists.push({ path, diff: diffList(baseText, headText, path) });
  }
  return { group, base, head, lists };
}

// ── Event-file groups (TrailDiscover) ─────────────────────────────────────────────────────────
export const EVENT_HEADER = Object.freeze(["file", "event", "usedInWild", "mitre"]);

/** True for one entry file directly under `<watchPath>/<Service>/` — not the `.json.cloudtrail` samples. */
export function isEventFile(path, watchPath) {
  if (!path.startsWith(`${watchPath}/`)) return false;
  const rest = path.slice(watchPath.length + 1).split("/");
  return rest.length === 2 && rest[0] !== "" && /^[^/]+\.json$/.test(rest[1]);
}

const TECHNIQUE_ID = /^(T\d{4}(?:\.\d{3})?)\b/;
const techniqueIds = (values) =>
  (Array.isArray(values) ? values : []).map((v) => TECHNIQUE_ID.exec(String(v).trim())?.[1]).filter(Boolean);

/**
 * The fields of one event file the port used, as diff cells: the file, "<source> <eventName>",
 * "usedInWild=<bool>" and the sorted ATT&CK ids (techniques and sub-techniques). Throws on a file
 * that is not JSON or names no event — the check never reads a broken file as "no change".
 */
export function summariseEventFile(text, path) {
  let data;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error(`${path}: not valid JSON (${err instanceof Error ? err.message : String(err)})`);
  }
  if (
    !data ||
    typeof data !== "object" ||
    typeof data.eventName !== "string" ||
    typeof data.eventSource !== "string"
  ) {
    throw new Error(`${path}: no eventName / eventSource — refusing to treat it as an event`);
  }
  const ids = [
    ...new Set([...techniqueIds(data.mitreAttackTechniques), ...techniqueIds(data.mitreAttackSubTechniques)]),
  ].sort();
  return [
    path,
    `${data.eventSource.replace(/\.amazonaws\.com$/i, "")} ${data.eventName}`,
    `usedInWild=${data.usedInWild === true}`,
    `mitre=${ids.join(" ")}`,
  ];
}

/**
 * Diff the event files of one group between two commits. `listFiles(repo, dir, ref)` resolves to a
 * Map of path → blob sha for the files under `dir`. A file whose blob is the same at both commits is
 * not fetched (it cannot differ); every other event file is fetched and summarised.
 */
export async function diffEventFiles(group, base, head, fetchFile, listFiles) {
  const [baseFiles, headFiles] = await Promise.all(
    [base, head].map(async (ref) => {
      const all = await listFiles(group.repo, group.watchPath, ref);
      const events = new Map([...all].filter(([path]) => isEventFile(path, group.watchPath)));
      if (events.size === 0) {
        throw new Error(`${group.repo}@${ref}: no event files under "${group.watchPath}/" — was it moved?`);
      }
      return events;
    }),
  );
  const summarise = async (files, other, ref) => {
    const entries = new Map();
    const touched = [...files.keys()].filter((p) => other.get(p) !== files.get(p)).sort();
    for (const path of touched) {
      entries.set(path, summariseEventFile(await fetchFile(group.repo, path, ref), path));
    }
    return { header: [...EVENT_HEADER], entries };
  };
  return diffEntries(
    await summarise(baseFiles, headFiles, base),
    await summarise(headFiles, baseFiles, head),
  );
}

// ── Rule-file groups (Panther, Sentinel) ──────────────────────────────────────────────────────
export const RULE_FILE_HEADER = Object.freeze(["file", "content"]);

/**
 * Diff the files directly in one rule folder between two commits. `listDir(repo, dir, ref)` resolves
 * to a Map of path -> content hash (the blob sha) for the files in `dir`. An empty folder at either
 * commit throws — a moved folder never reads as "every rule removed".
 */
export async function diffRuleFiles(group, base, head, listDir) {
  const [baseFiles, headFiles] = await Promise.all(
    [base, head].map(async (ref) => {
      const files = await listDir(group.repo, group.watchPath, ref);
      if (!(files instanceof Map) || files.size === 0) {
        throw new Error(`${group.repo}@${ref}: no files in "${group.watchPath}/" — was it moved?`);
      }
      return files;
    }),
  );
  const entries = (files) =>
    new Map(
      [...files].sort(([a], [b]) => a.localeCompare(b)).map(([path, hash]) => [path, [path, String(hash)]]),
    );
  return diffEntries(
    { header: [...RULE_FILE_HEADER], entries: entries(baseFiles) },
    { header: [...RULE_FILE_HEADER], entries: entries(headFiles) },
  );
}

export function groupChanged(result) {
  return result.lists.some((list) => hasChanges(list.diff));
}

// ── Report rendering ──────────────────────────────────────────────────────────────────────────
// Upstream strings go into a GitHub issue. They sit inside fenced code blocks (no Markdown, no
// @-mentions, no #-references render there); a run of backticks is broken up so a value cannot end
// the fence early.
const MAX_BODY = 60_000;
const fenceSafe = (value) => String(value).replace(/`{3,}/g, (m) => m.split("").join("\u200b"));
const row = (cells) => fenceSafe(cells.join(" | "));
const short = (sha) => sha.slice(0, 7);

/** Stable title marker: the group and the RECORDED (base) commit — see the workflow comment. */
export function issueMarker(result) {
  return `[upstream-rules ${result.group.id}@${short(result.base)}]`;
}

export function issueTitle(results) {
  const changed = results.filter(groupChanged);
  const names = changed.map((r) => r.group.name).join(", ");
  return `Upstream rule lists changed: ${names} ${changed.map(issueMarker).join(" ")}`;
}

function renderList({ path, diff }) {
  if (!hasChanges(diff)) return [`#### ${path}`, "", "No change.", ""];
  const lines = [];
  if (diff.headerChanged) lines.push(`! columns: ${row(diff.baseHeader)}  ->  ${row(diff.headHeader)}`);
  for (const e of diff.added) lines.push(`+ ${row(e.cells)}`);
  for (const e of diff.removed) lines.push(`- ${row(e.cells)}`);
  for (const c of diff.changed) {
    lines.push(`- ${row(c.before)}`, `+ ${row(c.after)}`);
  }
  const counts = `${diff.added.length} added, ${diff.removed.length} removed, ${diff.changed.length} changed`;
  return [`#### ${path} — ${counts}`, "", "```diff", ...lines, "```", ""];
}

function renderGroup(result) {
  const { group, base, head } = result;
  return [
    `### ${group.name}`,
    "",
    `Commit range: \`${short(base)}\` (recorded in \`${markerFileOf(group)}\`) → \`${short(head)}\` (newest upstream commit touching \`${group.watchPath}\`).`,
    `Compare: https://github.com/${group.repo}/compare/${base}...${head}`,
    "",
    ...result.lists.flatMap(renderList),
  ];
}

/** The issue body. Never puts a closing keyword next to an issue number. */
export function renderReport(results) {
  const changed = results.filter(groupChanged);
  const body = [
    "The weekly upstream rule-list check found changes in upstream rules the Companion ports into `companion/data/tags.yaml` or bundles verbatim (`companion/data/sigma-suzaku`).",
    "",
    ...changed.flatMap(renderGroup),
    "### What to do",
    "",
    "- Port the changes with the same judgment as the original port: leave out entries an existing rule already covers, grade only what is clearly wrong at Info or Low, and check overlap with other rules.",
    "- A bundled-verbatim folder (Suzaku) is re-synced, not ported: copy the changed rule files as they are and re-run the detection-overlap check.",
    "- In the same PR, move the recorded upstream commit (in the file named in its commit range above) forward to the head commit above.",
    "- This issue is updated in place while the recorded commit stays the same. It is never acted on automatically.",
    "",
    "Generated by `.github/workflows/upstream-rules-check.yml` (relates to #2343).",
  ].join("\n");
  if (body.length <= MAX_BODY) return body;
  const cut = body.slice(0, MAX_BODY);
  const openFence = (cut.match(/^```/gm) ?? []).length % 2 === 1 ? "\n```" : "";
  return `${cut}${openFence}\n\n…truncated — run the workflow with dry-run for the full diff.`;
}
