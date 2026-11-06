/**
 * Pure logic for the weekly upstream rule-list check (#2343).
 *
 * Some built-in tagger rules in data/tags.yaml are HAND-PORTED from upstream lists — today the
 * five Microsoft-Analyzer-Suite blacklists (#2306). A port is a judgment call (what to leave out,
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
 * Adding a source (the AWS/GCP ports, #2345/#2346): append one entry to UPSTREAM_GROUPS and put a
 * matching "<marker>: <sha> (<date>)" line in that port's tags.yaml header.
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
]);

/** Read the recorded port commit for one group from the tags.yaml text, or throw. */
export function readRecordedCommit(tagsYaml, marker) {
  const match = recordedCommitPattern(marker).exec(tagsYaml);
  if (!match) {
    throw new Error(
      `tags.yaml has no "# ${marker}: <40-hex sha> (<YYYY-MM-DD>)" line — the check cannot know which upstream commit the port came from.`,
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
  const base = parseList(baseText, `${label} (base)`);
  const head = parseList(headText, `${label} (head)`);
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
export async function compareGroup(group, base, head, fetchFile) {
  if (base === head) return { group, base, head, lists: [] };
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
    `Commit range: \`${short(base)}\` (recorded in tags.yaml) → \`${short(head)}\` (newest upstream commit touching \`${group.watchPath}\`).`,
    `Compare: https://github.com/${group.repo}/compare/${base}...${head}`,
    "",
    ...result.lists.flatMap(renderList),
  ];
}

/** The issue body. Never puts a closing keyword next to an issue number. */
export function renderReport(results) {
  const changed = results.filter(groupChanged);
  const body = [
    "The weekly upstream rule-list check found changes in lists that are hand-ported into `companion/data/tags.yaml`.",
    "",
    ...changed.flatMap(renderGroup),
    "### What to do",
    "",
    "- Port the changes with the same judgment as the original port: leave out entries an existing rule already covers, grade only what is clearly wrong at Info or Low, and check overlap with other rules.",
    "- In the same PR, move the recorded upstream commit in the tags.yaml header forward to the head commit above.",
    "- This issue is updated in place while the recorded commit stays the same. It is never acted on automatically.",
    "",
    "Generated by `.github/workflows/upstream-rules-check.yml` (relates to #2343).",
  ].join("\n");
  if (body.length <= MAX_BODY) return body;
  const cut = body.slice(0, MAX_BODY);
  const openFence = (cut.match(/^```/gm) ?? []).length % 2 === 1 ? "\n```" : "";
  return `${cut}${openFence}\n\n…truncated — run the workflow with dry-run for the full diff.`;
}
