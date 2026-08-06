#!/usr/bin/env node
// The inventory of what is still inside dashboard.html's inline script (#415 item 2).
//
// #415's own note says the first task is to produce this, "not an extraction": six features have
// been extracted by picking a likely-looking block and measuring it by hand, and at that rate the
// issue budgets ~30 more PRs with no list of what those PRs are. This produces the list.
//
// Run `node scripts/dashboard-inventory.mjs` for the table, `--json` for the raw rows, `--update`
// to refresh scripts/dashboard-inventory.json.
//
// TWO MEASUREMENTS DECIDE WHETHER A BLOCK IS READY, and both are easy to get wrong:
//
//   1. State escapes, NOT escapes. A *function* referenced from outside its block is the ordinary
//      case — the extracted module publishes it onto `window` and every call site is unchanged. A
//      mutable *binding* read from outside is the blocker, because it means the state does not
//      travel with the feature. Counted together they mis-rank the list badly: "Event-density
//      heatmap" looks like it has three escapes and is in fact ready, because all three are
//      functions.
//
//   2. Read the AST, not the text. Both blocks measured by hand before this script existed had
//      apparent escapes that were a mention inside a comment and an HTML id attribute. Grep says
//      "blocked" for blocks that are clean.
//
// Module-scope DOM access is reported too, because it decides the SHAPE of the extraction rather
// than whether it can happen: an extracted module is a <head> script, so wiring that runs at module
// scope would query its elements before they exist and wire nothing, silently. Any block with a
// non-zero `dom` count needs its wiring wrapped in an init function the page calls behind a guard.
import ts from "typescript";
import { readFileSync, writeFileSync } from "node:fs";

// `--html <path>` exists so the coverage guard below can be tested against a deliberately broken
// dashboard. A guard nobody has watched fail is not a guard.
const htmlArg = process.argv.indexOf("--html");
const HTML_PATH =
  htmlArg !== -1 && process.argv[htmlArg + 1]
    ? new URL(process.argv[htmlArg + 1], `file://${process.cwd()}/`)
    : new URL("../../public/dashboard.html", import.meta.url);
const JSON_PATH = new URL("./dashboard-inventory.json", import.meta.url);

const lines = readFileSync(HTML_PATH, "utf8").split("\n");

// The inline block is the longest <script> with no src=. Located rather than hard-coded: it has
// moved every time a feature left it.
let bounds = null;
for (let i = 0; i < lines.length; i++) {
  if (!/<script(?![^>]*\ssrc=)/.test(lines[i])) continue;
  for (let j = i + 1; j < lines.length; j++) {
    if (lines[j].includes("</script>")) {
      if (!bounds || j - i > bounds[1] - bounds[0]) bounds = [i, j];
      break;
    }
  }
}
if (!bounds) {
  console.error("[inventory] no inline <script> found in public/dashboard.html");
  process.exit(1);
}
const [START, END] = bounds;
const code = lines.slice(START + 1, END).join("\n");
const sf = ts.createSourceFile("inline.js", code, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
const lineOf = (pos) => code.slice(0, pos).split("\n").length + START + 1;

// The file's own banner comments are the section boundaries. They are the author's grouping, and
// every extraction so far has followed one, so the inventory should not invent a different one.
const banners = [];
for (let i = START + 1; i < END; i++) {
  const raw = lines[i];
  const isBanner =
    /^\s*\/\/\s*[-─—=]{3,}/.test(raw) || /^\s*\/\/\s*[-─—]{2,}\s*\S/.test(raw) || /\/\/\s*[─]{2,}/.test(raw);
  if (!isBanner) continue;
  const label = raw
    .replace(/^\s*\/\/\s*/, "")
    .replace(/[-─—=]{2,}/g, "")
    .trim();
  if (label) banners.push({ line: i + 1, label });
}
const sections = banners.map((b, i) => ({
  ...b,
  end: i + 1 < banners.length ? banners[i + 1].line - 1 : END,
}));

// Top-level declarations only. A nested one cannot be referenced from another section anyway, so
// including it would inflate every count.
const decls = new Map();
for (const st of sf.statements) {
  const line = lineOf(st.getStart(sf));
  if (ts.isFunctionDeclaration(st) && st.name) decls.set(st.name.text, { line, kind: "fn" });
  else if (ts.isVariableStatement(st)) {
    for (const d of st.declarationList.declarations) {
      if (ts.isIdentifier(d.name)) decls.set(d.name.text, { line, kind: "var" });
    }
  }
}

// Identifier *references*: not the name in a declaration, not a property being accessed, not an
// object-literal key. Without those three exclusions `foo` in `{ foo: 1 }` and in `bar.foo` both
// read as references to a top-level `foo`, and nearly every block looks entangled.
const refs = [];
(function walk(node) {
  if (ts.isIdentifier(node)) {
    const p = node.parent;
    const isDeclName =
      (ts.isFunctionDeclaration(p) ||
        ts.isVariableDeclaration(p) ||
        ts.isParameter(p) ||
        ts.isFunctionExpression(p) ||
        ts.isClassDeclaration(p)) &&
      p.name === node;
    const isMember = ts.isPropertyAccessExpression(p) && p.name === node;
    const isKey = (ts.isPropertyAssignment(p) || ts.isMethodDeclaration(p)) && p.name === node;
    if (!isDeclName && !isMember && !isKey) {
      refs.push({ name: node.text, line: lineOf(node.getStart(sf)) });
    }
  }
  node.forEachChild(walk);
})(sf);

// Statements that touch the DOM outside any function — the wiring that needs an initializer.
const domByLine = new Map();
for (const st of sf.statements) {
  if (ts.isFunctionDeclaration(st)) continue;
  const hits = (st.getText(sf).match(/document\.(getElementById|querySelector|querySelectorAll)\(/g) || [])
    .length;
  if (hits) domByLine.set(lineOf(st.getStart(sf)), hits);
}

const rows = sections.map((sec) => {
  const inSection = (line) => line >= sec.line && line <= sec.end;
  const own = [...decls.entries()].filter(([, d]) => inSection(d.line));
  const ownNames = new Set(own.map(([n]) => n));

  const escaped = new Set();
  for (const r of refs) {
    if (ownNames.has(r.name) && !inSection(r.line)) escaped.add(r.name);
  }
  const publish = [...escaped].filter((n) => decls.get(n).kind === "fn");
  const stateEscapes = [...escaped].filter((n) => decls.get(n).kind === "var");

  let dom = 0;
  for (const [line, hits] of domByLine) if (inSection(line)) dom += hits;

  return {
    label: sec.label,
    start: sec.line,
    end: sec.end,
    size: sec.end - sec.line + 1,
    functions: own.filter(([, d]) => d.kind === "fn").length,
    stateBindings: own.filter(([, d]) => d.kind === "var").length,
    publish: publish.sort(),
    stateEscapes: stateEscapes.sort(),
    moduleScopeDom: dom,
  };
});

const covered = rows.reduce((n, r) => n + r.size, 0);
const inlineSize = END - START - 1;
const report = {
  // Regenerate with `npm run inventory:dashboard -- --update`. Do not hand-edit: the point of this
  // file is that it cannot drift from the code the way a hand-kept list of features would.
  inlineScript: { start: START + 2, end: END, lines: inlineSize },
  covered,
  ready: rows.filter((r) => r.stateEscapes.length === 0).length,
  readyLines: rows.filter((r) => r.stateEscapes.length === 0).reduce((n, r) => n + r.size, 0),
  sections: rows,
};

if (process.argv.includes("--update")) {
  writeFileSync(JSON_PATH, JSON.stringify(report, null, 2) + "\n");
  console.log(`[inventory] wrote ${rows.length} sections to scripts/dashboard-inventory.json`);
} else if (process.argv.includes("--json")) {
  console.log(JSON.stringify(report, null, 2));
} else {
  const pad = (s, n) => String(s).padStart(n);
  console.log(
    `[inventory] inline script: ${inlineSize} lines in ${rows.length} sections ` +
      `(${covered} covered)\n` +
      `[inventory] ready to extract (no state escapes): ${report.ready} sections, ` +
      `${report.readyLines} lines\n`,
  );
  console.log(" size  fns   st  esc  dom  range           feature");
  for (const r of [...rows].sort((a, b) => b.size - a.size)) {
    console.log(
      `${pad(r.size, 5)} ${pad(r.functions, 4)} ${pad(r.stateBindings, 4)} ` +
        `${pad(r.stateEscapes.length, 4)} ${pad(r.moduleScopeDom, 4)}  ` +
        `${`${r.start}-${r.end}`.padEnd(14)}  ${r.label.slice(0, 56)}`,
    );
  }
  console.log(
    "\nesc = state bindings read from outside the block (the blocker). Functions called from " +
      "outside\nare not counted: an extracted module publishes those onto `window`.\n" +
      "dom = DOM access at module scope, so the block needs its wiring wrapped in an initializer.",
  );
}

// Coverage is the one invariant worth failing on: the sections must account for every line of the
// inline script. If they do not, a feature exists that this inventory cannot see, which is the
// exact failure the issue is complaining about.
if (covered !== inlineSize) {
  console.error(
    `[inventory] FAIL: sections cover ${covered} lines but the inline script is ${inlineSize}. ` +
      `A block sits outside every banner comment and is invisible to this inventory.`,
  );
  process.exit(1);
}
