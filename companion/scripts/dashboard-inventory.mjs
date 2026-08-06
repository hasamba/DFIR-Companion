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
import prettier from "prettier";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

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
//
// THIS NUMBER IS NOT check:size's `#inline-js`, and the gap is not a bug in either. That ledger
// sums all five inline blocks (14,731 today); this covers only the big one, and counts whole lines
// between the tags rather than the partial lines the tags sit on — 14,541 against its 14,543. The
// other four blocks total 188 lines and are page bootstrap, not features: nothing to inventory.
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
const declEnd = new Map(); // name -> last line of its declaration, for the cohesion pass below
for (const st of sf.statements) {
  const line = lineOf(st.getStart(sf));
  const end = lineOf(st.getEnd());
  if (ts.isFunctionDeclaration(st) && st.name) {
    decls.set(st.name.text, { line, kind: "fn" });
    declEnd.set(st.name.text, end);
  } else if (ts.isVariableStatement(st)) {
    for (const d of st.declarationList.declarations) {
      if (ts.isIdentifier(d.name)) {
        decls.set(d.name.text, { line, kind: "var" });
        declEnd.set(d.name.text, end);
      }
    }
  }
}

// Identifier *references*: not the name in a declaration, not a property being accessed, not an
// object-literal key. Without those three exclusions `foo` in `{ foo: 1 }` and in `bar.foo` both
// read as references to a top-level `foo`, and nearly every block looks entangled.
const refs = [];
(function walk(node, inFn) {
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
      // `loadTime` means: evaluated as the page parses, with no function between here and the top.
      // `addEventListener("click", foo)` reads foo at load; `addEventListener("click", () => foo())`
      // does not. That distinction is the whole point of the flag, so the arrow counts as a
      // function even though it is not a declaration.
      refs.push({ name: node.text, line: lineOf(node.getStart(sf)), loadTime: !inFn });
    }
  }
  const opens =
    inFn ||
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessor(node) ||
    ts.isSetAccessor(node);
  node.forEachChild((c) => walk(c, opens));
})(sf, false);

// References from the ALREADY-EXTRACTED modules back into the inline script. Without these the
// inventory is blind in the one direction that breaks a live page: a sibling module calling a page
// function by bare name is not an identifier anywhere in the inline AST, so the name reads as
// block-local and the extraction would not publish it — and nothing in the unit suite would notice,
// because the call only happens in a browser. Eleven of the extracted modules already do this.
const siblingRefs = new Map(); // name -> count of references from public/js/*.js
{
  // Relative to the HTML file, not to this script: the modules live in js/ beside dashboard.html,
  // and resolving from the script's own path lands outside the repo whenever --html is used. The
  // first version did exactly that, found nothing anywhere, and looked correct because the headline
  // count did not move.
  const JS_DIR = new URL("./js/", HTML_PATH);
  let files = [];
  try {
    files = readdirSync(JS_DIR).filter((f) => f.endsWith(".js"));
  } catch {
    files = []; // --html pointed somewhere without a sibling js/ dir; only the tests do that
  }
  for (const f of files) {
    const src = readFileSync(new URL(f, JS_DIR), "utf8");
    const mod = ts.createSourceFile(f, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    (function walkMod(node) {
      if (ts.isIdentifier(node)) {
        const par = node.parent;
        const isMember = ts.isPropertyAccessExpression(par) && par.name === node;
        const isKey = (ts.isPropertyAssignment(par) || ts.isMethodDeclaration(par)) && par.name === node;
        if (!isMember && !isKey && decls.has(node.text)) {
          siblingRefs.set(node.text, (siblingRefs.get(node.text) ?? 0) + 1);
        }
      }
      node.forEachChild(walkMod);
    })(mod);
  }
}

// Guard stanzas left behind by EARLIER extractions. When a feature moves out, three or four lines
// replace it — `if (typeof initX !== "undefined") initX(); else dfirFeatureUnavailable("…")` — and
// those lines sit between two banner comments, so the inventory files them under whichever section
// happens to enclose them. They are not part of that feature and must not travel with it.
//
// This is not hypothetical: the NSRL block's range ended with six lines belonging to the Settings →
// Tools extraction, and copying the range wholesale put a call to the page's dfirFeatureUnavailable
// inside a module, where it is not defined. The module suite caught it, but only after the fact.
//
// Detected structurally rather than by text: an `if` whose condition tests `typeof NAME` for a NAME
// that one of the extracted modules publishes.
//
// BOTH IDIOMS, because the file uses both and matching only one is worse than matching neither. The
// first version required the literal `undefined`, so it missed
// `if (typeof initTicketIntegrations === "function")` — and that stanza was inside the very next
// block extracted, went into the module, and stopped the ticket integrations initialising at all.
// Silently: the page was fine, the feature simply never started. The lifecycle suite caught it.
const publishedByModules = new Set();
for (const [name] of siblingRefs) publishedByModules.add(name);
{
  const JS_DIR = new URL("./js/", HTML_PATH);
  let files = [];
  try {
    files = readdirSync(JS_DIR).filter((f) => f.endsWith(".js"));
  } catch {
    files = [];
  }
  for (const f of files) {
    for (const m of readFileSync(new URL(f, JS_DIR), "utf8").matchAll(/window\.(\w+)\s*=/g)) {
      publishedByModules.add(m[1]);
    }
  }
}
const foreignStanzaLines = new Map(); // first line -> the guarded name
for (const st of sf.statements) {
  if (!ts.isIfStatement(st)) continue;
  const cond = st.expression.getText(sf);
  const m = /typeof\s+(\w+)\s*[!=]==?\s*["'](?:undefined|function)["']/.exec(cond);
  if (m && publishedByModules.has(m[1])) foreignStanzaLines.set(lineOf(st.getStart(sf)), m[1]);
}

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

  const escaped = new Map(); // name -> how many reference sites outside this section
  // Names this block declares that some OTHER top-level statement reads as the page loads. These
  // are controls bound from somewhere else — the page's shared modal-wiring block does this for
  // every modal — and they are the reason `moduleScopeDom: 0` does not mean "no initializer
  // needed". Two extractions in a row scored zero here and still needed one; the block wires
  // nothing, but something wires the block, and moving the functions out turns those into bare
  // references evaluated at load. A 404 then throws before the WebSocket connects.
  const boundElsewhere = new Set();
  for (const r of refs) {
    if (!ownNames.has(r.name) || inSection(r.line)) continue;
    escaped.set(r.name, (escaped.get(r.name) ?? 0) + 1);
    if (r.loadTime) boundElsewhere.add(r.name);
  }
  // A sibling module referencing one of this block's names counts exactly like an inline reference
  // from outside the block: the name has to be published, or the state does not travel.
  for (const [name, count] of siblingRefs) {
    if (ownNames.has(name)) escaped.set(name, (escaped.get(name) ?? 0) + count);
  }
  const publish = [...escaped.keys()].filter((n) => decls.get(n).kind === "fn");
  const stateEscapes = [...escaped.keys()].filter((n) => decls.get(n).kind === "var");

  // CORE MACHINERY IS NOT A FEATURE, and cohesion cannot tell the difference — so it is named
  // instead of inferred. A section that declares any of these owns the page's own spine: the
  // case-load path, the state save every `if (DfirState.lastState()) render(...)` refresh depends
  // on, or the render entry points themselves. Extracting one takes the refresh fan-out with it.
  //
  // This list is short and explicit on purpose. It was learned the expensive way: the "Cross-case
  // capture warning" block reports as ONE cohesive cluster of 24 with three cleanly-fixable state
  // escapes, passes every other filter here, and is the page's connect() path. Two lifecycle gates
  // caught the extraction; nothing in this file did.
  const CORE_MACHINERY = new Set([
    "connect",
    "proceedConnect",
    "render",
    "renderIocs",
    "setLastState",
    "dfirFeatureUnavailable",
  ]);

  // How hard the most-called published function is pulled on from outside. A feature's own entry
  // points have a handful of external callers; shared machinery has dozens. This is the check on
  // the boundaries themselves: banner comments are the author's grouping, not a guarantee that
  // everything under one banner belongs to that feature. `render()` is declared inside the "Now
  // investigator cockpit" banner and has 22 call sites across the page — extracting that section as
  // written would move the page's central render function into a feature module. A high number here
  // means read the block before believing its size.
  const fanout = Math.max(0, ...publish.map((n) => escaped.get(n)));
  const shared = publish.filter((n) => escaped.get(n) >= 10).sort();

  let dom = 0;
  for (const [line, hits] of domByLine) if (inSection(line)) dom += hits;

  // COHESION: does this block hold one feature, or several that share a banner? Three sections in a
  // row turned out to be two features under a heading naming only one — the Settings block is three
  // panels, the Sigma block is Sigma plus the hunt modal, and "Push ingest token" heads 222 lines of
  // which 47 are the push token and the rest are the Velociraptor bundle builder above it.
  // Extracting to the banner in that last case would have cut a live feature in half.
  //
  // Measured as connected components over the block's OWN declarations: two functions are joined if
  // either references the other. Functions that never touch each other are not one feature, whatever
  // comment sits above them. This is a reading prompt, not a verdict — a real feature can have a
  // genuinely standalone helper — but a block reporting three components deserves a look before its
  // line range is trusted.
  const ownArr = own.map(([n]) => n);
  const coreMachinery = ownArr.filter((n) => CORE_MACHINERY.has(n)).sort();

  // A section can be core machinery without declaring any of those NAMES. The 397-line block under
  // the "Theme picker" banner declares ws, SEV, aiEnabled, lastIocs, tlPage, iocPage, timelineSort
  // and twenty more — the page's central state — and not one core FUNCTION, so the name list above
  // waves it through as a 397-line feature worth extracting. It is not a feature. It is the state
  // every feature reads, filed under whichever banner happened to be above it.
  //
  // The signal is the escape count itself. A real feature keeps its state to itself and escapes in
  // ones and twos; the three answers (accessor on the owner / ownership follows use / the
  // declaration was in the wrong file) all assume a handful. Past roughly a dozen, "escape" is the
  // wrong word — nothing escaped, the section simply IS the page's state, and the work to do is to
  // find each binding's real owner, not to lift the block.
  const STATE_HUB_ESCAPES = 12;
  const isStateHub = stateEscapes.length >= STATE_HUB_ESCAPES;
  const idx = new Map(ownArr.map((n, i) => [n, i]));
  const parent = ownArr.map((_, i) => i);
  const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const union = (a, b) => {
    const ra = find(a),
      rb = find(b);
    if (ra !== rb) parent[ra] = rb;
  };
  for (const [name, d] of own) {
    // Every reference inside this declaration's own line span to another of the block's names.
    const end = declEnd.get(name) ?? d.line;
    for (const r of refs) {
      if (r.line < d.line || r.line > end) continue;
      if (r.name === name || !idx.has(r.name)) continue;
      union(idx.get(name), idx.get(r.name));
    }
  }
  const components = new Map();
  ownArr.forEach((n, i) => {
    const root = find(i);
    components.set(root, (components.get(root) ?? 0) + 1);
  });
  // Singletons are usually noise — a lone lookup table is not a second feature — but a lone
  // FUNCTION of any size is one, and dropping every singleton made the check miss its first real
  // case: `doAsk`, the AI Ask box, sat under the "Import undo / redo (#76)" banner referencing
  // nothing around it and referenced by nothing in the block. Forty-four lines, its own controls,
  // its own Settings wiring, and the check called the block cohesive.
  //
  // So a singleton counts when its declaration spans enough lines to be a feature rather than a
  // constant. Ten is the line that separates every lookup table in this file from every function.
  const SINGLETON_MIN_LINES = 10;
  const sizeOfDecl = (name) => (declEnd.get(name) ?? decls.get(name).line) - decls.get(name).line + 1;
  const membersOf = new Map();
  ownArr.forEach((n, i) => {
    const root = find(i);
    if (!membersOf.has(root)) membersOf.set(root, []);
    membersOf.get(root).push(n);
  });
  const clusters = [...membersOf.values()]
    .filter((names) => names.length >= 2 || sizeOfDecl(names[0]) >= SINGLETON_MIN_LINES)
    .map((names) => names.length)
    .sort((a, b) => b - a);

  return {
    label: sec.label,
    start: sec.line,
    end: sec.end,
    size: sec.end - sec.line + 1,
    functions: own.filter(([, d]) => d.kind === "fn").length,
    stateBindings: own.filter(([, d]) => d.kind === "var").length,
    publish: publish.sort(),
    stateEscapes: stateEscapes.sort(),
    maxFanout: fanout,
    sharedMachinery: shared,
    moduleScopeDom: dom,
    // Lines in this range that belong to an already-extracted feature, not to this one. Subtract
    // them before copying the range out.
    foreignStanzas: [...foreignStanzaLines]
      .filter(([line]) => inSection(line))
      .map(([line, name]) => `${line} ${name}`),
    coreMachinery,
    isStateHub,
    isCoreMachinery: coreMachinery.length > 0 || isStateHub,
    boundElsewhere: [...boundElsewhere].sort(),
    needsInitializer: dom > 0 || boundElsewhere.size > 0,
    clusters,
    looksLikeTwoFeatures: clusters.length > 1,
  };
});

const covered = rows.reduce((n, r) => n + r.size, 0);
const inlineSize = END - START - 1;
const report = {
  // Regenerate with `npm run inventory:dashboard -- --update`. Do not hand-edit: the point of this
  // file is that it cannot drift from the code the way a hand-kept list of features would.
  inlineScript: { start: START + 2, end: END, lines: inlineSize },
  covered,
  // Ready means both: the state travels with the feature, AND the block is not holding a function
  // the rest of the page leans on. Either one alone overstates it.
  ready: rows.filter((r) => r.stateEscapes.length === 0 && r.sharedMachinery.length === 0).length,
  readyLines: rows
    .filter((r) => r.stateEscapes.length === 0 && r.sharedMachinery.length === 0)
    .reduce((n, r) => n + r.size, 0),
  sections: rows,
};

if (process.argv.includes("--update")) {
  // Written through prettier, not JSON.stringify alone. format:check covers this artifact, and
  // prettier's JSON printer keeps short arrays on one line where JSON.stringify never does — so a
  // raw dump lands the branch a red CI, and running `npm run format` to fix it leaves a file that
  // goes red again the next time anyone regenerates. Formatting here makes the two agree forever.
  const raw = JSON.stringify(report, null, 2) + "\n";
  const options = (await prettier.resolveConfig(JSON_PATH.pathname)) ?? {};
  writeFileSync(
    JSON_PATH,
    await prettier.format(raw, { ...options, parser: "json", filepath: JSON_PATH.pathname }),
  );
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
  console.log(" size  fns   st  esc  dom  fan init range           feature");
  for (const r of [...rows].sort((a, b) => b.size - a.size)) {
    console.log(
      `${pad(r.size, 5)} ${pad(r.functions, 4)} ${pad(r.stateBindings, 4)} ` +
        `${pad(r.stateEscapes.length, 4)} ${pad(r.moduleScopeDom, 4)} ${pad(r.maxFanout, 4)} ` +
        `${r.needsInitializer ? "yes " : "  . "}` +
        `${`${r.start}-${r.end}`.padEnd(14)}  ${r.label.slice(0, 56)}`,
    );
  }
  console.log(
    "\nesc = state bindings read from outside the block (the blocker). Functions called from " +
      "outside\nare not counted: an extracted module publishes those onto `window`.\n" +
      "dom = DOM access at module scope, so the block needs its wiring wrapped in an initializer.\n" +
      "core = the section declares one of the page's own spine functions (connect, render, the " +
      "state save).\nIt is not a feature; extracting it takes the refresh fan-out with it.\n" +
      "fan = external call sites of its most-used function. Dozens means the block is holding " +
      "shared\nmachinery that a banner comment happened to enclose — read it before trusting its size.",
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
