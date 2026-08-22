#!/usr/bin/env node
// Split one section of dashboard.html's inline script into "declarations" and "runs at load".
//
// WHY THIS EXISTS. Every tier-3 extraction has the same shape: the declarations become the module
// body, and anything that executes at module scope becomes its initializer, because an extracted
// module is a <head> script and DOM work there runs before the markup exists — binding nothing, with
// no error anywhere.
//
// Getting that split right by eye is where the mistakes are. Searching for lines that begin
// `document.` found three of the six load-time statements in the Settings → Tools block; the other
// three were bare `{ … }` blocks scoping a `const b` around one button, and shipping them in the
// module body would have left #ctAddBtn, #mcpAddBtn and #mcpDiscoverBtn permanently dead. A parser
// does not care what a statement looks like.
//
//   node scripts/dashboard-section-split.mjs <startLine> <endLine>
//
// Prints the two line ranges, and `--json` gives them as data for a script to consume. Line numbers
// come from `npm run inventory:dashboard`.
import ts from "typescript";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const asJson = args.includes("--json");
const htmlArg = args.indexOf("--html");
// Native paths, not URLs — see the note in dashboard-inventory.mjs. An absolute Windows argument
// makes `new URL()` read the drive letter as a scheme and throw ERR_INVALID_URL_SCHEME.
const HTML_PATH =
  htmlArg !== -1 && args[htmlArg + 1]
    ? resolve(args[htmlArg + 1])
    : fileURLToPath(new URL("../../public/dashboard.html", import.meta.url));
const positional = args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--html");
const [FROM, TO] = positional.map(Number);
if (!Number.isInteger(FROM) || !Number.isInteger(TO) || FROM > TO) {
  console.error("usage: dashboard-section-split.mjs <startLine> <endLine> [--json] [--html PATH]");
  process.exit(2);
}

const lines = readFileSync(HTML_PATH, "utf8").split("\n");
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
  console.error("[split] no inline <script> found");
  process.exit(1);
}
const [START, END] = bounds;
const code = lines.slice(START + 1, END).join("\n");
const sf = ts.createSourceFile("inline.js", code, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
const lineOf = (pos) => code.slice(0, pos).split("\n").length + START + 1;

const declarations = [];
const runsAtLoad = [];
// A declaration whose initializer touches the DOM is not safely a declaration. `const overlay =
// document.getElementById("importCaseOverlay")` reads as one to "is this a VariableStatement", and
// in a <head> script it evaluates to null before the markup exists — every later use of it then
// throws or silently does nothing. It has to be split: the binding stays, the lookup moves into the
// initializer, or the whole thing does. Reported separately rather than guessed at.
const domInDeclaration = [];
for (const st of sf.statements) {
  const from = lineOf(st.getStart(sf));
  if (from < FROM || from > TO) continue;
  const range = [from, lineOf(st.getEnd())];
  // A function or variable declaration defines something; everything else at this level DOES
  // something, the moment the script is parsed. That is the whole distinction — deliberately not
  // "does it mention the DOM", which both misses a wrapper block and would miss a timer or a fetch
  // kicked off at load.
  if (ts.isFunctionDeclaration(st) || ts.isVariableStatement(st)) {
    declarations.push(range);
    if (
      ts.isVariableStatement(st) &&
      /document\.(getElementById|querySelector|querySelectorAll)\(/.test(st.getText(sf))
    ) {
      domInDeclaration.push(range);
    }
  } else runsAtLoad.push(range);
}

// A statement that starts inside the range and ends past it means the range cuts it in half, and
// copying those lines out produces JavaScript that does not parse. It happens for a mundane reason:
// line numbers go stale the moment another feature is extracted, and the inventory is regenerated
// per extraction. Refuse rather than hand back a range that silently truncates.
// Guard stanzas belonging to ALREADY-EXTRACTED features. `if (typeof initX !== "undefined") initX();
// else dfirFeatureUnavailable("…")` is what an extraction leaves behind, and those two lines sit
// between banner comments, so a section's line range can enclose one that is not its own. Copying
// the range out then takes another feature's initializer with it — the feature simply stops being
// initialised, with no error, no failing unit test and nothing on screen to notice.
//
// This has happened twice: initHostRanking, swallowed by the IOC-provenance range, and initDataAct
// by the collapsible range. Both were caught by a lifecycle gate AFTER the module was written, and
// only because that gate exists. Refuse here instead.
const foreign = [];
for (let i = FROM; i <= TO; i++) {
  // BOTH guard forms. The page uses `!== "undefined"` and `=== "function"` interchangeably, and a
  // detector that knows only one is worse than none — it reports clean and you trust it. Matching
  // only `!== "undefined"` is the exact bug that let a ticket-integrations stanza travel into a
  // module earlier in #415, and it let initHypotheses through here on the first try.
  const m = /typeof\s+(init[A-Za-z0-9_]*)\s*(?:!==\s*"undefined"|===\s*"function")/.exec(lines[i - 1] || "");
  if (m) foreign.push(`${i} ${m[1]}`);
}
if (foreign.length) {
  console.error(
    `[split] REFUSING: ${foreign.length} guard stanza(s) inside ${FROM}-${TO} initialise OTHER ` +
      `features (${foreign.join(", ")}). They were left behind by earlier extractions and are not ` +
      `part of this block. Move them out of the range first, or exclude those lines — taking one ` +
      `into a module silently stops that feature initialising.`,
  );
  process.exit(1);
}

const straddling = [...declarations, ...runsAtLoad].filter((r) => r[1] > TO);
if (straddling.length) {
  console.error(
    `[split] REFUSING: ${straddling.length} statement(s) start inside ${FROM}-${TO} and end past it ` +
      `(${straddling.map((r) => `${r[0]}-${r[1]}`).join(", ")}). Either the end line is wrong or the ` +
      `numbers are stale — re-run \`npm run inventory:dashboard\` and use its current ranges.`,
  );
  process.exit(1);
}

if (asJson) {
  console.log(JSON.stringify({ declarations, runsAtLoad, domInDeclaration }, null, 2));
} else {
  const span = (r) => (r[0] === r[1] ? `${r[0]}` : `${r[0]}-${r[1]}`);
  const count = (rs) => rs.reduce((n, r) => n + (r[1] - r[0] + 1), 0);
  console.log(`[split] lines ${FROM}-${TO} of the inline script\n`);
  console.log(
    `declarations — the module body (${declarations.length} statements, ${count(declarations)} lines)`,
  );
  console.log(`  ${declarations.map(span).join("  ") || "(none)"}\n`);
  console.log(`runs at load — the initializer (${runsAtLoad.length} statements, ${count(runsAtLoad)} lines)`);
  console.log(`  ${runsAtLoad.map(span).join("  ") || "(none)"}`);
  for (const r of runsAtLoad) {
    console.log(`\n  ${span(r)}: ${lines[r[0] - 1].trim().slice(0, 92)}`);
  }
  if (domInDeclaration.length) {
    console.log(`\nCAREFUL — ${domInDeclaration.length} declaration(s) read the DOM while the page loads:`);
    for (const r of domInDeclaration) {
      console.log(`  ${span(r)}: ${lines[r[0] - 1].trim().slice(0, 88)}`);
    }
    console.log(
      "  These look like module body and are not. In a <head> script the lookup returns null before\n" +
        "  the markup exists. Move the lookup into the initializer, or the whole statement.",
    );
  }
  if (!runsAtLoad.length) {
    console.log("\n  Nothing runs at load, so this block needs no initializer of its own — but check");
    console.log("  `boundElsewhere` in the inventory before concluding it needs none at all.");
  }
}
