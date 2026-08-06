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

const args = process.argv.slice(2);
const asJson = args.includes("--json");
const htmlArg = args.indexOf("--html");
const HTML_PATH =
  htmlArg !== -1 && args[htmlArg + 1]
    ? new URL(args[htmlArg + 1], `file://${process.cwd()}/`)
    : new URL("../../public/dashboard.html", import.meta.url);
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
for (const st of sf.statements) {
  const from = lineOf(st.getStart(sf));
  if (from < FROM || from > TO) continue;
  const range = [from, lineOf(st.getEnd())];
  // A function or variable declaration defines something; everything else at this level DOES
  // something, the moment the script is parsed. That is the whole distinction — deliberately not
  // "does it mention the DOM", which both misses a wrapper block and would miss a timer or a fetch
  // kicked off at load.
  if (ts.isFunctionDeclaration(st) || ts.isVariableStatement(st)) declarations.push(range);
  else runsAtLoad.push(range);
}

// A statement that starts inside the range and ends past it means the range cuts it in half, and
// copying those lines out produces JavaScript that does not parse. It happens for a mundane reason:
// line numbers go stale the moment another feature is extracted, and the inventory is regenerated
// per extraction. Refuse rather than hand back a range that silently truncates.
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
  console.log(JSON.stringify({ declarations, runsAtLoad }, null, 2));
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
  if (!runsAtLoad.length) {
    console.log("\n  Nothing runs at load, so this block needs no initializer of its own — but check");
    console.log("  `boundElsewhere` in the inventory before concluding it needs none at all.");
  }
}
