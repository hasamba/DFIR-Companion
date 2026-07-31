// Accessibility violation ratchet.
//
// Same contract as check-file-size.mjs and check-imports.mjs, deliberately: the ledger only
// shrinks, --update records reductions, and --init is the one way a number rises — which makes an
// accessibility regression an arguable line in a diff rather than a silent slide.
//
// Reads a11y-results.json, written by tests/e2e/a11y/axe.spec.ts. Run the E2E suite first:
//
//   npm run test:e2e && npm run check:a11y
//   node scripts/check-a11y.mjs --update   # record reductions after fixing something
//   node scripts/check-a11y.mjs --init     # re-baseline; raises are printed, justify them
//
// The baseline is seeded at the REAL count, not zero. A ledger of zeros would make CI red on
// arrival, and a gate that is red on arrival gets switched off in a week; one seeded at today's
// number starts catching the NEXT regression immediately, which is the point.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const COMPANION = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const LEDGER = join(COMPANION, "scripts", "a11y-ledger.json");
const RESULTS = join(COMPANION, "a11y-results.json");

if (!existsSync(RESULTS)) {
  console.error("[a11y] no a11y-results.json — run `npm run test:e2e` first.");
  process.exit(1);
}

const results = JSON.parse(readFileSync(RESULTS, "utf8"));
const ledger = existsSync(LEDGER) ? JSON.parse(readFileSync(LEDGER, "utf8")) : {};

const init = process.argv.includes("--init");
const update = init || process.argv.includes("--update");

const raises = [];
const additions = [];
const missingScopes = [];

for (const scope of Object.keys(ledger)) {
  if (!(scope in results)) missingScopes.push(scope);
}

for (const [scope, rules] of Object.entries(results)) {
  for (const [rule, count] of Object.entries(rules)) {
    const before = ledger[scope]?.[rule];
    if (before === undefined) additions.push({ scope, rule, count });
    else if (count > before) raises.push({ scope, rule, from: before, to: count });
  }
}

if (update) {
  if (raises.length > 0 && !init) {
    console.error(`\n[a11y] refusing to update: ${raises.length} ledgered rule(s) got worse.`);
    for (const r of raises) console.error(`  ✖ ${r.scope} / ${r.rule}: ${r.from} -> ${r.to}`);
    console.error(
      "\n[a11y] The ledger only shrinks. Fix the violation, or — if this is a deliberate\n" +
        "[a11y] re-baseline — use `--init` and justify each raise in the PR.",
    );
    process.exit(1);
  }
  writeFileSync(LEDGER, `${JSON.stringify(results, null, 2)}\n`);
  for (const a of additions) console.log(`  + ${a.scope} / ${a.rule}: ${a.count}`);
  for (const r of raises) console.log(`  ↑ ${r.scope} / ${r.rule}: ${r.from} -> ${r.to}`);
  console.log(`[a11y] ledger written: ${LEDGER}`);
  process.exit(0);
}

// A scope that vanished is a scan that stopped running, which would otherwise read as "no
// violations" — the failure mode where a gate quietly stops gating.
if (missingScopes.length > 0) {
  console.error(`\n[a11y] ${missingScopes.length} ledgered scope(s) were not scanned at all:`);
  for (const s of missingScopes) console.error(`  ✖ ${s}`);
  console.error(
    "\n[a11y] A scope that stops being scanned looks identical to one with no\n[a11y] violations. Restore the scan in tests/e2e/a11y/axe.spec.ts.",
  );
  process.exit(1);
}

if (raises.length === 0 && additions.length === 0) {
  const total = Object.values(results).reduce(
    (sum, rules) => sum + Object.values(rules).reduce((a, b) => a + b, 0),
    0,
  );
  console.log(`[a11y] ok — ${Object.keys(results).length} scope(s), ${total} known violation(s), none new`);
  process.exit(0);
}

console.error("\n[a11y] accessibility regressed.\n");
for (const a of additions) console.error(`  ✖ NEW  ${a.scope} / ${a.rule}: ${a.count} node(s)`);
for (const r of raises) console.error(`  ✖ MORE ${r.scope} / ${r.rule}: ${r.from} -> ${r.to} node(s)`);
console.error(
  "\n[a11y] Each line is a rule that got worse on one scope. The offending nodes are in the\n" +
    "[a11y] Playwright report: companion/playwright-report/index.html\n" +
    "[a11y] If a fix genuinely IMPROVED things, run `npm run check:a11y -- --update`.\n",
);
process.exit(1);
