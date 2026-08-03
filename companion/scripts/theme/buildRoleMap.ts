// Resolves every `--c-<hex>` variable in the dashboard's client source to a semantic role and
// writes scripts/theme/role-map.json, then prints a collapse audit. Since #415 that source is two
// files — public/css/dashboard.css and public/dashboard.html — read as one corpus; see THEME_SOURCES.
//
//   npm run theme:map          write role-map.json + print the audit
//   npm run theme:map -- --check   audit only, non-zero exit if anything is unassigned
//
// The audit matters more than the map. Collapsing 149 colours onto ~45 roles is lossy
// by construction, and the useful question is *where* it is lossy: a role whose member
// hexes span a wide lightness range is a place where the UI currently draws a
// distinction the semantic layer would erase. Those need a role split, not a shrug.

import { writeFileSync } from "node:fs";
import { loadBaseline, ROLE_MAP_PATH as OUT, THEME_SOURCES } from "./loadBaseline.js";
import { isThemeInvariant, readPaletteFacts } from "./paletteFacts.js";
import { assignRoles, type RoleAssignment, TIER_B } from "./roleMap.js";

/** Lightness spread beyond which a merge is assumed to erase a real visual step. */
const SPREAD_LIMIT = 12;

/** How much further apart light values may sit than dark ones before it is suspicious. */
const LIGHT_DIVERGENCE_LIMIT = 20;

/** Straight-line distance in sRGB. Crude, but the right order of magnitude for a flag. */
function rgbDistance(a: string, b: string): number {
  const rgb = (h: string) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
  const [p, q] = [rgb(a), rgb(b)];
  if (p.some(Number.isNaN) || q.some(Number.isNaN)) return 0;
  return Math.round(Math.sqrt(p.reduce((s, v, i) => s + (v - q[i]) ** 2, 0)));
}

function main() {
  const check = process.argv.includes("--check");
  const baseline = loadBaseline();
  const facts = readPaletteFacts(THEME_SOURCES, baseline);
  const map = assignRoles(facts, baseline);

  // A theme-invariant variable that got a themed role would start shifting per theme.
  const misfiled = facts.filter((f) => isThemeInvariant(f) && map[f.name].tier !== "C");
  const unassigned = facts.filter((f) => !map[f.name]?.role);

  const byRole = new Map<string, Array<RoleAssignment & { name: string }>>();
  for (const [name, a] of Object.entries(map)) {
    const list = byRole.get(a.role) ?? [];
    list.push({ name, ...a });
    byRole.set(a.role, list);
  }

  const phantoms = facts.filter((f) => f.phantom);
  console.log(`variables   ${facts.length}  (${facts.length - phantoms.length} declared, ${phantoms.length} phantom)`);
  console.log(`assigned    ${facts.length - unassigned.length}`);
  console.log(`roles       ${byRole.size}  (A ${countTier(byRole, "A")} / B ${countTier(byRole, "B")} / C ${countTier(byRole, "C")})`);
  console.log(`call sites  ${facts.reduce((s, f) => s + f.uses, 0)}`);
  if (misfiled.length) {
    console.log(`\nWARN theme-invariant but assigned a themed role: ${misfiled.map((f) => f.name).join(", ")}`);
  }

  console.log("\nrole                      tier  vars  calls  L-spread");
  console.log("-".repeat(58));
  const rows = [...byRole.entries()].sort(
    (a, b) => weight(b[1]) - weight(a[1]),
  );
  const wide: Array<[string, Array<RoleAssignment & { name: string }>]> = [];
  for (const [role, g] of rows) {
    const spread = lightnessSpread(g);
    if (g.length > 1 && spread > SPREAD_LIMIT) wide.push([role, g]);
    console.log(
      `${role.padEnd(25)} ${g[0].tier}    ${String(g.length).padStart(4)} ${String(weight(g)).padStart(6)}  ${spread.toFixed(1).padStart(7)}${g.length > 1 && spread > SPREAD_LIMIT ? "  <- review" : ""}`,
    );
  }

  if (wide.length) {
    console.log(`\nRoles merging hexes more than ${SPREAD_LIMIT} lightness points apart:`);
    for (const [role, g] of wide) {
      console.log(`\n  ${role}`);
      for (const x of [...g].sort((a, b) => a.lightness - b.lightness)) {
        console.log(
          `    ${x.name.padEnd(13)} ${x.dark}  L=${x.lightness.toFixed(1).padStart(5)}  n=${String(x.uses).padStart(4)}  ${x.via}`,
        );
      }
    }
  }

  // Members are grouped by their DARK lightness, because dark is the palette the app was
  // designed in. That reading is blind to pairs which sit together in dark and apart in
  // light — `--c-161a22` and `--c-161b22` differ by one point in dark and by white
  // versus grey in light, a panel hierarchy that only exists in the light theme. Merging
  // those is invisible in every check that only looks at dark.
  const divergent: Array<[string, number, number, string, string]> = [];
  for (const [role, g] of byRole) {
    const withLight = g.filter((x) => x.light);
    if (withLight.length < 2) continue;
    let darkMax = 0;
    let lightMax = 0;
    let pair: [string, string] = ["", ""];
    for (let i = 0; i < withLight.length; i++) {
      for (let j = i + 1; j < withLight.length; j++) {
        darkMax = Math.max(darkMax, rgbDistance(withLight[i].dark, withLight[j].dark));
        const dl = rgbDistance(withLight[i].light as string, withLight[j].light as string);
        if (dl > lightMax) {
          lightMax = dl;
          pair = [withLight[i].name, withLight[j].name];
        }
      }
    }
    if (lightMax - darkMax > LIGHT_DIVERGENCE_LIMIT) {
      divergent.push([role, darkMax, lightMax, pair[0], pair[1]]);
    }
  }
  if (divergent.length) {
    console.log(`\nRoles whose members agree in dark but diverge in light by >${LIGHT_DIVERGENCE_LIMIT}:`);
    for (const [role, d, l, a, b] of divergent.sort((x, y) => y[2] - y[1] - (x[2] - x[1]))) {
      const fa = facts.find((f) => f.name === a);
      const fb = facts.find((f) => f.name === b);
      console.log(`  ${role.padEnd(23)} dark ${String(d).padStart(3)} / light ${String(l).padStart(3)}`);
      console.log(`     ${a} ${fa?.dark}/${fa?.light}  vs  ${b} ${fb?.dark}/${fb?.light}`);
    }
  }

  // Roles nothing maps onto. Harmless for TIER_A (a theme may still define them) but
  // worth surfacing: an unused TIER_B role is one we invented and did not need.
  const orphanB = Object.keys(TIER_B).filter((r) => !byRole.has(r));
  if (orphanB.length) console.log(`\nTIER_B roles with no variable mapped: ${orphanB.join(", ")}`);

  if (phantoms.length) {
    // These render as inherited/initial today because the variable was never declared.
    // Giving them a role makes them show the colour their name always claimed, which is
    // a visible change — list them so it is reviewed rather than discovered.
    const sites = phantoms.reduce((s, f) => s + f.uses, 0);
    console.log(`\nReferenced but never declared — ${phantoms.length} variables, ${sites} call sites.`);
    console.log("Currently render as inherited/initial; assigning a role makes them visible:");
    for (const f of [...phantoms].sort((a, b) => b.uses - a.uses)) {
      console.log(`  ${f.name.padEnd(13)} ${f.dark}  n=${String(f.uses).padStart(3)}  -> ${map[f.name].role}`);
    }
  }

  if (check) {
    if (unassigned.length || misfiled.length) {
      console.error(`\nFAIL ${unassigned.length} unassigned, ${misfiled.length} misfiled`);
      process.exit(1);
    }
    console.log("\nOK");
    return;
  }

  writeFileSync(OUT, `${JSON.stringify(map, null, 2)}\n`);
  console.log(`\nwrote ${OUT}`);
}

const weight = (g: RoleAssignment[]) => g.reduce((s, x) => s + x.uses, 0);
const lightnessSpread = (g: RoleAssignment[]) =>
  Math.max(...g.map((x) => x.lightness)) - Math.min(...g.map((x) => x.lightness));
const countTier = (m: Map<string, RoleAssignment[]>, t: string) =>
  [...m.values()].filter((g) => g[0].tier === t).length;

main();
