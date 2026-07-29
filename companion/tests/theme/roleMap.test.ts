// Guards the semantic colour layer against drift.
//
// The mapping in scripts/theme/roleMap.ts is only useful while it stays total: every
// `--c-<hex>` variable in public/dashboard.html must resolve to a role, or the theme
// generator silently drops a colour and one component reverts to an unthemed literal.
// dashboard.html is edited constantly, so "someone added a colour and nobody re-ran the
// mapper" is the expected failure, not a hypothetical one.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { DASHBOARD_PATH as DASHBOARD, loadBaseline } from "../../scripts/theme/loadBaseline.js";
import { isThemeInvariant, readPaletteFacts } from "../../scripts/theme/paletteFacts.js";
import { assignRoles, TIER_A, TIER_B, TIER_C } from "../../scripts/theme/roleMap.js";

const baseline = loadBaseline();
const facts = readPaletteFacts(DASHBOARD, baseline);
const map = assignRoles(facts, baseline);
const dashboard = readFileSync(DASHBOARD, "utf8");

describe("dashboard colour role map", () => {
  it("finds the palette and every variable in it", () => {
    // If this drops to zero the block selectors in readPaletteFacts stopped matching,
    // which would make every other assertion here vacuously true.
    expect(facts.length).toBeGreaterThan(100);
    for (const f of facts) expect(f.dark).toMatch(/^#[0-9a-f]{6}$/i);
  });

  it("assigns a role to every variable", () => {
    const missing = facts.filter((f) => !map[f.name]?.role).map((f) => f.name);
    expect(missing, "re-run `npm run theme:map` after adding colours").toEqual([]);
  });

  it("only emits roles declared in one of the three tiers", () => {
    const known = new Set<string>([...TIER_A, ...Object.keys(TIER_B), ...Object.values(TIER_C)]);
    const unknown = [...new Set(Object.values(map).map((a) => a.role))].filter((r) => !known.has(r));
    expect(unknown, "role assigned but never declared").toEqual([]);
  });

  it("keeps theme-invariant colours out of the themed tiers", () => {
    // A colour with identical dark and light values is the existing code saying "this
    // is brand, do not theme it". Giving it a themed role would make the product mark
    // shift with every theme.
    const misfiled = facts.filter((f) => isThemeInvariant(f) && map[f.name].tier !== "C");
    expect(misfiled.map((f) => f.name)).toEqual([]);
  });

  it("derives every tier B role from tier A alone", () => {
    // This is the drop-in contract: an upstream theme block defines the 25
    // tier A roles and nothing else. If a tier B fallback leans on another tier B role,
    // that chain can resolve to an undefined variable and the component renders
    // transparent. Each fallback must bottom out in tier A.
    const tierA = new Set<string>(TIER_A);
    for (const [role, expr] of Object.entries(TIER_B)) {
      const refs = [...expr.matchAll(/var\((--[a-z0-9-]+)\)/g)].map((m) => m[1]);
      expect(refs.length, `${role} has no fallback reference`).toBeGreaterThan(0);
      for (const ref of refs) {
        expect(tierA.has(ref), `${role} falls back to ${ref}, which is not tier A`).toBe(true);
      }
    }
  });

  it("declares no tier B role that duplicates a tier A name", () => {
    const clash = Object.keys(TIER_B).filter((r) => (TIER_A as readonly string[]).includes(r));
    expect(clash, "tier B must extend tier A, not shadow it").toEqual([]);
  });
});

describe("dashboard.html after the role migration", () => {
  it("references colours by role, not by hex-named variable", () => {
    // Every `--c-` left in the file must be a declaration in the generated alias block.
    // A `var(--c-...)` outside it means a call site the rewriter missed, or one that
    // arrived on another branch after the migration; `npm run theme:apply` fixes both.
    const calls = [...dashboard.matchAll(/var\(\s*(--c-[0-9a-f]{6})\s*[,)]/g)].map((m) => m[1]);
    expect(calls, "run `npm run theme:apply`").toEqual([]);
  });

  it("defines every tier A role in both built-in themes", () => {
    // A role defined in only one theme renders as `unset` in the other — usually
    // transparent or inherited, which reads as a rendering bug rather than a colour bug.
    const block = (selector: string) => {
      const at = dashboard.indexOf(selector);
      expect(at, `${selector} block missing`).toBeGreaterThan(-1);
      return dashboard.slice(at, dashboard.indexOf("\n    }", at));
    };
    for (const selector of [':root[data-theme="dark"] {', ':root[data-theme="light"] {']) {
      const body = block(selector);
      const missing = TIER_A.filter((role) => !body.includes(`${role}:`));
      expect(missing, `${selector} is missing roles`).toEqual([]);
    }
  });

  it("keeps the tier B fallbacks out of the theme blocks", () => {
    // The fallbacks belong at bare `:root`. Inside a `[data-theme]` block they would
    // outrank nothing, but the built-in themes' explicit values must NOT leak to bare
    // `:root` either — that is what lets an imported theme derive its own. Assert the
    // explicit values live behind a data-theme selector.
    const rootStart = dashboard.indexOf("\n    :root {");
    const rootBody = dashboard.slice(rootStart, dashboard.indexOf("\n    }", rootStart));
    // Compare on collapsed whitespace: the generator pads declarations into columns and
    // the column width shifts whenever the longest role name changes.
    const flat = rootBody.replace(/\s+/g, " ");
    const missing = Object.entries(TIER_B)
      .filter(([role, expr]) => !flat.includes(`${role}: ${expr.replace(/\s+/g, " ")}`))
      .map(([role]) => role);
    expect(missing, "tier B derivations must sit at bare :root").toEqual([]);
  });
});
