// The semantic colour vocabulary for the dashboard, and the mapping from the 149
// mechanical `--c-<hex>` variables in public/dashboard.html onto it.
//
// WHY THIS EXISTS
// The dashboard palette was produced by an automated "hoist every literal hex into
// a custom property" pass. That made the two-theme (dark/light) switch possible, but
// it left us with 149 variables named after their own dark-mode value — `--c-0d1117`
// means nothing, and near-duplicates like #0d1017 / #0d1117 / #0f1115 / #11141a are
// all "the page background" with no way to know that from the name. Adding a third
// theme under that scheme means hand-picking 149 unrelated hexes per theme.
//
// A semantic layer fixes that: components ask for `--bg-primary`, and a theme is the
// ~25 answers to "what colour is each role". An upstream theme project (MIT,
// Copyright (c) 2026 Security Onion Solutions, LLC) ships 24 themes against exactly
// this shape, so TIER_A below reuses its role names verbatim — an upstream theme
// block then drops in with no translation.
//
// See scripts/theme/README.md for the porting plan and the attribution requirement.

import { hueName, type VarFact } from "./paletteFacts.js";

/**
 * The upstream roles, spelled exactly as upstream spells them. Any theme block
 * copied from that stylesheet sets these and nothing else, so this list is the
 * compatibility contract: it must not be renamed or extended.
 */
export const TIER_A = [
  "--bg-primary",
  "--bg-secondary",
  "--bg-tertiary",
  "--bg-hover",
  "--bg-hover-light",
  "--border-color",
  "--text-primary",
  "--text-bright",
  "--text-muted",
  "--accent",
  "--accent-hover",
  "--bg-drop-active",
  "--modal-backdrop",
  "--badge-danger-text",
  "--danger-bg",
  "--badge-bg-neutral",
  "--badge-warning-text",
  "--badge-success-text",
  "--tag-red-text",
  "--tag-purple-text",
  "--tag-orange-text",
  "--tag-blue-text",
  "--tag-gray-text",
  "--tag-green-text",
  "--help-icon-color",
] as const;

/**
 * Tier A roles that no `--c-*` variable maps onto, because the dashboard never used a
 * colour for them. They still have to be emitted: the contract says a theme defines
 * all 25, so ours must too, or an imported theme would be the only one that sets them
 * and switching away would leave them undefined.
 */
export const TIER_A_UNMAPPED: Record<string, { dark: string; light: string }> = {
  // Upstream's own values. Nothing in the dashboard dims behind a modal today.
  "--modal-backdrop": { dark: "rgba(0, 0, 0, 0.8)", light: "rgba(0, 0, 0, 0.5)" },
  // The dashboard has no blue or grey tag; point them at the nearest role in use so
  // an imported theme that styles tags still looks coherent if we add them later.
  "--tag-blue-text": { dark: "#6aa9ff", light: "#2563c9" },
  "--tag-gray-text": { dark: "#9aa4b2", light: "#5a6573" },
};

/**
 * Roles the companion needs that upstream has no equivalent for — chiefly the
 * severity scale, which is the single most load-bearing colour family in a DFIR UI
 * and which upstream simply does not have.
 *
 * Every entry carries a fallback expressed only in TIER_A terms. That is what makes
 * an upstream theme usable unmodified: define the 25, get these 20 derived. A theme
 * author who wants finer control can still override any of them explicitly.
 */
export const TIER_B: Record<string, string> = {
  // Severity. Distinct from the tag colours because severity is ordinal and appears
  // on rows, cards, chips and timeline events that must stay comparable at a glance.
  "--sev-critical": "var(--tag-red-text)",
  "--sev-high": "var(--tag-orange-text)",
  "--sev-medium": "var(--help-icon-color)",
  "--sev-low": "var(--tag-green-text)",
  "--sev-info": "var(--accent)",

  // Text ramp. Upstream stops at three steps (bright/primary/muted); the dashboard
  // uses five, with two dimmer steps for placeholders, disabled controls and captions.
  "--text-dim": "color-mix(in oklab, var(--text-muted) 78%, var(--bg-primary))",
  "--text-faint": "color-mix(in oklab, var(--text-muted) 52%, var(--bg-primary))",

  // Border ramp. One `--border-color` cannot cover both the hairline between table
  // rows and the outline around a raised card without flattening the hierarchy.
  "--border-subtle": "color-mix(in oklab, var(--border-color) 65%, var(--bg-secondary))",
  "--border-strong": "color-mix(in oklab, var(--border-color) 60%, var(--text-muted))",

  // Accent-as-surface. `--accent` is link and icon text; a primary button face needs
  // to be darker so white label text stays legible on it. Upstream gets away with one
  // value because its accent is mid-tone; ours is not.
  "--accent-solid": "color-mix(in oklab, var(--accent) 72%, var(--bg-primary))",
  "--accent-solid-hover": "color-mix(in oklab, var(--accent) 82%, var(--bg-primary))",

  // Status anchors used as solid fills (progress bars, confirm buttons).
  "--success": "color-mix(in oklab, var(--badge-success-text) 70%, var(--bg-primary))",

  // Tinted status surfaces and their borders. Derived rather than authored so a theme
  // never has to hand-pick twelve washes that all need to sit on its own background.
  "--success-bg": "color-mix(in oklab, var(--badge-success-text) 13%, var(--bg-primary))",
  "--success-border": "color-mix(in oklab, var(--badge-success-text) 34%, var(--bg-primary))",
  "--warning-bg": "color-mix(in oklab, var(--badge-warning-text) 11%, var(--bg-primary))",
  "--warning-bg-strong": "color-mix(in oklab, var(--badge-warning-text) 22%, var(--bg-primary))",
  "--warning-border": "color-mix(in oklab, var(--badge-warning-text) 36%, var(--bg-primary))",
  "--danger-border": "color-mix(in oklab, var(--badge-danger-text) 36%, var(--bg-primary))",
  "--info-bg": "color-mix(in oklab, var(--tag-purple-text) 13%, var(--bg-primary))",
  "--info-border": "color-mix(in oklab, var(--tag-purple-text) 34%, var(--bg-primary))",

  // Row/card selection. Accent-tinted so it reads as "you picked this", not "this is hovered".
  "--surface-selected": "color-mix(in oklab, var(--accent) 15%, var(--bg-secondary))",

  // The primary content surface — header, section, modals, text inputs — as distinct
  // from the nested cards and menus that sit on top of it. In dark mode the two are a
  // point apart (#161a22 vs #161b22) and look mergeable; in light mode the first is
  // #ffffff and the second #e4e9f2, a deliberate white-panel-on-grey-page hierarchy
  // that a dark-only reading would flatten.
  //
  // The fallback is identity rather than a guess. Upstream has no elevated-surface
  // concept, so an imported theme genuinely has nothing to say here, and inventing a
  // lighter mix would be wrong in half of its themes: nudging toward --text-bright
  // lightens a dark theme and darkens a light one.
  "--bg-elevated": "var(--bg-secondary)",
};

/**
 * Brand constants. These four are byte-identical in the dark and light blocks today,
 * which is the existing code stating that they are deliberately not themed. Themes
 * must not touch them, or the product mark shifts per theme.
 */
export const TIER_C: Record<string, string> = {
  "--c-0e7c75": "--brand-teal-deep",
  "--c-0f8a82": "--brand-teal",
  "--c-15a89d": "--brand-teal-bright",
  "--c-eafffb": "--brand-teal-ink",
};

/**
 * Assignments that colour alone cannot justify — each one was read off the selectors
 * the variable actually appears in. Anything not listed here is assigned by the usage
 * bands in `bandRole()`, which is safe only for the neutral surface/border/text bulk.
 */
export const EXPLICIT: Record<string, string> = {
  // Severity scale, from `.sev-Critical` / `.sev-High` / `.sev-Medium` / `.sev-Low`
  // and their `.sevr-*` row and card variants.
  "--c-ff5c5c": "--sev-critical",
  "--c-ff9f43": "--sev-high",
  "--c-ff8a5c": "--sev-high",
  "--c-ffd93b": "--sev-medium",
  "--c-6bcb77": "--sev-low",
  // #6aa9ff is `.sev-Info` AND the general accent across 105 distinct selectors.
  // It maps to --accent; --sev-info falls back to var(--accent), so both hold.
  "--c-6aa9ff": "--accent",

  // Accent split by role rather than by hue: #6aa9ff is accent-as-text (links, icons,
  // chevrons), #2d6cdf is accent-as-surface (primary button faces). Collapsing them
  // would put button-face blue on link text and fail contrast on both.
  "--c-2d6cdf": "--accent-solid",
  "--c-2a7bff": "--accent-solid",
  "--c-1f6feb": "--accent-solid-hover",
  "--c-38bdf8": "--accent",
  "--c-6fb3e0": "--accent",
  "--c-9cc5ff": "--accent-hover",
  "--c-9ecbff": "--accent-hover",
  "--c-8fb3e0": "--accent-hover",
  "--c-8aa0c0": "--text-muted",

  // Destructive actions and error states.
  "--c-ff7a7a": "--badge-danger-text",
  "--c-ff6b6b": "--badge-danger-text",
  "--c-e06060": "--badge-danger-text",
  "--c-ff7b8a": "--tag-red-text",
  "--c-ff8a8a": "--tag-red-text",
  "--c-ff8aa0": "--tag-red-text",
  "--c-ff9aa4": "--tag-red-text",
  "--c-ff9f9f": "--tag-red-text",

  // Adversary / playbook-match category colour.
  "--c-c79bff": "--tag-purple-text",

  // Green: solid fills vs text weights.
  "--c-2f8f4e": "--success",
  "--c-2ea043": "--success",
  "--c-4ade80": "--badge-success-text",
  "--c-4cd964": "--badge-success-text",
  "--c-5fd470": "--badge-success-text",
  "--c-7ec8a4": "--tag-green-text",

  // Amber/gold text weights.
  "--c-ffb454": "--badge-warning-text",
  "--c-ffcf66": "--tag-orange-text",
  "--c-ffd07a": "--tag-orange-text",
  "--c-ffce8a": "--tag-orange-text",
  "--c-ffe6a6": "--tag-orange-text",
  "--c-e0b84a": "--help-icon-color",
  "--c-caa86a": "--help-icon-color",

  // Selection vs drop-target vs hover — three states the band rules would merge
  // because they sit within a few points of lightness of each other.
  "--c-142038": "--surface-selected", // .finding-selected, .ev-selected, .ioc-selected
  "--c-11202e": "--surface-selected", // .cmdp-row.sel, .comment-chip.has, .mention-chip
  "--c-13243a": "--bg-drop-active",
  "--c-1a2433": "--bg-drop-active",
  "--c-1f3a52": "--bg-drop-active",
  "--c-243a5e": "--bg-drop-active",
  "--c-23304a": "--bg-drop-active",
  "--c-1f2942": "--bg-drop-active",
  "--c-2a3050": "--bg-hover",

  // Tinted status surfaces.
  "--c-3a1a1a": "--danger-bg",
  "--c-3a2020": "--danger-bg",
  "--c-5a1722": "--danger-bg",
  "--c-2a2233": "--info-bg",
  "--c-3a2230": "--info-bg",
  "--c-3a2330": "--info-bg",

  // Status borders.
  "--c-5a2a2a": "--danger-border",
  "--c-1f5a35": "--success-border",
  "--c-2a5a2a": "--success-border",
  "--c-5a4a1a": "--warning-border",
  "--c-5a4800": "--warning-border",
  "--c-5a4416": "--warning-border",
  "--c-7a5d1e": "--warning-border",
  "--c-4a3a5a": "--info-border",

  // Neutral badge face.
  "--c-21262d": "--badge-bg-neutral",
  "--c-22272e": "--badge-bg-neutral",

  // header, section, .comment-modal, .wiz-modal, #globalSearch — the primary content
  // surface. Pure white in light mode, where --bg-secondary is #e4e9f2.
  "--c-161a22": "--bg-elevated",
};

export type UsageClass = "SURFACE" | "BORDER" | "TEXT" | "CANVAS";
export type HueName =
  | "neutral" | "red" | "orange" | "yellow" | "green" | "cyan" | "blue" | "violet" | "pink";

/**
 * Fallback assignment for the neutral bulk — the ~90 surface, border and text hexes
 * that carry no component-specific meaning and differ only by lightness. Thresholds
 * are the gaps that actually appear in the dark palette, not round numbers.
 */
export function bandRole(cls: UsageClass, lightness: number, hue: HueName): string {
  if (cls === "SURFACE" || cls === "CANVAS") {
    if (hue === "green") return "--success-bg";
    // Amber surfaces span L 5.5-26 across two visibly different intensities
    // (a subtle callout wash and a saturated badge face). One role cannot hold both.
    if (hue === "orange" || hue === "yellow") {
      return lightness < 12 ? "--warning-bg" : "--warning-bg-strong";
    }
    if (hue === "red") return "--danger-bg";
    if (hue === "violet" || hue === "pink") return "--info-bg";
    if (lightness < 8.5) return "--bg-primary";
    if (lightness < 13.5) return "--bg-secondary";
    if (lightness < 18.5) return "--bg-tertiary";
    return "--bg-hover";
  }

  if (cls === "BORDER") {
    if (hue === "green") return "--success-border";
    if (hue === "orange" || hue === "yellow") return "--warning-border";
    if (hue === "red") return "--danger-border";
    if (hue === "violet" || hue === "pink") return "--info-border";
    // Neutral borders run L 12.9-24.7. The low band is the hairline between rows,
    // the high band is the outline around cards; merging loses that hierarchy.
    if (lightness < 18) return "--border-subtle";
    if (lightness < 26) return "--border-color";
    if (lightness < 50) return "--border-strong";
    return "--bg-hover-light";
  }

  // TEXT
  if (hue === "red") return "--tag-red-text";
  if (hue === "green") return "--tag-green-text";
  if (hue === "orange" || hue === "yellow") return "--badge-warning-text";
  if (hue === "violet" || hue === "pink") return "--tag-purple-text";
  if (lightness >= 87) return "--text-bright";
  if (lightness >= 78) return "--text-primary";
  if (lightness >= 62) return "--text-muted";
  if (lightness >= 50) return "--text-dim";
  return "--text-faint";
}

/** Which tier a role belongs to. Drives whether a theme must define it. */
export function tierOf(role: string): "A" | "B" | "C" {
  if ((TIER_A as readonly string[]).includes(role)) return "A";
  if (role in TIER_B) return "B";
  return "C";
}

export interface RoleAssignment {
  role: string;
  tier: "A" | "B" | "C";
  /**
   * How the role was chosen: a brand constant, a hand-read call site, a usage band, or
   * carried over from the committed map because the migration has already erased the
   * usage evidence this file would otherwise classify from.
   */
  via: "explicit" | "fixed" | "band" | "baseline";
  dark: string;
  light: string | null;
  uses: number;
  cls: VarFact["cls"];
  lightness: number;
  phantom: boolean;
}

/**
 * Resolve every variable to a role.
 *
 * Precedence: brand constants first (they must never be themed), then hand-read call
 * sites, then a committed assignment if one exists, and only then the usage bands —
 * which are a reasonable default for the neutral bulk and wrong for anything carrying
 * component-specific meaning.
 *
 * The committed assignment ranks above the bands because after the migration there are
 * no call sites left to band on; see the header of loadBaseline.ts.
 */
export function assignRoles(
  facts: VarFact[],
  baseline?: Record<string, { role: string }>,
): Record<string, RoleAssignment> {
  const out: Record<string, RoleAssignment> = {};
  for (const f of facts) {
    let role: string;
    let via: RoleAssignment["via"];
    if (f.name in TIER_C) {
      role = TIER_C[f.name];
      via = "fixed";
    } else if (f.name in EXPLICIT) {
      role = EXPLICIT[f.name];
      via = "explicit";
    } else if (baseline?.[f.name]?.role) {
      role = baseline[f.name].role;
      via = "baseline";
    } else {
      role = bandRole(f.cls, f.lightness, hueName(f.hue, f.sat));
      via = "band";
    }
    out[f.name] = {
      role,
      tier: tierOf(role),
      via,
      dark: f.dark,
      light: f.light,
      uses: f.uses,
      cls: f.cls,
      lightness: f.lightness,
      phantom: f.phantom,
    };
  }
  return out;
}
