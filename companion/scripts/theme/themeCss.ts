// Turns the role map into the CSS custom-property blocks that replace the 149
// `--c-<hex>` declarations in public/dashboard.html.
//
// CASCADE LAYOUT, and why it is split the way it is:
//
//   :root                          layer 1 — brand constants, tier B fallbacks,
//                                            legacy --c-* aliases, and the dark
//                                            tier A values as an unconditional base
//   :root[data-theme="dark"]       layer 2 — the built-in dark theme
//   :root[data-theme="light"]      layer 2 — the built-in light theme
//
// The tier B fallbacks MUST sit at bare `:root` and the built-in themes' explicit
// tier B values MUST sit inside a `[data-theme]` block. An imported theme
// is `:root[data-theme="nord"]`, specificity (0,2,0). If our explicit `--sev-high`
// lived at bare `:root` (0,1,0) it would still lose to nothing — nord does not set
// it — so nord would inherit OUR severity orange instead of deriving its own from
// nord's `--tag-orange-text`. Putting it behind `[data-theme="dark"]` means nord
// simply does not match it, and the tier B fallback at `:root` takes over.
//
// The dark tier A values are ALSO written at bare `:root`, duplicating layer 2. That
// is deliberate: the theme bootstrap is an inline <script> with a templated CSP nonce,
// and if it is ever blocked the `data-theme` attribute never appears. Without a base
// at `:root` the entire dashboard would render with every colour undefined. Twenty-five
// generated lines is a cheap guard against a blank page.

import {
  contrast,
  deepenForContrast,
  hexToRgb,
  isLightBackground,
  rgbToHex,
  solveForContrast,
} from "./contrast.js";
import type { AlphaAlias, VarFact } from "./paletteFacts.js";
import {
  type Severity,
  SEVERITY_FALLBACK,
  SEVERITY_ORDER,
  type SeveritySolution,
  solveSeverityScale,
} from "./severity.js";
import { IMPORTED_THEMES } from "./vendor/themePalettes.js";
import {
  type RoleAssignment,
  TIER_A,
  TIER_A_UNMAPPED,
  TIER_B,
  TIER_C,
} from "./roleMap.js";

export interface RoleValue {
  role: string;
  dark: string;
  light: string;
  /** The variable whose value was adopted, and how many call sites it had. */
  from: string;
  uses: number;
  /** Other variables folded into this role, for the changelog. */
  folded: string[];
}

/**
 * Choose one concrete value per role.
 *
 * The winner is the member variable with the most call sites. Weighting by usage means
 * the colour the eye sees most keeps its exact current value and the low-traffic
 * near-duplicates snap to it — the smallest possible visible change for a refactor that
 * touches every colour in the product.
 */
export function resolveRoleValues(
  facts: VarFact[],
  map: Record<string, RoleAssignment>,
): Map<string, RoleValue> {
  const byRole = new Map<string, VarFact[]>();
  for (const f of facts) {
    const role = map[f.name].role;
    byRole.set(role, [...(byRole.get(role) ?? []), f]);
  }

  const out = new Map<string, RoleValue>();
  for (const [role, members] of byRole) {
    // A phantom has no light value — it was never in either palette block — so it must
    // not set a role's value while any declared member could. Declared first, then by
    // call-site count; ties break on declaration order so output is stable across runs.
    const winner = [...members].sort(
      (a, b) => Number(a.phantom) - Number(b.phantom) || b.uses - a.uses,
    )[0];
    out.set(role, {
      role,
      dark: winner.dark,
      light: winner.light ?? winner.dark,
      from: winner.name,
      uses: winner.uses,
      folded: members.filter((m) => m.name !== winner.name).map((m) => m.name),
    });
  }

  for (const [role, v] of Object.entries(TIER_A_UNMAPPED)) {
    if (!out.has(role)) {
      out.set(role, { role, dark: v.dark, light: v.light, from: "(unmapped)", uses: 0, folded: [] });
    }
  }
  return out;
}

const pad = (s: string, n: number) => s + " ".repeat(Math.max(0, n - s.length));

/** WCAG 2.x AA for normal-size text. 3.0 is the LARGE-text / non-text floor and does not apply to
 *  the text ramp — see textRampSteps, where assuming otherwise generated sub-AA body text. */
const AA_TEXT_CONTRAST = 4.5;

/**
 * Tier A roles that carry TEXT, and so owe WCAG AA against whatever they sit on.
 *
 * The legacy values were captured from the original hand-written dashboard, where nothing checked
 * them: `--badge-warning-text` (#e07e00) measured 2.52:1 on --bg-secondary and `--text-muted`
 * (#5a6573) 4.33:1 on --border-color. Severity and the text ramp are already solved for the
 * built-in themes rather than carried over — this closes the last family that was not.
 */
const TIER_A_TEXT_ROLES = new Set([
  "--text-muted",
  "--badge-danger-text",
  "--badge-warning-text",
  "--badge-success-text",
  "--tag-red-text",
  "--tag-purple-text",
  "--tag-orange-text",
  "--tag-blue-text",
  "--tag-gray-text",
  "--tag-green-text",
  "--help-icon-color",
]);

function tierABlock(values: Map<string, RoleValue>, mode: "dark" | "light"): string {
  const lines: string[] = [];
  const pick = (role: string, fallback: string): string => {
    const v = values.get(role);
    if (!v) return fallback;
    return mode === "dark" ? v.dark : v.light;
  };
  // Text lands on the page, on panels, and on grey chips and secondary buttons — whose background
  // IS --border-color. Solving against the page alone is what let chip text ship at 4.33:1.
  const surfaces = ["--bg-primary", "--bg-secondary", "--border-color"].map((r) =>
    hexToRgb(pick(r, "#000000")),
  );

  for (const role of TIER_A) {
    const v = values.get(role);
    if (!v) throw new Error(`tier A role has no value: ${role}`);
    let value = mode === "dark" ? v.dark : v.light;
    // Only ever DARKENS/lightens toward legibility, and only when the value actually falls short —
    // a role already clearing AA passes through byte-identical, so shipped colours do not move.
    if (TIER_A_TEXT_ROLES.has(role) && /^#[0-9a-f]{6}$/i.test(value)) {
      const rgb = hexToRgb(value);
      const worst = surfaces.reduce((a, b) => (contrast(rgb, a) <= contrast(rgb, b) ? a : b));
      if (contrast(rgb, worst) < AA_TEXT_CONTRAST) {
        value = rgbToHex(deepenForContrast(worst, rgb, AA_TEXT_CONTRAST));
      }
    }
    lines.push(`      ${pad(`${role}:`, 24)} ${value};`);
  }
  return lines.join("\n");
}

/**
 * The severity scale for one of the built-in themes.
 *
 * The legacy `--sev-*` values are the candidates, so a scale that already satisfies the
 * contrast and separation floors passes through untouched and the shipped colours do not
 * move. See severity.ts for why the tier A fallbacks alone are not sufficient.
 */
function builtInSeverity(values: Map<string, RoleValue>, mode: "dark" | "light"): SeveritySolution {
  const pick = (role: string, fallback: string) => {
    const v = values.get(role);
    if (!v) return fallback;
    return mode === "dark" ? v.dark : v.light;
  };
  const candidates = {} as Record<Severity, string>;
  for (const s of SEVERITY_ORDER) {
    candidates[s] = pick(`--sev-${s}`, pick(SEVERITY_FALLBACK[s], "#888888"));
  }
  const surfaces = [
    hexToRgb(pick("--bg-primary", "#000000")),
    hexToRgb(pick("--bg-secondary", "#000000")),
  ];
  return solveSeverityScale(candidates, surfaces);
}

function tierBExplicitBlock(values: Map<string, RoleValue>, mode: "dark" | "light"): string {
  const lines: string[] = [];
  const severity = builtInSeverity(values, mode);
  // Same argument as severity directly below: the text ramp is SOLVED for the built-in themes too,
  // not carried over from the legacy values. Carrying it over is what kept `--text-faint: #737d8c`
  // — 3.57:1 on --bg-secondary — in the default light theme while every imported theme got an
  // AA-solved value, i.e. the floors held everywhere except the theme most people actually see.
  const pick = (role: string, fallback: string): string => {
    const v = values.get(role);
    if (!v) return fallback;
    return mode === "dark" ? v.dark : v.light;
  };
  const ramp = textRampSteps({
    "--bg-primary": pick("--bg-primary", "#000000"),
    "--bg-secondary": pick("--bg-secondary", pick("--bg-primary", "#000000")),
    "--text-muted": pick("--text-muted", "#888888"),
  });
  for (const role of Object.keys(TIER_B)) {
    if (role === "--text-dim" || role === "--text-faint") {
      lines.push(`      ${pad(`${role}:`, 24)} ${role === "--text-dim" ? ramp.dim : ramp.faint};`);
      continue;
    }
    // Severity is solved rather than carried over, so that the floors hold in the
    // built-in themes too and are not something only imported themes are held to.
    const sev = SEVERITY_ORDER.find((s) => `--sev-${s}` === role);
    if (sev) {
      lines.push(`      ${pad(`${role}:`, 24)} ${severity.colors[sev]};`);
      continue;
    }
    const v = values.get(role);
    // A tier B role with no member variable has no legacy value to preserve; it keeps
    // the derivation from layer 1 in every theme, ours included.
    if (!v) continue;
    lines.push(`      ${pad(`${role}:`, 24)} ${mode === "dark" ? v.dark : v.light};`);
  }
  return lines.join("\n");
}

/**
 * The legacy `--c-<hex>` names, redefined as aliases onto their role. Any call site the
 * rewriter misses — in CSS, in a JS template string, in code added on another branch
 * while this was in flight — keeps working and simply follows the theme.
 *
 * These are scaffolding. Once a release has shipped with no `--c-` references left,
 * delete the block; `npm run theme:map` reports the remaining count.
 */
function aliasBlock(map: Record<string, RoleAssignment>, alphas: AlphaAlias[]): string {
  const lines: string[] = [];
  for (const name of Object.keys(map).sort()) {
    lines.push(`      ${pad(`${name}:`, 17)} var(${map[name].role});`);
  }
  // Translucent variants keep their own name because no opaque role can express them.
  // Mixing against `transparent` in sRGB reproduces the original alpha compositing.
  for (const a of alphas) {
    const role = map[a.base]?.role;
    if (!role) continue;
    lines.push(
      `      ${pad(`${a.name}:`, 17)} color-mix(in srgb, var(${role}) ${a.alphaPct}%, transparent);`,
    );
  }
  return lines.join("\n");
}

/**
 * The two sub-muted text steps for an imported theme.
 *
 * Targets are floors, not fixed points: WCAG AA's 4.5:1 for BOTH steps. The faintest step used to
 * floor at 3.0, on the reasoning that it dresses placeholders, disabled controls and timestamps.
 * That reasoning does not survive contact with the markup — an axe scan found `--text-faint` on 28
 * nodes of ordinary small body text, timestamps and confidence figures among them, measuring
 * 3.57:1. 3.0 is the floor for LARGE text and non-text UI, and none of those were either. A ramp
 * step generated below AA is a violation the generator manufactures on every theme at once, which
 * is why it is fixed here rather than at 28 call sites.
 *
 * Both are still capped at the theme's own `--text-muted` contrast, because a step below muted must
 * never end up MORE prominent than muted — that would invert the ramp. Where a theme's muted is
 * itself under AA the cap wins and the steps collapse onto muted: flatter than intended, but never
 * less legible than the step above, which is the right way to fail.
 */
function textRampSteps(palette: Record<string, string>): { dim: string; faint: string } {
  // The surface that gives the least contrast is the one every step has to satisfy. Faint text
  // sits on panels and chips (--bg-secondary) as often as on the page, and in a light theme the
  // secondary surface is the DARKER of the two — so a value solved against the page alone came up
  // short exactly where it was used. The severity solver beside this one already takes both.
  const surfaces = [hexToRgb(palette["--bg-primary"]), hexToRgb(palette["--bg-secondary"])];
  const muted = hexToRgb(palette["--text-muted"]);
  const worst = surfaces.reduce((a, b) => (contrast(muted, a) <= contrast(muted, b) ? a : b));
  const mutedContrast = contrast(muted, worst);

  const faintTarget = Math.min(Math.max(AA_TEXT_CONTRAST, mutedContrast * 0.72), mutedContrast);
  const dimTarget = Math.min(Math.max(faintTarget * 1.25, mutedContrast * 0.88), mutedContrast);

  return {
    dim: rgbToHex(solveForContrast(worst, muted, dimTarget)),
    faint: rgbToHex(solveForContrast(worst, muted, faintTarget)),
  };
}

export function themePolarity(palette: Record<string, string>): "light" | "dark" {
  return isLightBackground(palette["--bg-primary"]) ? "light" : "dark";
}

/**
 * Render the imported themes as `:root[data-theme="name"]` blocks.
 *
 * Each block sets the 25 tier A roles from upstream plus two things upstream has no
 * concept of:
 *
 *   color-scheme   computed from --bg-primary luminance, so form controls, scrollbars
 *                  and the caret follow the theme instead of staying dark
 *   --hover-wash   a white or black scrim depending on that same polarity
 *
 * Everything in tier B derives from tier A at bare `:root`, so these blocks say nothing
 * about severity, text ramps or status washes — that is the whole point of the contract.
 *
 * ONE DELIBERATE ADAPTATION: upstream's `--accent-hover` is DARKER than its `--accent`,
 * because upstream dims on hover. This dashboard brightens, at 8 of its 10 accent-hover
 * call sites. Importing the value as-is would invert every hover in 23 themes, so
 * upstream's darker value is taken as `--accent-solid-hover` (our button-face hover,
 * which does dim) and `--accent-hover` is derived toward `--text-bright` — which
 * brightens in a dark theme and deepens in a light one, correct in both.
 */
/**
 * One rendered `:root[data-theme="…"]` block per imported theme, alphabetically.
 *
 * Exposed as an array rather than only the joined string because #415 split the generated region
 * across two stylesheet parts, and the split has to fall BETWEEN blocks. Halving a list is exact;
 * finding a block boundary by re-parsing the joined text afterwards is guesswork that gets a
 * theme's opening brace wrong the first time a label contains the separator.
 */
export function importedThemeBlocks(
  themes: Record<string, { label: string; group: string; palette: Record<string, string> }>,
): string[] {
  const blocks: string[] = [];
  for (const name of Object.keys(themes).sort()) {
    const { label, palette } = themes[name];
    const polarity = themePolarity(palette);
    const lines = TIER_A.map((role) => {
      if (role === "--accent-hover") {
        return `      ${pad(`${role}:`, 24)} color-mix(in oklab, var(--accent) 78%, var(--text-bright));`;
      }
      return `      ${pad(`${role}:`, 24)} ${palette[role]};`;
    });
    const ramp = textRampSteps(palette);
    const severity = solveSeverityScale(
      Object.fromEntries(
        SEVERITY_ORDER.map((s) => [s, palette[SEVERITY_FALLBACK[s]]]),
      ) as Record<Severity, string>,
      [hexToRgb(palette["--bg-primary"]), hexToRgb(palette["--bg-secondary"])],
    );
    const sevLines = SEVERITY_ORDER.map(
      (s) => `      ${pad(`--sev-${s}:`, 24)} ${severity.colors[s]};`,
    );
    blocks.push(
      `    /* ${label} — MIT (c) 2026 Security Onion Solutions, LLC */\n` +
        `    :root[data-theme="${name}"] {\n` +
        `      color-scheme: ${polarity};\n` +
        `      --hover-wash: ${polarity === "light" ? "rgba(0,0,0,.06)" : "rgba(255,255,255,.07)"};\n` +
        `${lines.join("\n")}\n` +
        `      --accent-solid-hover:    ${palette["--accent-hover"]};\n` +
        `      /* solved for contrast, not derived — see textRampSteps() */\n` +
        `      ${pad("--text-dim:", 24)} ${ramp.dim};\n` +
        `      ${pad("--text-faint:", 24)} ${ramp.faint};\n` +
        `      /* solved for contrast AND mutual separation — see severity.ts */\n` +
        `${sevLines.join("\n")}\n` +
        `    }`,
    );
  }
  return blocks;
}

export function renderImportedThemes(
  themes: Record<string, { label: string; group: string; palette: Record<string, string> }>,
): string {
  return importedThemeBlocks(themes).join("\n\n");
}

/**
 * Per-theme picker chrome: the swatch colours, and which glyph the toggle shows.
 *
 * Both are emitted as CSS rather than set from JS. The swatch keeps the menu free of
 * inline styles, which would otherwise need a CSP style nonce for a purely decorative
 * chip. The glyph rule keys off POLARITY rather than theme name — showing a moon on
 * Catppuccin Latte, which is near-white, would misreport what is on screen.
 */
function renderThemeChrome(
  themes: Record<string, { palette: Record<string, string> }>,
  values: Map<string, RoleValue>,
): string {
  const rows: Array<{ name: string; bg: string; accent: string; polarity: "light" | "dark" }> = [
    {
      name: "dark",
      bg: values.get("--bg-primary")?.dark ?? "#0f1115",
      accent: values.get("--accent")?.dark ?? "#6aa9ff",
      polarity: "dark",
    },
    {
      name: "light",
      bg: values.get("--bg-primary")?.light ?? "#ffffff",
      accent: values.get("--accent")?.light ?? "#2563c9",
      polarity: "light",
    },
  ];
  for (const name of Object.keys(themes).sort()) {
    const p = themes[name].palette;
    rows.push({
      name,
      bg: p["--bg-primary"],
      accent: p["--accent"],
      polarity: themePolarity(p),
    });
  }

  const swatches = rows
    .map(
      (r) =>
        `    .theme-swatch[data-for="${r.name}"] { background: linear-gradient(135deg, ${r.bg} 0 50%, ${r.accent} 50% 100%); }`,
    )
    .join("\n");
  const lightThemes = rows.filter((r) => r.polarity === "light").map((r) => r.name);
  const glyph =
    `${lightThemes.map((n) => `    :root[data-theme="${n}"] #themeToggle .ti-moon`).join(",\n")} { display: none; }\n` +
    `${lightThemes.map((n) => `    :root[data-theme="${n}"] #themeToggle .ti-sun`).join(",\n")} { display: inline; }`;

  return `    /* Theme picker chrome — swatch colours and the sun/moon glyph, per theme. */\n${swatches}\n\n${glyph}`;
}

export const REGISTRY_BEGIN = "/* >>> dfir-theme registry (generated) */";
export const REGISTRY_END = "/* <<< dfir-theme registry */";

/**
 * The theme registry, as a JS object literal for the picker.
 *
 * Generated rather than hand-maintained so it cannot drift from the CSS: a theme in the
 * menu with no matching block renders as the previous theme with a new name, and a block
 * with no menu entry is unreachable. `polarity` is computed from `--bg-primary`, not
 * taken from upstream's `group` — upstream files Sguil under "fun" and it is on a white
 * background, and the picker needs to know that to label it honestly.
 */
export function renderThemeRegistry(
  themes: Record<string, { label: string; group: string; palette: Record<string, string> }>,
  builtIn: Map<string, RoleValue>,
): string {
  const entries: string[] = [
    `      dark:  { label: "Dark",  group: "dark",  polarity: "dark"  },`,
    `      light: { label: "Light", group: "light", polarity: "light" },`,
  ];
  void builtIn;
  for (const name of Object.keys(themes).sort()) {
    const t = themes[name];
    const polarity = themePolarity(t.palette);
    entries.push(
      `      ${/^[a-z][\w]*$/.test(name) ? name : JSON.stringify(name)}: { label: ${JSON.stringify(t.label)}, group: ${JSON.stringify(t.group)}, polarity: ${JSON.stringify(polarity)} },`,
    );
  }
  return `${REGISTRY_BEGIN}
    // Theme palettes are third-party, MIT, (c) 2026 Security Onion Solutions, LLC;
    // see companion/scripts/theme/vendor/themePalettes.ts for the full notice.
    const DFIR_THEMES = {
${entries.join("\n")}
    };
    ${REGISTRY_END}`;
}

/**
 * Drop the four columns every template below is written at.
 *
 * The region used to be spliced into a `<style>` block inside dashboard.html, so it was authored
 * indented to sit under it. #415 moved the CSS into public/css/dashboard.css, where it belongs at
 * column 0 — and the whole stylesheet was moved by removing exactly these four columns from every
 * non-blank line, so applying the same transform here is what keeps the generated region looking
 * like its neighbours instead of like something pasted in.
 *
 * Done at the one return point rather than by re-indenting fifteen template literals: the
 * templates read as CSS either way, and a single documented transform is easier to verify than
 * fifteen edits that must all agree.
 */
const atColumnZero = (css: string): string =>
  css
    .split("\n")
    .map((line) => (line.startsWith("    ") ? line.slice(4) : line))
    .join("\n");

/** The generated token region, already split across the three stylesheet parts that hold it. */
export interface ThemeCssParts {
  /** public/css/dashboard-tokens.css — the begin marker, :root, and the dark/light overrides. */
  tokens: string;
  /** public/css/dashboard-themes-a.css — the first half of the imported themes. */
  themesA: string;
  /** public/css/dashboard-themes-b.css — the rest, the picker chrome, and the end marker. */
  themesB: string;
}

export function renderThemeCss(
  facts: VarFact[],
  map: Record<string, RoleAssignment>,
  values: Map<string, RoleValue>,
  alphas: AlphaAlias[],
): ThemeCssParts {
  const brand = Object.entries(TIER_C)
    .map(([varName, role]) => {
      const f = facts.find((x) => x.name === varName);
      return `      ${pad(`${role}:`, 24)} ${f?.dark ?? "#000000"};`;
    })
    .join("\n");

  const fallbacks = Object.entries(TIER_B)
    .map(([role, expr]) => `      ${pad(`${role}:`, 24)} ${expr};`)
    .join("\n");

  const tokens = atColumnZero(`    /* === dfir-theme tokens (issue #53) ===
       GENERATED by \`npm run theme:apply\` from companion/scripts/theme/. Do not
       hand-edit: the next run overwrites it. To change a colour, change the role
       definition in roleMap.ts and re-run.

       Colours are addressed by ROLE (--bg-primary, --sev-high), not by their own hex.
       A theme is the 25 tier A answers; the 20 tier B roles derive from those unless a
       theme overrides them, and the 4 brand constants are never themed. See
       scripts/theme/README.md for the full contract. */

    :root {
      /* Brand constants. Identical in every theme by design — theming these would make
         the product mark shift from theme to theme. */
${brand}

      /* Tier B fallbacks. Reached by any theme that defines only the 25 tier A roles,
         which is every imported theme. Must reference tier A only;
         tests/theme/roleMap.test.ts enforces that. */
${fallbacks}

      /* Base tier A values (dark), so the page still renders if the theme bootstrap
         never runs and no data-theme attribute is set. */
      color-scheme: dark;
      --hover-wash: rgba(255,255,255,.07);
${tierABlock(values, "dark")}

      /* Legacy aliases — transitional, see aliasBlock() in scripts/theme/themeCss.ts. */
${aliasBlock(map, alphas)}
    }

    :root[data-theme="dark"] {
      color-scheme: dark;
      --hover-wash: rgba(255,255,255,.07);
${tierABlock(values, "dark")}

      /* Explicit tier B, holding the exact pre-refactor colours rather than the
         derivations. Keeps dark mode pixel-identical to what shipped. */
${tierBExplicitBlock(values, "dark")}
    }

    :root[data-theme="light"] {
      color-scheme: light;
      --hover-wash: rgba(0,0,0,.06);
${tierABlock(values, "light")}

${tierBExplicitBlock(values, "light")}
    }

`);

  // THE GENERATED REGION SPANS THREE FILES SINCE #415, and the seams are chosen here rather than
  // found later by re-reading the output. Seam 1 is after the light :root block; seam 2 halves the
  // imported themes. Halving self-balances as themes are imported, where a fixed name or line
  // number would drift until one part crossed the 800-line limit and the split needed redoing.
  //
  // Concatenating the three IN THIS ORDER reproduces exactly what one file used to hold —
  // applyRoles asserts that on every run, because the cascade is only unchanged while it is true.
  const blocks = importedThemeBlocks(IMPORTED_THEMES);
  const half = Math.ceil(blocks.length / 2);
  const themesA = atColumnZero(`${blocks.slice(0, half).join("\n\n")}\n\n`);
  const themesB = atColumnZero(
    `${blocks.slice(half).join("\n\n")}

${renderThemeChrome(IMPORTED_THEMES, values)}

    /* === end dfir-theme tokens === */`,
  );
  // No trailing newline on themesB: findTokenRegion() ends the region at the end marker, so the
  // newline that followed it is still in the tail being appended. Emitting one here too
  // adds a blank line on every run and the file grows forever.
  return { tokens, themesA, themesB };
}
