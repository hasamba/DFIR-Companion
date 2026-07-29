# Dashboard colour roles

`public/dashboard.html` carries 149 CSS custom properties named after their own
dark-mode hex value (`--c-0d1117: #0d1117`), referenced from 1,894 call sites.
That scheme came from an automated "hoist every literal into a variable" pass. It
made a dark/light switch possible, but the names carry no meaning, near-duplicates
are indistinguishable (`#0d1017`, `#0d1117`, `#0f1115` and `#11141a` are all the
page background), and a third theme would mean hand-picking 149 unrelated hexes.

This directory holds the semantic layer that replaced it: **47 roles** that
components ask for by meaning, so a theme is the ~25 answers to "what colour is
each role" instead of 149. The dashboard now ships **24 themes**.

The migration has been applied. `dashboard.html` now addresses colour by role at all
1,996 call sites, and the old `--c-*` names survive only as aliases (`--c-0d1117:
var(--bg-primary)`) so any reference that arrives on another branch keeps working.

## Why these role names

An MIT-licensed upstream theme project ships 24 themes against exactly this shape —
`<html data-theme="...">` plus CSS custom properties, the same mechanism
`dashboard.html` already uses. Tier A below reuses its role names verbatim, so a
theme block copied out of its stylesheet drops in with no translation.

## The three tiers

| Tier | Count | What it is | Must a theme define it? |
|------|-------|------------|-------------------------|
| A | 25 | The upstream roles, spelled exactly as upstream spells them | Yes |
| B | 21 | Roles the companion needs and upstream has no equivalent for | No — each derives from tier A |
| C | 4 | Brand constants, identical in both existing palettes | No — never themed |

The generated CSS is laid out so that cascade order does the work:

```
:root                        brand constants, tier B derivations, legacy aliases,
                             and the dark tier A values as an unconditional base
:root[data-theme="dark"]     the built-in dark theme
:root[data-theme="light"]    the built-in light theme
:root[data-theme="nord"]     …and 21 more imported themes
.theme-swatch[data-for=…]    picker chrome, one rule per theme
```

The whole region is delimited by `/* === dfir-theme tokens` and
`/* === end dfir-theme tokens === */`. Those markers are load-bearing: an earlier
version inferred the end by walking the run of consecutive `:root {}` rules, which
held only while the region contained nothing else. Once it grew `.theme-swatch` rules
the walk stopped at the first of them, so each run replaced a prefix and re-prepended
a full copy — the region silently tripled and shipped three conflicting definitions of
every theme, with the last one quietly winning the cascade. `tests/theme/themeContrast.test.ts`
now asserts one marker pair and one block per theme.

The tier B derivations must sit at bare `:root` and the built-in themes' explicit
tier B values must sit behind `[data-theme]`. An imported theme is
`:root[data-theme="nord"]`, specificity (0,2,0); if our explicit `--sev-high` lived
at bare `:root` then nord — which never sets it — would inherit *our* severity orange
instead of deriving its own from nord's `--tag-orange-text`.

The dark tier A values appear twice, at `:root` and in the dark block. The theme
bootstrap is an inline `<script>` with a templated CSP nonce; if it is ever blocked
the `data-theme` attribute never appears, and without a base at `:root` the whole
dashboard would render with every colour undefined.

Tier B exists mostly because of **severity**. `.sev-Critical` through `.sev-Info`
is the most load-bearing colour family in the UI and upstream simply has no
equivalent, so `--sev-*` had to be invented. The rest of tier B fills in steps our
UI uses and upstream does not: five text weights rather than three, two border
weights, accent-as-surface distinct from accent-as-text, and derived status washes.

Every tier B role carries a fallback written only in tier A terms
(`--sev-high: var(--tag-orange-text)`). **That is the drop-in contract**: define
the 25, get the other 20 for free. `tests/theme/roleMap.test.ts` enforces it — a
fallback that leans on another tier B role fails the suite, because such a chain
can resolve to an undefined variable and render the component transparent.

## Commands

```bash
npm run theme:apply
```

Regenerates the token blocks in `dashboard.html` and rewrites every call site onto
roles. Idempotent — byte-identical output on a second run — so it is safe to re-run
after a merge brings in new `--c-` references from another branch.

```bash
npm run theme:map
```

Rewrites `role-map.json` and prints the audit. Run it after adding any colour.

```bash
npm run theme:check
```

Audit only, non-zero exit if a variable is unassigned or a brand constant picked up
a themed role.

`role-map.json` is **committed and authoritative**. It has to be: both the value and
the role of a variable are derived from the pre-migration file, and the migration
destroys both inputs — the palette becomes `--c-0d1117: var(--bg-primary)` and every
call site becomes `var(--bg-primary)`. A second run with no baseline would see a
variable with no colour and no call sites and reclassify it. Do not delete the file
to "regenerate from scratch"; there is nothing left to regenerate from.

## Reading the audit

The audit's job is to show where the collapse is **lossy**. A role whose member
hexes span a wide lightness range is a place the UI currently draws a distinction
the semantic layer would erase, and the fix is a role split, not a shrug. Four such
splits already came out of it:

- `--border-subtle` / `--border-color` — the hairline between table rows is not the
  outline around a raised card.
- `--accent` / `--accent-solid` — `#6aa9ff` is link and icon text across 105
  selectors; `#2d6cdf` is a primary button face. Merging them puts button-face blue
  on link text and fails contrast both ways.
- `--warning-bg` / `--warning-bg-strong` — amber surfaces span L 5.5 to 26, a subtle
  callout wash and a saturated badge face.
- `--accent-solid-hover` — see the hover conflict below.
- `--bg-elevated` — see the light-divergence note below.

Two roles are still flagged (`--tag-orange-text`, `--warning-border`). Both are
low-traffic gradients of one hue where the merge is the intended normalization.

The audit also flags roles whose members sit **together in dark but apart in light**.
Members are grouped by dark lightness, because dark is the palette the app was
designed in, and that reading is blind to this case. It caught a real one:
`--c-161a22` and `--c-161b22` are one point apart in dark and `#ffffff` versus
`#e4e9f2` in light — a white-panel-on-grey-page hierarchy that only exists in the
light theme. That produced `--bg-elevated`. Two low-traffic pairs remain flagged
(`--border-strong` at 9 call sites, `--text-muted` at 1).

## Known conflicts with upstream

**Hover direction.** Upstream's `--accent-hover` is *darker* than `--accent` in dark
themes. The dashboard brightens on hover at 8 of 10 accent-hover call sites and
darkens at 2. Tier A `--accent-hover` therefore means "brighter" here, and the two
darkening sites moved to `--accent-solid-hover`. Anyone porting an upstream theme
should expect its `--accent-hover` value to read as a hover *dimming* and may want
to swap it.

**Roles we never use.** `--modal-backdrop`, `--tag-blue-text` and `--tag-gray-text`
have no variable mapped onto them. They stay in tier A anyway so upstream blocks
paste in unchanged. `--sev-info` likewise has no variable of its own — `#6aa9ff`
serves both `.sev-Info` and the general accent, so it maps to `--accent` and
`--sev-info` falls back to it.

## Attribution

The upstream theme project is MIT, `Copyright (c) 2026 Security Onion Solutions,
LLC`. MIT into
AGPL-3.0 is the compatible direction, and the licence's one condition is that the
copyright and permission notice travel with any copy or substantial portion.

Two distinct things are taken from upstream, with different standing:

- **Role names** (`--bg-primary`, `--tag-orange-text`) are not copyrightable and carry
  no obligation. Reusing them is what makes an upstream theme block drop in unchanged.
- **Palettes** for 22 themes are a substantial portion and do carry the obligation. The
  MIT notice travels with them in `vendor/themePalettes.ts`, generated into the CSS
  blocks in `dashboard.html`, and recorded in the top-level [`NOTICE`](../../../NOTICE).

No upstream *source code* is included — only colour values and the names they are
keyed by. The combined work stays AGPL; MIT infects nothing.

Several palettes are third-party schemes (Nord, Gruvbox, Catppuccin, Tokyo Night,
Rosé Pine, Everforest, Kanagawa). Colour values are not copyrightable and every one
of those upstreams is permissively licensed, so crediting them by name in the theme
picker is courtesy rather than obligation — worth doing anyway.

## What the migration changed

Measured by loading the pre- and post-migration files side by side and comparing the
computed style of every rendered element:

| | dark | light |
|---|---|---|
| elements pixel-identical | 86.3% | 86.9% |
| call sites unchanged | 75.3% | 75.5% |
| shift under 10/255 (imperceptible) | 9.8% | 6.3% |
| shift 10–25 (visible on inspection) | 7.3% | 9.4% |
| shift over 25 (clearly different) | 3.9% | 5.1% |
| previously broken, now render | 3.8% | 3.8% |

The shifts are the point of the exercise: near-duplicates like `#0d1017` / `#0d1117`
/ `#0f1115` collapse onto one background role, and whichever had the most call sites
sets the value. Nothing moves further than the role it was assigned.

**42 variables were referenced but never declared** — `var(--c-2b3242)` and friends,
75 call sites, resolving to nothing so the property fell back to inherited or initial.
The naming convention makes the intent recoverable (the name *is* the hex), so they
were folded in and now render the colour they always claimed. That is a bug fix
riding along with a refactor; `npm run theme:map` lists all 42.

## The imported themes

`npm run theme:import -- <path-to-upstream-checkout>` rewrites
`vendor/themePalettes.ts` from a local checkout. 22 of upstream's 25 themes ship:

- **Upstream's `dark` and `light` are skipped.** Ours are tuned against this UI and
  hold the exact pre-refactor colours.
- **`c64` is rejected on legibility grounds** — body text at 2.26:1 against its
  background, and an inverted ramp where `--text-muted` (4.09:1) is *more* prominent
  than `--text-primary`. The importer enforces this as a rule about the palette, not a
  hardcoded name, so a future upstream theme with the same defect is caught too. See
  `auditPalette()` in `contrast.ts`.

Each generated block adds two things upstream has no concept of: `color-scheme`,
computed from `--bg-primary` luminance so scrollbars and form controls follow the
theme, and `--hover-wash` in the matching polarity.

### The text ramp is solved, not derived

This dashboard uses a five-step text ramp; upstream defines three. The two extra
steps sit *below* `--text-muted`, and the obvious CSS derivation — mix muted toward
the background — scales contrast down multiplicatively. That is fine when muted starts
high and unusable when it does not: upstream ships themes whose muted is already at
the floor (Nord 3.31:1, Kanagawa 3.33:1, Rosé Pine 2.73:1). Measured across the
imported set, a fixed ratio put `--text-faint` below 3:1 in **23 of 25 themes**, as
low as 1.55:1.

A stylesheet cannot branch on the result of a colour mix, but the generator has the
palette in hand, so `textRampSteps()` bisects for a concrete colour per theme: a 3:1
floor for the faintest step, capped at the theme's own muted contrast so a step below
muted can never end up more prominent than muted. Where a theme's muted is itself
under 3:1 the cap wins and the steps collapse onto muted — flatter than intended, but
legible, which is the right way to fail. `tests/theme/themeContrast.test.ts` asserts
both the floor and the ordering for every theme.

### The severity scale is solved too

Severity began as tier A fallbacks (`--sev-critical: var(--tag-red-text)`). That only
works if a theme supplies five distinct, severity-appropriate hues, and the tier A
vocabulary does not guarantee it. Measured across the imported set:

| defect | themes affected |
|---|---|
| a severity below 3:1 against its surface | 3 |
| an **adjacent** pair too close to tell apart | 10 |
| **Medium and Info the identical colour** (ΔE 0.000) | 18 |
| High and Medium the identical colour | 2 (Ristretto, CGA) |
| **Medium 70°–172° from amber** — a teal or blue | 11 |

The Medium/Info case is the one worth dwelling on. `--sev-medium` falls back to
`--help-icon-color` and `--sev-info` to `--accent`, and most themes set those two roles
to the same value. They are two ranks apart, so an adjacent-pair check never compares
them — the collision was invisible to the first version of the audit and shipped
looking fine.

The hue problem is the subtler one: a scale reading red, orange, **teal**, green, blue
passes every contrast and separation check and is still unreadable as an ordinal scale.

`solveSeverityScale()` in [`severity.ts`](severity.ts) repairs rather than replaces. A
theme's own colours are kept whenever they already satisfy the constraints, and only the
failures move, using the least destructive lever that works: snap an implausible hue to
the convention for its rank, then lightness, then chroma, then hue again to break a tie.
Chroma is never invented — it comes from the theme's own candidate, so Nord keeps muted
severity colours and Vaporwave keeps vivid ones, and a monochrome theme (Vantablack,
White) keeps its greys, told apart by lightness instead. The built-in dark theme's five
colours come through **byte-identical**, which the tests assert.

All 24 themes now clear 3:1 against both surfaces, ΔE 0.08 on **all ten pairs**, and sit
within 60° of the conventional hue for their rank.

One wiring bug came out of checking the rendered result rather than the variables:
`.sev-Info` resolved to `var(--accent)`, because the rewriter had mapped `#6aa9ff` to
`--accent` for its 105 other call sites. The solved `--sev-info` was never reaching the
page. Measuring the variables alone would not have caught it.

**Known limitation — colour-vision deficiency.** Under simulated deuteranopia and
protanopia, Critical and High converge (ΔE 0.016–0.088) in most themes. That is inherent
to a red→orange scale, not something the solver introduced, and fixing it would mean
abandoning the red-to-blue convention every SIEM already trains analysts on. It is
mitigated by the UI: severity is never conveyed by colour alone — every chip renders its
word next to the dot (`<span class="sev-dot"></span>Critical`). Worth revisiting if a
colour-only severity indicator is ever added.

### One deliberate adaptation

Upstream's `--accent-hover` is *darker* than its `--accent`; this dashboard brightens
on hover at 8 of its 10 accent-hover call sites. Importing verbatim would invert every
hover in 22 themes, so upstream's darker value becomes `--accent-solid-hover` (our
button-face hover, which does dim) and `--accent-hover` is derived toward
`--text-bright` — brightening in a dark theme and deepening in a light one.

## The picker

The header toggle opens a grouped menu (`renderThemeMenu()` in `dashboard.html`)
built with `createElement`/`textContent` rather than `innerHTML`, since it is the one
place a theme name reaches the DOM.

The stored theme is untrusted input — any script that ever ran on this origin could
have written it — and it goes straight into a DOM attribute, so it is checked twice:

1. The `<head>` bootstrap runs before the registry exists, so it applies a strict
   character allowlist (`/^[a-z][a-z0-9-]{0,31}$/`). It cannot know which names are
   real; it only guarantees nothing dangerous enters an attribute.
2. The main script re-checks against the generated registry and corrects an unknown
   name to the OS preference.

Being briefly wrong about *which* theme is a flash. Being wrong about what may enter
an attribute is not.

## What is not done

1. Mop up the ~177 hex literals still in CSS outside the token blocks and ~320 more
   in JS. These already ignore the existing light theme; 24 themes make that 24 times
   more visible.
2. Decide whether `mobile.html` and `present.html` join in. Neither supports
   `data-theme` at all today.
3. Drop the legacy alias block once a release has shipped with nothing referencing
   `--c-*`. `npm run theme:apply` reports the remaining count on every run.
4. Colour-vision deficiency in the severity scale — see the limitation noted above.
   Currently mitigated by the text label on every chip.
