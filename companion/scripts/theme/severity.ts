// Solves the five-step severity scale for a theme.
//
// WHY THE FALLBACKS ARE NOT ENOUGH
//
// Severity started as tier A fallbacks — `--sev-critical: var(--tag-red-text)` and so on.
// That works only if a theme supplies five distinct, severity-appropriate hues, and the
// tier A vocabulary does not guarantee it. Measured across the imported set:
//
//   * `--sev-medium` falls back to `--help-icon-color`, which 18 of 22 themes set to the
//     same value as `--accent` — so Medium and Info shipped as the IDENTICAL colour. They
//     are two ranks apart, so an adjacent-pair check never compared them
//   * that same role is a blue or a teal in most themes, putting Medium 70°-172° away from
//     amber and giving a scale that reads red, orange, TEAL, green, blue
//   * Ristretto and CGA set `--tag-orange-text` and `--help-icon-color` to the same value,
//     so High and Medium were identical too — OKLab ΔE 0.000
//   * ten of 22 themes had an adjacent pair under the separation floor, and three had a
//     severity below 3:1 against the surface it sits on
//
// In a forensics tool a severity scale that cannot be read at a glance is not a cosmetic
// problem: mistaking High for Critical while triaging changes what an analyst does next.
//
// WHAT THIS DOES
//
// It repairs, rather than replaces. A theme's own severity colours are kept whenever they
// already satisfy the constraints, so themes that were fine look exactly as before — the
// built-in dark theme comes through byte-identical. Only the failures are adjusted, in
// the least destructive order:
//
//   0. hue       — snapped to the convention for its rank when the candidate is more than
//                  SEVERITY_HUE_BAND away from it
//   1. hue       — snapped when two severities (ANY pair, not just adjacent) collide;
//                  the lower-ranked one moves, so Critical keeps the theme's red
//   2. lightness — moved until the colour clears the contrast floor against the worse of
//                  the two surfaces it renders on
//   3. lightness, then chroma, then hue — whichever is needed to pull apart a pair that
//                  is still too close to tell apart, iterated until every pair passes
//
// Chroma is never invented: it comes from the theme's own candidate, so a muted theme like
// Nord keeps muted severity colours and Vaporwave keeps vivid ones. A monochrome theme
// (Vantablack, White) keeps its greys — hue is meaningless at zero chroma, and the
// separation pass distinguishes those ranks by lightness instead.

import { contrast, hexToRgb, type Rgb, rgbToHex } from "./contrast.js";

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

/** Which tier A role each severity falls back to when a theme sets no explicit value. */
export const SEVERITY_FALLBACK: Record<Severity, string> = {
  critical: "--tag-red-text",
  high: "--tag-orange-text",
  medium: "--help-icon-color",
  low: "--tag-green-text",
  info: "--accent",
};

/**
 * Canonical OKLCh hues for each rank. Red-through-blue is the convention every SIEM and
 * scanner already trains analysts on; a theme is free to shade it, but not to make
 * Critical green or Medium teal.
 */
export const CANONICAL_HUE: Record<Severity, number> = {
  critical: 27,
  high: 55,
  medium: 92,
  low: 148,
  info: 250,
};

/** Severity text sits on chips and rows; 4.5:1 is the target, 3:1 the hard floor. */
export const SEVERITY_CONTRAST_TARGET = 4.5;
export const SEVERITY_CONTRAST_FLOOR = 3.0;

/**
 * Minimum OKLab distance between adjacent severities.
 *
 * Calibration: ~0.02 is a just-noticeable difference under ideal viewing. These are small
 * chips read peripherally while scanning a table, so the bar is higher. 0.08 admits the
 * orange/amber step of the existing dark theme (0.092), which is comfortably readable in
 * practice, and rejects every pair that measured confusable.
 */
export const SEVERITY_SEPARATION_FLOOR = 0.08;

/**
 * How far a theme's candidate hue may sit from the convention for its rank before it is
 * snapped. 60° is wide enough to let a theme shade the scale — a brick-red Critical, an
 * amber-leaning High — and narrow enough to reject a teal Medium.
 */
export const SEVERITY_HUE_BAND = 60;

// ---------------------------------------------------------------------------
// OKLab / OKLCh
// ---------------------------------------------------------------------------

const toLinear = (v: number) => {
  const c = v / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
};
const fromLinear = (c: number) => {
  const v = c <= 0.0031308 ? c * 12.92 : 1.055 * c ** (1 / 2.4) - 0.055;
  return v * 255;
};

export type Oklab = [number, number, number];
export type Oklch = { L: number; C: number; h: number };

export function rgbToOklab(rgb: Rgb): Oklab {
  const [r, g, b] = rgb.map(toLinear);
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ];
}

function oklabToRgbRaw([L, a, b]: Oklab): [number, number, number] {
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return [
    fromLinear(4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s),
    fromLinear(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s),
    fromLinear(-0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s),
  ];
}

export const oklabToOklch = ([L, a, b]: Oklab): Oklch => ({
  L,
  C: Math.hypot(a, b),
  h: ((Math.atan2(b, a) * 180) / Math.PI + 360) % 360,
});

export const oklchToOklab = ({ L, C, h }: Oklch): Oklab => [
  L,
  C * Math.cos((h * Math.PI) / 180),
  C * Math.sin((h * Math.PI) / 180),
];

const inGamut = (p: [number, number, number]) => p.every((v) => v >= -0.5 && v <= 255.5);

/**
 * OKLCh to sRGB, reducing chroma until the colour fits the gamut. Clipping channels
 * instead would shift hue — the thing the whole scale depends on staying put.
 */
export function oklchToRgb(c: Oklch): Rgb {
  if (inGamut(oklabToRgbRaw(oklchToOklab(c)))) {
    return oklabToRgbRaw(oklchToOklab(c)).map((v) => Math.round(Math.min(255, Math.max(0, v)))) as Rgb;
  }
  let lo = 0;
  let hi = c.C;
  for (let i = 0; i < 20; i++) {
    const mid = (lo + hi) / 2;
    if (inGamut(oklabToRgbRaw(oklchToOklab({ ...c, C: mid })))) lo = mid;
    else hi = mid;
  }
  return oklabToRgbRaw(oklchToOklab({ ...c, C: lo })).map((v) =>
    Math.round(Math.min(255, Math.max(0, v))),
  ) as Rgb;
}

export const deltaE = (a: Rgb, b: Rgb): number => {
  const [x, y] = [rgbToOklab(a), rgbToOklab(b)];
  return Math.hypot(x[0] - y[0], x[1] - y[1], x[2] - y[2]);
};

/** Smallest angular gap between two hues, in degrees. */
const hueGap = (a: number, b: number) => {
  const d = Math.abs(a - b) % 360;
  return d > 180 ? 360 - d : d;
};

// ---------------------------------------------------------------------------
// The solver
// ---------------------------------------------------------------------------

/**
 * Move a colour's lightness until it clears `target` against both surfaces, keeping hue
 * and chroma. Searches away from the background: darker on a light theme, lighter on a
 * dark one. Returns the input unchanged when it already passes.
 */
function solveLightness(c: Oklch, surfaces: Rgb[], target: number): Oklch {
  const worst = (x: Oklch) => Math.min(...surfaces.map((s) => contrast(oklchToRgb(x), s)));
  if (worst(c) >= target) return c;

  // Which direction helps depends on the background, and a mid-tone surface may only be
  // clearable in one of them. Try both and keep whichever gets closest.
  let best = c;
  let bestScore = worst(c);
  for (const dir of [1, -1]) {
    let lo = c.L;
    let hi = dir > 0 ? 1 : 0;
    for (let i = 0; i < 24; i++) {
      const mid = (lo + hi) / 2;
      const cand = { ...c, L: mid };
      if (worst(cand) < target) lo = mid;
      else hi = mid;
    }
    const cand = { ...c, L: hi };
    const score = worst(cand);
    if (score > bestScore) {
      best = cand;
      bestScore = score;
    }
  }
  return best;
}

export interface SeveritySolution {
  colors: Record<Severity, string>;
  /** What had to be changed, for the audit. Empty when the theme was already fine. */
  repairs: string[];
}

/**
 * Solve the severity scale for one theme.
 *
 * @param candidates hex per severity — a theme's explicit `--sev-*` where it sets them,
 *                   otherwise the tier A fallback role's value
 * @param surfaces   the backgrounds severity text renders on (page and panel)
 */
export function solveSeverityScale(
  candidates: Record<Severity, string>,
  surfaces: Rgb[],
): SeveritySolution {
  const repairs: string[] = [];
  const lch: Record<Severity, Oklch> = {} as Record<Severity, Oklch>;
  for (const s of SEVERITY_ORDER) {
    // A candidate that is not a plain hex — an unresolved `var()`, an `rgba()`, a typo —
    // must not reach the maths, or it yields NaN channels and serialises to `#NaNNaNNaN`,
    // which the browser drops silently and the role falls back to inherited text colour.
    // Start from the canonical hue instead and let the contrast pass place it.
    if (!/^#[0-9a-fA-F]{6}$/.test(candidates[s] ?? "")) {
      repairs.push(`${s}: candidate ${JSON.stringify(candidates[s])} is not a hex colour, using canonical hue`);
      lch[s] = { L: 0.7, C: 0.14, h: CANONICAL_HUE[s] };
      continue;
    }
    lch[s] = oklabToOklch(rgbToOklab(hexToRgb(candidates[s])));
  }

  // 0. Hues that are not plausible for their rank.
  //
  //    `--sev-medium` falls back to `--help-icon-color`, which most themes set to a blue
  //    or a teal — measured 70° to 172° away from amber in 11 of the 22 imported themes,
  //    and identical to `--accent` in 18 of them. A severity scale that runs
  //    red, orange, TEAL, green, blue is not one an analyst can read at a glance, however
  //    well it scores on contrast and separation.
  //
  //    Only the hue is replaced; chroma and lightness stay, so a muted theme gets a muted
  //    amber and a vivid one gets a vivid amber. Themes whose candidate is already in the
  //    right neighbourhood are untouched, which is most of them for every rank but Medium.
  for (const s of SEVERITY_ORDER) {
    const off = hueGap(lch[s].h, CANONICAL_HUE[s]);
    if (off <= SEVERITY_HUE_BAND) continue;
    repairs.push(
      `${s}: hue ${lch[s].h.toFixed(0)}° is ${off.toFixed(0)}° from the ${CANONICAL_HUE[s]}° convention, snapped`,
    );
    lch[s] = { ...lch[s], h: CANONICAL_HUE[s] };
  }

  // 1. Hue collisions, across EVERY pair rather than only adjacent ones.
  //
  //    Checking adjacent pairs alone leaves the worst case untouched: `--sev-medium`
  //    falls back to `--help-icon-color` and `--sev-info` to `--accent`, and 18 of the
  //    22 imported themes give those two roles the same value. Medium and Info are two
  //    ranks apart, so an adjacent-only pass never compares them and they shipped as
  //    literally the same colour.
  //
  //    Repairs move the LOWER-ranked member, so Critical keeps the theme's red and
  //    ambiguity is pushed down the scale.
  for (let i = 0; i < SEVERITY_ORDER.length; i++) {
    for (let j = i + 1; j < SEVERITY_ORDER.length; j++) {
      const hi = SEVERITY_ORDER[i];
      const lo = SEVERITY_ORDER[j];
      if (hueGap(lch[hi].h, lch[lo].h) >= 12) continue;
      repairs.push(
        `${lo}: hue ${lch[lo].h.toFixed(0)}° collided with ${hi} (${lch[hi].h.toFixed(0)}°), moved to canonical ${CANONICAL_HUE[lo]}°`,
      );
      lch[lo] = { ...lch[lo], h: CANONICAL_HUE[lo] };
      // A theme that collapsed two severities usually gave them no chroma to tell apart
      // either; borrow the neighbour's so the repaired step still looks like the theme.
      if (lch[lo].C < 0.02) lch[lo] = { ...lch[lo], C: Math.max(lch[hi].C, 0.08) };
    }
  }

  // 2. Contrast against the surfaces.
  for (const s of SEVERITY_ORDER) {
    const before = Math.min(...surfaces.map((x) => contrast(oklchToRgb(lch[s]), x)));
    if (before < SEVERITY_CONTRAST_TARGET) {
      const fixed = solveLightness(lch[s], surfaces, SEVERITY_CONTRAST_TARGET);
      const after = Math.min(...surfaces.map((x) => contrast(oklchToRgb(fixed), x)));
      if (after > before + 0.01) {
        repairs.push(`${s}: contrast ${before.toFixed(2)}:1 -> ${after.toFixed(2)}:1`);
        lch[s] = fixed;
      }
    }
  }

  // 3. Any adjacent pair still too close is separated with three levers, applied in order
  //    of least damage to the theme's character. Lightness first, because it keeps both
  //    hue and chroma; then chroma, which keeps hue; then hue toward canonical, which is
  //    the same repair as step 1 but driven by the MEASURED distance rather than the hue
  //    gap. A wide hue gap does not guarantee separation — two colours can sit far apart
  //    in hue and still land close in OKLab when lightness and chroma nearly match.
  const worstContrast = (c: Oklch) => Math.min(...surfaces.map((x) => contrast(oklchToRgb(c), x)));
  const gap = (a: Severity, b: Severity) => deltaE(oklchToRgb(lch[a]), oklchToRgb(lch[b]));

  // Every pair, repeatedly: separating one pair can close another, so iterate until no
  // pair is under the floor or the rounds run out. Five ranks means ten pairs; three
  // rounds is ample and bounds the work.
  for (let round = 0; round < 3; round++) {
    let worked = false;
    for (let i = 0; i < SEVERITY_ORDER.length; i++) {
      for (let j = i + 1; j < SEVERITY_ORDER.length; j++) {
        const hi = SEVERITY_ORDER[i];
        const lo = SEVERITY_ORDER[j];
        if (gap(hi, lo) >= SEVERITY_SEPARATION_FLOOR) continue;
        const before = gap(hi, lo);

        // Lever 1: lightness, away from the neighbour, as far as the contrast floor allows.
        const dir = lch[lo].L <= lch[hi].L ? -1 : 1;
        for (let step = 1; step <= 12 && gap(hi, lo) < SEVERITY_SEPARATION_FLOOR; step++) {
          const cand = { ...lch[lo], L: Math.min(1, Math.max(0, lch[lo].L + dir * 0.02 * step)) };
          if (worstContrast(cand) < SEVERITY_CONTRAST_FLOOR) break;
          lch[lo] = cand;
        }

        // Lever 2: chroma. Saturating the lower-ranked step reads as "more urgent", so it
        // moves in the direction the scale already implies.
        for (let step = 1; step <= 8 && gap(hi, lo) < SEVERITY_SEPARATION_FLOOR; step++) {
          const cand = { ...lch[lo], C: Math.min(0.4, lch[lo].C + 0.015 * step) };
          if (worstContrast(cand) < SEVERITY_CONTRAST_FLOOR) break;
          lch[lo] = cand;
        }

        // Lever 3: hue, interpolated toward the canonical hue for this rank.
        if (gap(hi, lo) < SEVERITY_SEPARATION_FLOOR) {
          const from = lch[lo].h;
          const delta = ((CANONICAL_HUE[lo] - from + 540) % 360) - 180;
          for (let step = 1; step <= 10 && gap(hi, lo) < SEVERITY_SEPARATION_FLOOR; step++) {
            const cand = { ...lch[lo], h: (from + delta * (step / 10) + 360) % 360 };
            if (worstContrast(cand) < SEVERITY_CONTRAST_FLOOR) break;
            lch[lo] = cand;
          }
        }

        const after = gap(hi, lo);
        if (after > before + 0.001) {
          worked = true;
          if (round === 0) {
            repairs.push(`${lo}: separation from ${hi} ${before.toFixed(3)} -> ${after.toFixed(3)}`);
          }
        }
      }
    }
    if (!worked) break;
  }

  const colors = {} as Record<Severity, string>;
  for (const s of SEVERITY_ORDER) colors[s] = rgbToHex(oklchToRgb(lch[s]));
  return { colors, repairs };
}
