// WCAG contrast maths, shared by the theme importer, the CSS generator and the tests.
// All three need to agree on what "legible" means, so there is one implementation.

export type Rgb = [number, number, number];

export function hexToRgb(hex: string): Rgb {
  const s = hex.replace("#", "").trim();
  return [0, 2, 4].map((i) => parseInt(s.slice(i, i + 2), 16)) as Rgb;
}

export function rgbToHex([r, g, b]: Rgb): string {
  const h = (v: number) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, "0");
  return `#${h(r)}${h(g)}${h(b)}`;
}

export function relLuminance(rgb: Rgb): number {
  const [r, g, b] = rgb
    .map((v) => v / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG 2.x contrast ratio between two hex colours. */
export function contrastHex(a: string, b: string): number {
  const [hi, lo] = [relLuminance(hexToRgb(a)), relLuminance(hexToRgb(b))].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

export function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [relLuminance(a), relLuminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

export const mix = (a: Rgb, b: Rgb, t: number): Rgb =>
  [0, 1, 2].map((i) => a[i] + (b[i] - a[i]) * t) as Rgb;

/** A theme is light when its page background is. Drives `color-scheme`. */
export function isLightBackground(hex: string): boolean {
  return relLuminance(hexToRgb(hex)) > 0.5;
}

/**
 * Find the blend of `bg` toward `ink` whose contrast against `bg` is closest to `target`.
 *
 * WHY THIS IS COMPUTED RATHER THAN EXPRESSED IN CSS:
 *
 * The dashboard uses a five-step text ramp; upstream defines three. The missing two
 * (`--text-dim`, `--text-faint`) sit BELOW `--text-muted`, and the obvious CSS derivation
 * — mix muted toward the background — scales contrast down multiplicatively. That is fine
 * when muted starts high and unusable when it does not: upstream ships themes whose muted
 * is already at the floor (Nord 3.31:1, Kanagawa 3.33:1, Rosé Pine 2.73:1), and taking half
 * of that lands near 1.6:1, which is invisible. Measured across the imported set, a fixed
 * ratio put `--text-faint` below 3:1 in 23 of 25 themes.
 *
 * A stylesheet cannot branch on the result of a colour mix, but the generator has the
 * palette in hand, so it solves for a concrete colour per theme instead.
 */
export function solveForContrast(bg: Rgb, ink: Rgb, target: number): Rgb {
  // Contrast is monotonic in t along this axis, so bisection converges.
  if (contrast(ink, bg) <= target) return ink;
  let lo = 0;
  let hi = 1;
  for (let i = 0; i < 24; i++) {
    const midpoint = (lo + hi) / 2;
    if (contrast(mix(bg, ink, midpoint), bg) < target) lo = midpoint;
    else hi = midpoint;
  }
  return mix(bg, ink, hi);
}

/** The five-step ramp, most prominent first. */
export const TEXT_RAMP = [
  "--text-bright",
  "--text-primary",
  "--text-muted",
  "--text-dim",
  "--text-faint",
] as const;

/** Body text must clear this against the page background. */
export const BODY_CONTRAST_FLOOR = 4.5;

/** Incidental text (placeholders, disabled controls, timestamps) must clear this. */
export const INCIDENTAL_CONTRAST_FLOOR = 3.0;

/**
 * Check the three invariants an imported palette has to satisfy to be shippable.
 * Returns human-readable problems; an empty array means the palette is fine.
 *
 * Only the roles a theme actually supplies are checked — `--text-dim` and `--text-faint`
 * are solved for later by the generator, so they are not upstream's responsibility.
 */
export function auditPalette(palette: Record<string, string>): string[] {
  const problems: string[] = [];
  const bg = palette["--bg-primary"];
  if (!bg) return ["no --bg-primary"];

  const primary = contrastHex(palette["--text-primary"], bg);
  if (primary < BODY_CONTRAST_FLOOR) {
    problems.push(
      `--text-primary is ${primary.toFixed(2)}:1 against --bg-primary (need ${BODY_CONTRAST_FLOOR}:1)`,
    );
  }

  // The ramp must not invert: secondary text louder than body text reads as emphasis
  // pointing at the wrong thing.
  const supplied = ["--text-bright", "--text-primary", "--text-muted"];
  for (let i = 1; i < supplied.length; i++) {
    const above = contrastHex(palette[supplied[i - 1]], bg);
    const below = contrastHex(palette[supplied[i]], bg);
    if (below > above + 0.01) {
      problems.push(
        `${supplied[i]} (${below.toFixed(2)}:1) is more prominent than ${supplied[i - 1]} (${above.toFixed(2)}:1)`,
      );
    }
  }
  return problems;
}
