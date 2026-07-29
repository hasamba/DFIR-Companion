// Loads scripts/theme/role-map.json, the committed record of what every `--c-` variable
// was worth and which role it belongs to.
//
// WHY A BASELINE IS REQUIRED, not just convenient:
//
// Both the value and the ROLE of a variable are derived from the pre-migration file.
// The value comes from the palette block, and the role comes largely from how the
// variable is used — a hex at lightness 20 is a panel background or a card border only
// according to the CSS properties it feeds. The migration destroys both inputs: the
// palette becomes `--c-0d1117: var(--bg-primary)` and every call site becomes
// `var(--bg-primary)`, so a second run would see a variable with no colour and no call
// sites and reclassify it as something else.
//
// So role-map.json is the source of truth once written, and the tooling reads it back
// rather than re-deriving. New `--c-` names appearing after the migration are handled
// on their own terms: with no palette block to declare them, they are phantoms, and the
// naming convention means their value is recoverable from the name.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export const ROLE_MAP_PATH = join(here, "role-map.json");
export const DASHBOARD_PATH = join(here, "..", "..", "..", "public", "dashboard.html");

export interface BaselineEntry {
  dark: string;
  light: string | null;
  role: string;
  cls: "SURFACE" | "BORDER" | "TEXT" | "CANVAS";
  uses: number;
  phantom: boolean;
}

export type Baseline = Record<string, BaselineEntry>;

export function loadBaseline(): Baseline | undefined {
  if (!existsSync(ROLE_MAP_PATH)) return undefined;
  return JSON.parse(readFileSync(ROLE_MAP_PATH, "utf8")) as Baseline;
}
