// companion/src/version.ts
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// The running Companion version, resolved across all three runtimes:
//   1. DFIR_BUILD_VERSION   — baked into the SEA bundle by build-sea.mjs (no package.json there).
//   2. npm_package_version  — set by npm in dev (`npm run dev` / `npm test`).
//   3. ../package.json      — Docker / `node dist/server.js` (package.json is one level up from dist/).
//   4. "unknown"            — last resort.
export function getAppVersion(): string {
  const baked = process.env.DFIR_BUILD_VERSION;
  if (baked && baked.trim() && baked !== "undefined") return baked.trim();
  const npmVer = process.env.npm_package_version;
  if (npmVer && npmVer.trim()) return npmVer.trim();
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")) as { version?: unknown };
    if (typeof pkg.version === "string" && pkg.version.trim()) return pkg.version.trim();
  } catch {
    // package.json not adjacent (e.g. SEA without a baked version) — fall through.
  }
  return "unknown";
}
