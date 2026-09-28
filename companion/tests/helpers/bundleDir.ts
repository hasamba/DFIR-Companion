import { basename, dirname, join } from "node:path";

/**
 * A bundle-store directory that belongs to ONE test app (#1748).
 *
 * Bundles are a global store in production, so tests place the store beside the case root rather
 * than inside it. But every mkdtemp() root in a run shares one parent (vitest.config.ts points
 * TMPDIR at a single per-run root for every worker), so `join(dirname(root), "bundles")` was ONE
 * directory for every test file in every worker. veloBundle.test.ts saves overrides of the
 * built-in `best-practice` bundle there, and any later test that launched `best-practice` then
 * collected the overridden artifact list instead — one import-debug line where two were expected.
 *
 * The name carries the case root's own mkdtemp suffix, so it is unique per app and still sits
 * inside the run root that globalSetup deletes.
 */
export function privateBundleDir(caseRoot: string): string {
  return join(dirname(caseRoot), `bundles-${basename(caseRoot)}`);
}
