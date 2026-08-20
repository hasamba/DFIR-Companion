import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { AI_LIMIT_PATHS, AI_LIMIT_PATTERNS } from "../../src/composition/aiRateLimit.js";

/**
 * composition/aiRateLimit.ts claims its path set "covers EVERY route that issues an LLM call".
 * It did not. Eight AI routes added after that file was written were never added to the set, so an
 * attacker who knew a caseId could burn the operator's AI budget by using any of them instead of
 * /synthesize. The comment stayed true-looking the whole time, because nothing checked it.
 *
 * So check it. Every POST under /cases/:id whose handler gates on an AI provider must be either
 * covered by the limiter or named in EXCLUDED below with a reason. A new AI route now fails this
 * test until someone makes that choice deliberately.
 *
 * Scanning the ROUTES is textual on purpose. Resolving the real Express layer stack would need a
 * booted app and would tell us which paths are mounted, not which ones spend money — and "spends
 * money" is the property this guards. The AI gate is a route's own `hasSynthesisProvider()` /
 * "AI provider not configured" precondition, which is uniform across the route files.
 *
 * The limiter's own coverage is IMPORTED, not parsed. The first version of this test read the two
 * declarations out of the source with a regex and passed — until Prettier collapsed the pattern
 * array onto one line and the regex silently stopped seeing its last entry. One value, two readers.
 */
const ROUTES_DIR = fileURLToPath(new URL("../../src/routes/", import.meta.url));

/** Routes that bear AI cost and are deliberately NOT rate-limited. Each needs a reason. */
const EXCLUDED = new Map([
  [
    "/push",
    "external collector ingest, authenticated by a per-case push token rather than a session — " +
      "knowing a caseId is not enough to reach it, and a 20/min cap would throttle a bulk collector",
  ],
]);

/** Every `/cases/:id/...` POST whose handler gates on an AI provider, as `/suffix`. */
function aiGatedRoutes(): string[] {
  const found = new Set<string>();
  for (const file of readdirSync(ROUTES_DIR).filter((f) => f.endsWith(".ts"))) {
    const src = readFileSync(join(ROUTES_DIR, file), "utf8");
    const re = /\n {2}app\.post\("(\/cases\/:id[^"]*)"/g;
    for (let m = re.exec(src); m; m = re.exec(src)) {
      const rest = src.slice(m.index + m[0].length);
      const next = rest.indexOf("\n  app.");
      const handler = next > 0 ? rest.slice(0, next) : rest;
      if (/hasSynthesisProvider|AI provider not configured|synthesisProvider/.test(handler)) {
        found.add(m[1].slice("/cases/:id".length));
      }
    }
  }
  return [...found].sort();
}

/** A route suffix with its params filled in, so a pattern can be tested against it. */
const concrete = (suffix: string): string => suffix.replace(/:[A-Za-z]+/g, "x").toLowerCase();

describe("AI rate limiter ↔ the routes that spend AI budget", () => {
  it("finds the AI routes at all (guards against a scan that silently matches nothing)", () => {
    const routes = aiGatedRoutes();
    expect(routes.length).toBeGreaterThan(15);
    expect(routes).toContain("/synthesize");
  });

  it("imports a limiter coverage list that is actually populated", () => {
    expect(AI_LIMIT_PATHS.has("/synthesize")).toBe(true);
    expect(AI_LIMIT_PATTERNS.some((re) => re.test("/events/ev1/explain"))).toBe(true);
  });

  it("covers or explicitly excludes every AI-gated POST route", () => {
    const uncovered = aiGatedRoutes().filter((suffix) => {
      if (EXCLUDED.has(suffix)) return false;
      const rel = concrete(suffix);
      return !AI_LIMIT_PATHS.has(rel) && !AI_LIMIT_PATTERNS.some((re) => re.test(rel));
    });

    expect(
      uncovered,
      "these routes issue an LLM call with no rate limit — add them to AI_LIMIT_PATHS " +
        "(or AI_LIMIT_PATTERNS if they carry a dynamic segment), or to EXCLUDED here with a reason",
    ).toEqual([]);
  });

  it("keeps every EXCLUDED entry pointing at a route that still exists", () => {
    // A stale exclusion is worse than none: it reads as a considered decision about a route that
    // was renamed or deleted, and hides the successor.
    const routes = new Set(aiGatedRoutes());
    expect([...EXCLUDED.keys()].filter((s) => !routes.has(s))).toEqual([]);
  });
});
