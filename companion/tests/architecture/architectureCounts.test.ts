import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { architectureWithCounts } from "../../scripts/architectureCounts.mjs";
import { runScript } from "../helpers/runScript.js";

// #907. moduleMap.test.ts asserts that ARCHITECTURE.md's derived figures match the boundary scan.
// This asserts the other half — that the writer which produces those figures agrees with the reader
// that checks them. Two regexes over one document, and nothing but these tests keeps them in step.

const ROOT = new URL("../../../", import.meta.url);
const readDoc = (): Promise<string> => readFile(new URL("ARCHITECTURE.md", ROOT), "utf8");

const boundaryCounts = (): { crossDomain: number; complying: number; violations: number } =>
  // fileURLToPath, not `.pathname` — see the note in moduleMap.test.ts about Windows drives.
  JSON.parse(
    runScript(fileURLToPath(new URL("companion/scripts/check-boundaries.mjs", ROOT)), ["--json"]),
  ) as { crossDomain: number; complying: number; violations: number };

describe("architectureWithCounts (#907)", () => {
  it("rewrites the comply/total pair, grouped the way the guard test reads it", () => {
    const out = architectureWithCounts(
      "For context: **1 of the 2 cross-domain file dependencies already comply.**",
      {
        complying: 1983,
        crossDomain: 2022,
        violations: 39,
      },
    );

    expect(out.text).toBe(
      "For context: **1,983 of the 2,022 cross-domain file dependencies already comply.**",
    );
    expect(out.pair).toBe(true);
    expect(out.changed).toBe(true);
  });

  it("writes the violation count WITHOUT a separator, because the guard test matches it with a bare \\d+", () => {
    // The load-bearing asymmetry. "1,039 violations" would satisfy this writer and then be read as
    // "039" by moduleMap.test.ts — a disagreement that only appears once the ledger passes 999.
    const out = architectureWithCounts("records the **39 violations** that break the map", {
      complying: 0,
      crossDomain: 1039,
      violations: 1039,
    });

    expect(out.text).toContain("**1039 violations**");
    expect(/(\d+)\s+violations/.exec(out.text)?.[1]).toBe("1039");
  });

  it("moves only the ledger number in 'N of the M recorded violations', not the type-only count", () => {
    const out = architectureWithCounts("**15 of the 39 recorded violations are type-only**", {
      complying: 0,
      crossDomain: 0,
      violations: 41,
    });

    expect(out.text).toBe("**15 of the 41 recorded violations are type-only**");
    expect(out.violationClaims).toBe(1);
  });

  it("rewrites every violation claim in the document, not just the first", () => {
    const out = architectureWithCounts("the 39 violations here, and the 39 recorded violations there", {
      complying: 0,
      crossDomain: 0,
      violations: 7,
    });

    expect(out.text).toBe("the 7 violations here, and the 7 recorded violations there");
    expect(out.violationClaims).toBe(2);
  });

  it("reports a missing sentence and leaves the text alone rather than inventing prose", () => {
    const out = architectureWithCounts("A document that no longer says any of it.", {
      complying: 1,
      crossDomain: 2,
      violations: 3,
    });

    expect(out.pair).toBe(false);
    expect(out.violationClaims).toBe(0);
    expect(out.changed).toBe(false);
    expect(out.text).toBe("A document that no longer says any of it.");
  });

  it("is a no-op on the real ARCHITECTURE.md, so the writer and the committed doc already agree", async () => {
    // The join to reality. Every case above is synthetic; this one fails if the writer would rewrite
    // the live document differently from what is committed — which is exactly the drift #907 is about.
    const doc = await readDoc();
    const out = architectureWithCounts(doc, boundaryCounts());

    expect(out.pair, "ARCHITECTURE.md should still state the comply/total pair").toBe(true);
    expect(out.violationClaims, "ARCHITECTURE.md should still state a violation count").toBeGreaterThan(0);
    expect(out.changed, "check:boundaries --update would rewrite ARCHITECTURE.md right now").toBe(false);
  });

  it("returns exactly the keys architectureCounts.d.mts declares", () => {
    // The .d.mts is hand-written, so nothing stops it drifting from the module it describes. This is
    // what stops it: a declaration that has gone stale fails here rather than type-checking a lie.
    const out = architectureWithCounts("nothing derived here", {
      complying: 1,
      crossDomain: 2,
      violations: 3,
    });

    expect(Object.keys(out).sort()).toEqual(["changed", "pair", "text", "violationClaims"]);
    expect(typeof out.text).toBe("string");
    expect(typeof out.changed).toBe("boolean");
    expect(typeof out.pair).toBe("boolean");
    expect(typeof out.violationClaims).toBe("number");
  });

  it("is idempotent — re-running it over its own output changes nothing", async () => {
    const counts = boundaryCounts();
    const once = architectureWithCounts(await readDoc(), counts);

    expect(architectureWithCounts(once.text, counts).text).toBe(once.text);
  });
});
