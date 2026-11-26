import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// #2923: `.vql-result-wrap` is a scroll container (overflow:auto, max-height 260px) around a plain
// table, which has nothing focusable inside. A keyboard user could not scroll it, and axe reported
// scrollable-region-focusable on the Timeline Gaps table in the Analyst view. Only the table that
// happens to overflow on a given case is flagged, so the e2e scan alone would miss a wrapper whose
// panel is short on the demo case. This pins every place the dashboard emits one: a tab stop, a
// region role, and a name — a sixth render site that forgets them fails here.

const JS_DIR = join(import.meta.dirname, "..", "..", "..", "public", "js");

/** Every opening tag of a vql-result-wrap emitted from public/js, with the file it came from. */
function wrapperTags(): { file: string; tag: string }[] {
  const found: { file: string; tag: string }[] = [];
  for (const file of readdirSync(JS_DIR).filter((f) => f.endsWith(".js"))) {
    const src = readFileSync(join(JS_DIR, file), "utf8");
    for (const m of src.matchAll(/<div class="vql-result-wrap"[^>]*>/g)) found.push({ file, tag: m[0] });
  }
  return found;
}

describe("scrolling result tables are keyboard-reachable (#2923)", () => {
  const tags = wrapperTags();

  it("finds the wrappers it guards", () => {
    // Timeline gaps, anomalies, beacons, cloud coverage, renderVqlRows.
    expect(tags.length).toBeGreaterThanOrEqual(5);
  });

  it.each(tags.map((t) => [t.file, t.tag]))("%s: %s", (_file, tag) => {
    expect(tag).toContain('tabindex="0"');
    expect(tag).toContain('role="region"');
    expect(tag).toMatch(/aria-label="[^"]+"/);
  });
});
