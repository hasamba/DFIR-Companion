import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

// `a11y/tooltips.js` copies a control's `data-tip` into `aria-label` ONCE, at page load, when the
// control has no other name. A script that later rewrites `data-tip` on an icon-only control
// (Dashboard view, Case lifecycle) changes the hover card but not the name a screen reader reads,
// so the analyst hears the stale first value. Such a script must write `aria-label` too. (#2469)

const HTML = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
const JS_DIR = new URL("../../../public/js/", import.meta.url);

/** Ids of tipped controls whose markup carries no visible text and no explicit aria-label. */
function iconOnlyTippedIds(): Set<string> {
  const ids = new Set<string>();
  const tagRe = /<(button|a)\b([^>]*\sdata-tip=[^>]*)>([\s\S]*?)<\/\1>/g;
  for (const [, , attrs, inner] of HTML.matchAll(tagRe)) {
    const id = /\sid="([^"]+)"/.exec(attrs)?.[1];
    if (!id || /\saria-label=/.test(attrs)) continue;
    const text = inner
      .replace(/<svg[\s\S]*?<\/svg>/g, "")
      .replace(/<[^>]+>/g, "")
      .trim();
    if (!text) ids.add(id);
  }
  return ids;
}

/** `[file, id]` for each script that rewrites data-tip on a bound element without its aria-label. */
function tipWritesWithoutName(): Array<[string, string]> {
  const hits: Array<[string, string]> = [];
  const files = readdirSync(JS_DIR, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".js"));
  for (const file of files) {
    const src = readFileSync(new URL(file, JS_DIR), "utf8");
    const binding = /\b(?:const|let|var)\s+(\w+)\s*=\s*document\.getElementById\(\s*["'](\w+)["']\s*\)/g;
    for (const [, name, id] of src.matchAll(binding)) {
      const tipWrite = new RegExp(`\\b${name}\\.dataset\\.tip\\s*=[^=]`);
      const nameWrite = new RegExp(`\\b${name}\\.setAttribute\\(\\s*["']aria-label["']`);
      if (tipWrite.test(src) && !nameWrite.test(src)) hits.push([file, id]);
    }
  }
  return hits;
}

describe("icon-only tipped controls keep their accessible name in sync (#2469)", () => {
  it("finds the icon-only controls whose tip changes at runtime", () => {
    const ids = iconOnlyTippedIds();
    expect(ids.has("dashViewBtn")).toBe(true);
    expect(ids.has("lifecycleBtn")).toBe(true);
    // Undo/Redo have visible text, so their name never comes from the tip.
    expect(ids.has("importUndoBtn")).toBe(false);
  });

  it("every script that rewrites data-tip on an icon-only control also writes aria-label", () => {
    const ids = iconOnlyTippedIds();
    const stale = tipWritesWithoutName().filter(([, id]) => ids.has(id));
    expect(stale).toEqual([]);
  });
});

describe("page-size selects are named (#2469)", () => {
  it("every tl-pagesize-sel select carries an aria-label", () => {
    const selects = HTML.match(/<select\b[^>]*\btl-pagesize-sel\b[^>]*>/g) ?? [];
    expect(selects.length).toBeGreaterThanOrEqual(2);
    for (const tag of selects) expect(tag).toMatch(/\saria-label="[^"]+"/);
  });

  it("the dashboard declares a meta description", () => {
    expect(HTML).toMatch(/<meta\s+name="description"\s+content="[^"]+"/);
  });
});

describe("script-rendered selects are named (part of #2492)", () => {
  // These selects are built as template strings, so no <label> or wrapper title names them.
  const cases: Array<[string, RegExp]> = [
    ["dashboard-hypotheses.js", /<select\b[^>]*\bhyp-status\b[^>]*>/g],
    ["dashboard-playbook.js", /<select\b[^>]*\bpb-status\b[^>]*>/g],
    ["dashboard-report-versions.js", /<select\b[^>]*\bdata-rv-reviewer=[^>]*>/g],
  ];
  it.each(cases)("%s: its status/reviewer select carries an aria-label", (file, re) => {
    const src = readFileSync(new URL(file, JS_DIR), "utf8");
    const selects = src.match(re) ?? [];
    expect(selects.length).toBeGreaterThanOrEqual(1);
    for (const tag of selects) expect(tag).toMatch(/\saria-label="[^"]+"/);
  });
});
