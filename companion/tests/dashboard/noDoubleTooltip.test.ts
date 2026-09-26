import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

// A control with a `data-tip` gets the dashboard's styled hover card. If script also sets a native
// `title` on it, the browser draws its own bubble too, and the analyst sees two tooltips stacked
// on top of each other (Undo import, Case lifecycle, Dashboard view). A control that needs a
// state-dependent tip must rewrite `data-tip`, never `title`.

const HTML = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
const JS_DIR = new URL("../../../public/js/", import.meta.url);

/** Ids of every element whose opening tag in dashboard.html carries a data-tip. */
function tippedIds(): Set<string> {
  const ids = new Set<string>();
  for (const tag of HTML.match(/<[a-zA-Z][^>]*\sdata-tip=[^>]*>/g) ?? []) {
    const id = /\sid="([^"]+)"/.exec(tag)?.[1];
    if (id) ids.add(id);
  }
  return ids;
}

/** `[file, id]` for each script that binds an element by id and then writes its native title. */
function nativeTitleWrites(): Array<[string, string]> {
  const hits: Array<[string, string]> = [];
  const files = readdirSync(JS_DIR, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".js"));
  for (const file of files) {
    const src = readFileSync(new URL(file, JS_DIR), "utf8");
    const binding = /\b(?:const|let|var)\s+(\w+)\s*=\s*document\.getElementById\(\s*["'](\w+)["']\s*\)/g;
    for (const [, name, id] of src.matchAll(binding)) {
      const write = new RegExp(`\\b${name}\\.title\\s*=[^=]|\\b${name}\\.setAttribute\\(\\s*["']title["']`);
      if (write.test(src)) hits.push([file, id]);
    }
  }
  return hits;
}

describe("data-tip controls never get a native title", () => {
  it("finds the tipped controls it guards", () => {
    const ids = tippedIds();
    for (const id of ["importUndoBtn", "importRedoBtn", "lifecycleBtn", "dashViewBtn"]) {
      expect(ids.has(id)).toBe(true);
    }
  });

  it("no script sets title on an element that already has a data-tip", () => {
    const ids = tippedIds();
    const doubled = nativeTitleWrites().filter(([, id]) => ids.has(id));
    expect(doubled).toEqual([]);
  });
});
