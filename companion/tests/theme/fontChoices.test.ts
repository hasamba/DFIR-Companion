import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

// The analyst's font choices (theme menu → "Text"). Three files must agree or a choice silently
// does nothing: the registry in js/dashboard-theme.js lists what the menu offers, the <head>
// bootstrap in dashboard.html applies a stored value before first paint, and css/dashboard-layout.css
// turns each font value into a font stack. Text size is a zoom set from script, so its mirror is the
// slider bounds, which the bootstrap repeats. There is no DOM in this suite, so these are mirror
// checks over the three sources.

const pub = (p: string) => new URL(`../../../public/${p}`, import.meta.url);
const read = (p: string) => readFileSync(pub(p), "utf8");

type Entry = { id: string; label: string; probe?: string[] };
type Registry = Record<"ui" | "code", Entry[]>;

function registry(): Registry {
  const src = read("js/dashboard-theme.js");
  const m = /const DFIR_FONTS = (\{[\s\S]*?\n {2}\});/.exec(src);
  if (!m) throw new Error("DFIR_FONTS literal not found in js/dashboard-theme.js");
  return new Function(`return ${m[1]};`)() as Registry;
}

function cssRules(kind: string): Set<string> {
  const css = read("css/dashboard-layout.css");
  const re = new RegExp(`:root\\[data-font-${kind}="([^"]+)"\\]`, "g");
  return new Set([...css.matchAll(re)].map((m) => m[1]));
}

describe("font choices", () => {
  const fonts = registry();

  for (const kind of ["ui", "code"] as const) {
    it(`every non-default ${kind} entry has a CSS rule, and every rule has an entry`, () => {
      const offered = fonts[kind].slice(1).map((f) => f.id);
      expect(offered.length).toBeGreaterThan(0);
      expect(new Set(offered)).toEqual(cssRules(kind));
    });

    it(`the default ${kind} entry needs no rule (it is applied by removing the attribute)`, () => {
      expect(cssRules(kind).has(fonts[kind][0].id)).toBe(false);
    });

    it(`the head bootstrap accepts every ${kind} id`, () => {
      const html = read("dashboard.html");
      const m = /getItem\('dfir-font-' \+ k\);\s*if \(\/(.+?)\/\.test/.exec(html);
      expect(m, "bootstrap font allowlist not found").not.toBeNull();
      const allow = new RegExp(m![1]);
      for (const f of fonts[kind]) expect(allow.test(f.id), f.id).toBe(true);
    });
  }

  it("the text-size slider and the head bootstrap share one range and one default", () => {
    const src = read("js/dashboard-theme.js");
    const m = /const TEXT_SIZE = (\{[^}]*\});/.exec(src);
    expect(m, "TEXT_SIZE literal not found").not.toBeNull();
    const size = new Function(`return ${m![1]};`)() as {
      min: number;
      max: number;
      step: number;
      def: number;
    };
    expect(size.def).toBe(100);
    expect(size.min).toBeLessThan(size.def);
    expect(size.max).toBeGreaterThan(size.def);
    expect((size.def - size.min) % size.step).toBe(0);
    const html = read("dashboard.html");
    const b =
      /z >= (\d+) && z <= (\d+) && z !== (\d+)\) document\.documentElement\.style\.zoom = z \/ 100/.exec(
        html,
      );
    expect(b, "bootstrap text-size line not found").not.toBeNull();
    expect(b!.slice(1).map(Number)).toEqual([size.min, size.max, size.def]);
  });

  it("no stylesheet sets the text-size zoom, so the script is its only writer", () => {
    expect(read("css/dashboard-layout.css")).not.toMatch(/data-font-size|\bzoom\s*:/);
  });

  it("the bootstrap rejects a value that could break out of an attribute", () => {
    const html = read("dashboard.html");
    const m = /getItem\('dfir-font-' \+ k\);\s*if \(\/(.+?)\/\.test/.exec(html);
    const allow = new RegExp(m![1]);
    for (const bad of ['a"b', "x onload=1", "<b>", "", "A", "-x"]) expect(allow.test(bad), bad).toBe(false);
  });
});

// Every monospace stack in the dashboard reads the one --font-code token. A hardcoded stack would
// ignore the analyst's code-font choice in that one spot.
describe("code font token", () => {
  const files = [
    "dashboard.html",
    ...readdirSync(pub("css")).map((f) => `css/${f}`),
    ...readdirSync(pub("js"))
      .filter((f) => f.endsWith(".js"))
      .map((f) => `js/${f}`),
  ];

  it("no dashboard file hardcodes a monospace font-family", () => {
    const offenders = files.filter((f) => /font-family:\s*(ui-monospace|monospace)/.test(read(f)));
    expect(offenders).toEqual([]);
  });

  it("the page body reads the UI font token", () => {
    expect(read("css/dashboard-layout.css")).toMatch(/body \{ font-family: var\(--font-ui\);/);
  });
});
