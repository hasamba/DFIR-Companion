import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import type { EscapeApi } from "./dashboardApi.js";
import type { DashboardGlobals } from "../helpers/dashboardModule.js";
import { declaredFunctions, loadDashboardModule } from "../helpers/dashboardModule.js";

// The contract shared by all eight helper modules extracted from dashboard.html in #415.
//
// The per-module suites next door test what the functions DO. This one tests that they are wired:
// loaded by the page, served by the server, published under their namespace, and — for `esc` —
// still identical to the two other copies of it in the tree. Every failure mode here is silent in
// a browser. A module missing from STATIC_ASSETS 404s and the page simply loses 95 functions; a
// function declared but left out of its namespace is invisible until something calls it.

const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

/** file -> the `window.Dfir*` name it publishes. */
const MODULES: Record<string, string> = {
  "dashboard-escape.js": "DfirEscape",
  "dashboard-time.js": "DfirTime",
  "dashboard-text.js": "DfirText",
  "dashboard-glyphs.js": "DfirGlyphs",
  "dashboard-filters.js": "DfirFilters",
  "dashboard-ioc.js": "DfirIoc",
  "dashboard-values.js": "DfirValues",
  "dashboard-fragments.js": "DfirFragments",
};
const FILES = Object.keys(MODULES);

describe.each(FILES)("%s", (file) => {
  it("loads as a classic script and publishes its namespace", () => {
    const globals = loadDashboardModule<DashboardGlobals>(
      file,
      FILES.filter((f) => f !== file),
    );
    expect(globals[MODULES[file]]).toBeTypeOf("object");
  });

  // The exact mistake #414 shipped: the module published only its top-level renderers, on the
  // assumption that the helpers had moved with their only callers. They had not — 46 bare calls
  // survived in the inline script and every one was a ReferenceError, while all 29 unit tests
  // passed because they exercised the module directly and never loaded the page.
  it("publishes every function it declares", () => {
    const globals = loadDashboardModule<DashboardGlobals>(
      file,
      FILES.filter((f) => f !== file),
    );
    const published = Object.keys(globals[MODULES[file]] as object);
    expect([...declaredFunctions(file)].sort()).toEqual([...published].sort());
  });

  it("is loaded by dashboard.html and served by the whitelist", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain(`<script src="/js/${file}"></script>`);
    expect(STATIC_ASSETS[`/js/${file}`]).toBe("application/javascript; charset=utf-8");
  });

  // NOT `defer`, NOT `type="module"`. Both would run the file after the HTML is parsed, and
  // dashboard.html calls legendIcon() from a top-level statement during parsing — the symptom
  // would be legend icons silently absent. See public/js/dashboard-escape.js.
  it("is tagged synchronously, ahead of the inline script that calls into it", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const tag = new RegExp(`<script([^>]*)\\ssrc="/js/${file.replace(".", "\\.")}"`).exec(html);
    expect(tag, `no <script src="/js/${file}"> in dashboard.html`).not.toBeNull();
    expect(tag?.[1]).not.toMatch(/defer|type="module"|async/);
    // "Ahead of" is the half that actually orders execution, so it is checked by position rather
    // than inferred from the absence of `defer`. The 18k-line inline script is the last
    // <script nonce> block in the file.
    expect(html.indexOf(`src="/js/${file}"`)).toBeLessThan(html.lastIndexOf("<script nonce="));
  });
});

// `esc` now exists in three places: the inline script (661 call sites, which is why it could not
// move), js/diagnostics-panel.js (#414's copy) and js/dashboard-escape.js (this extraction's).
// #414 accepted the duplication on the grounds that a drift test is a better trade than making
// every escape call depend on a module load for an XSS-critical primitive (#387). That trade only
// holds while they are actually identical, and with three copies it holds less on its own.
describe("esc drift guard", () => {
  const COPIES = ["diagnostics-panel.js", "dashboard-escape.js"];

  /** The function's body with all whitespace flattened, so indentation is not the thing compared. */
  const bodyOf = (src: string, decl: string, endMarker: string): string => {
    const start = src.indexOf(decl);
    expect(start, `${decl} not found`).toBeGreaterThan(-1);
    const end = src.indexOf("}", src.indexOf(endMarker, start));
    return src
      .slice(start, end + 1)
      .split("\n")
      .map((l) => l.trim())
      .join("");
  };

  it.each(COPIES)("keeps %s's esc identical to the dashboard's inline one", async (copy) => {
    const [html, module] = await Promise.all([
      readFile(DASHBOARD, "utf8"),
      readFile(new URL(`../../../public/js/${copy}`, import.meta.url), "utf8"),
    ]);
    const args = ["function esc(s) {", ".replace(/>/g"] as const;
    expect(bodyOf(module, ...args)).toBe(bodyOf(html, ...args));
  });

  // escAttr was never guarded, and it is the one that matters for the attribute sinks #217 fixed:
  // it escapes BOTH quote flavours, and a copy that lost the single-quote replace would still pass
  // every test that only checks double quotes.
  it("keeps escAttr identical to the dashboard's inline one", async () => {
    const [html, module] = await Promise.all([
      readFile(DASHBOARD, "utf8"),
      readFile(new URL("../../../public/js/dashboard-escape.js", import.meta.url), "utf8"),
    ]);
    const args = ["function escAttr(s) {", '&#39;"'] as const;
    expect(bodyOf(module, ...args)).toBe(bodyOf(html, ...args));
  });

  it("still escapes both quote flavours, whichever copy runs", () => {
    const { esc, escAttr } = loadDashboardModule<EscapeApi>("dashboard-escape.js");
    expect(esc('<img src=x onerror="alert(1)">')).toBe('&lt;img src=x onerror="alert(1)"&gt;');
    expect(escAttr(`" onmouseover='x'`)).toBe("&quot; onmouseover=&#39;x&#39;");
    expect(esc(null)).toBe("");
    expect(esc(undefined)).toBe("");
    expect(esc(0)).toBe("0");
  });
});

// The inline script keeps calling all 95 of these by bare name. A classic script's top-level
// declarations are global, so that works — but only while the file stays a classic script. An
// `export` or `import` anywhere in one of them silently reclassifies nothing in Node and breaks
// every call site in the browser, so it is worth failing here instead.
describe("the helper modules stay classic scripts", () => {
  it.each(FILES)("%s has no ESM syntax", async (file) => {
    const src = await readFile(new URL(`../../../public/js/${file}`, import.meta.url), "utf8");
    expect(src).not.toMatch(/^\s*(export|import)\s/m);
  });
});

// THE GUARANTEE THE WHOLE EXTRACTION RESTS ON.
//
// 95 function declarations were deleted from dashboard.html and 427 call sites were left pointing
// at them by bare name. Every one of those resolves only because the page loads these files as
// classic scripts first, and the cost of getting it wrong for one name is a ReferenceError the
// first time an analyst opens the panel that calls it — nothing at build time, nothing in any
// other suite, and in most cases nothing visible until the feature is used.
//
// So this loads the tagged scripts the way the browser does, in the order the page tags them, and
// checks both directions for every moved name: gone from the inline script, present as a global
// afterwards. Reading the tag list out of the HTML rather than hard-coding it means a module that
// is written and published but never tagged fails here too.
describe("every moved function still resolves at its call sites", () => {
  const MOVED = FILES.flatMap((f) => declaredFunctions(f)).filter(
    // esc/escAttr are the two the inline script deliberately kept (661 call sites, #414), so they
    // are copies rather than moves and must still be declared inline.
    (name) => name !== "esc" && name !== "escAttr",
  );

  it("moved 95 functions, so the check below is not vacuous", () => {
    expect(MOVED.length).toBe(95);
  });

  it("provides every one of them as a global once the tagged scripts have run", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const tagged = [...html.matchAll(/<script src="\/js\/([^"]+)"><\/script>/g)].map((m) => m[1]);
    const globals = loadDashboardModule<DashboardGlobals>(tagged[tagged.length - 1], tagged.slice(0, -1));
    const missing = MOVED.filter((name) => typeof globals[name] !== "function");
    expect(missing, "declared in a helper module but not reachable as a global").toEqual([]);
  });

  it("leaves no stale copy of them behind in the inline script", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const inline = html.match(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)?.join("\n") ?? "";
    const duplicated = MOVED.filter((name) => new RegExp(`^\\s{4}function ${name}\\s*\\(`, "m").test(inline));
    expect(duplicated, "moved out but still declared inline — the inline copy wins at runtime").toEqual([]);
  });

  // The two that did NOT move have to still be there, or the drift guard above is comparing a
  // module against nothing and passing.
  it("keeps esc and escAttr declared inline, where their 661 call sites are", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toMatch(/^\s{4}function esc\(s\) \{/m);
    expect(html).toMatch(/^\s{4}function escAttr\(s\) \{/m);
  });
});
