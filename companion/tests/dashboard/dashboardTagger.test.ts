import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { dashboardScripts, functionsOf } from "../helpers/dashboardAst.js";
import { declaredFunctions } from "../helpers/dashboardModule.js";

// public/js/dashboard-tagger.js — the first WHOLE FEATURE moved out by #415 tier 3.
//
// The helper modules before it were pure functions, testable by calling them. This one is a
// feature: it reads the DOM, calls the server and writes the DOM back. So what is worth asserting
// is not what the functions return but that the feature is intact and reachable — the failure modes
// are a function left behind, a name the dispatch table can no longer resolve, and a 404 that makes
// the whole feature silently absent.

const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);
const MODULE = new URL("../../../public/js/dashboard-tagger.js", import.meta.url);

/** The whole feature, by name. A function missing from this list is one left in the page. */
const TAGGER = [
  "runTagger",
  "suggestTaggerRule",
  "previewTaggerRule",
  "toggleTaggerSuggest",
  "addSuggestedTaggerRule",
  "discardSuggestedTaggerRule",
  "refreshTaggerRuleList",
  "removeTaggerRule",
  "resetTaggerRules",
  "clearTaggerTags",
  "toggleTaggerRules",
  "saveTaggerRules",
];

describe("the tagger feature moved whole", () => {
  it("declares all twelve functions and publishes every one", () => {
    expect(declaredFunctions("dashboard-tagger.js").sort()).toEqual([...TAGGER].sort());
  });

  // THE POINT OF THE MEASUREMENT THAT CHOSE THIS FEATURE. Eleven of fourteen features examined
  // would have landed in two places, because a feature is usually part standalone and part
  // entangled with the shared filter state. This asserts the tagger did not: nothing named
  // *Tagger* is left in the page.
  it("leaves no half of the feature behind in the inline script", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const leftBehind = [...html.matchAll(/^\s*(?:async )?function (\w*[Tt]agger\w*)\s*\(/gm)].map(
      (m) => m[1],
    );
    expect(leftBehind, "the feature must move as a unit or not at all").toEqual([]);
  });

  it("touches no shared dashboard state", async () => {
    // Why it could move at all: every one of these reads the DOM and the server, never the store.
    const src = await readFile(MODULE, "utf8");
    expect(src).not.toMatch(/\bDfirState\b/);
  });
});

describe("the tagger feature is still reachable", () => {
  // The dispatch table is built as `name: (el) => name()` — arrows, so the identifier resolves at
  // CLICK time, not when the table is constructed. That late binding is what let twelve functions
  // leave the file without editing a single ACTIONS entry, and it is the property the next feature
  // extraction depends on.
  it("keeps every ACTIONS entry resolving to a function the module publishes", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const block = html.split("const ACTIONS = {")[1].split("\n    };")[0];
    const routed = [...block.matchAll(/^\s{6}(\w+):\s*\(el\)\s*=>\s*(\w+)\(/gm)].filter(([, , target]) =>
      TAGGER.includes(target),
    );
    expect(routed.length, "no tagger action is dispatched at all — the check is vacuous").toBeGreaterThan(0);
    for (const [, action, target] of routed) {
      expect(
        declaredFunctions("dashboard-tagger.js"),
        `data-act="${action}" resolves to ${target}`,
      ).toContain(target);
    }
  });

  it("is loaded synchronously ahead of the inline script, and served by the whitelist", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const tag = /<script([^>]*)\ssrc="\/js\/dashboard-tagger\.js"/.exec(html);
    expect(tag).not.toBeNull();
    expect(tag?.[1]).not.toMatch(/defer|type="module"|async/);
    expect(html.indexOf('src="/js/dashboard-tagger.js"')).toBeLessThan(html.lastIndexOf("<script nonce="));
    expect(STATIC_ASSETS["/js/dashboard-tagger.js"]).toBe("application/javascript; charset=utf-8");
  });

  it("is covered by the AST gates now that it is a script of its own", () => {
    const scripts = dashboardScripts();
    expect(scripts.map((s) => s.name)).toContain("js/dashboard-tagger.js");
    const tagger = scripts.find((s) => s.name === "js/dashboard-tagger.js");
    expect(functionsOf(tagger!).length).toBeGreaterThanOrEqual(TAGGER.length);
  });
});

// public/js/dashboard-kev.js — the second and last wholly-movable feature (#415 tier 3).
//
// Wired differently from the tagger, which is the point of testing it separately: KEV uses
// `addEventListener("click", kevImportUrl)`, a function REFERENCE resolved when the listener is
// registered, where the tagger goes through the ACTIONS table's late-bound arrows. Both work only
// because the module is a synchronous classic script loaded before the inline script — but they
// would fail differently, so both are pinned.
describe("the KEV feature moved whole", () => {
  const KEV = ["loadKev", "kevImportUrl", "kevImportFile", "kevClear"];

  it("declares all four functions and publishes every one", () => {
    expect(declaredFunctions("dashboard-kev.js").sort()).toEqual([...KEV].sort());
  });

  it("leaves no half of the feature behind in the inline script", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const leftBehind = [...html.matchAll(/^\s*(?:async )?function (\w*[Kk]ev\w*)\s*\(/gm)].map((m) => m[1]);
    expect(leftBehind).toEqual([]);
  });

  it("touches no shared dashboard state", async () => {
    expect(
      await readFile(new URL("../../../public/js/dashboard-kev.js", import.meta.url), "utf8"),
    ).not.toMatch(/\bDfirState\b/);
  });

  // The listener registrations still name these functions. They resolve at registration time, in
  // the inline script — so the module must load first, and the names must be real globals.
  it("keeps the listener registrations resolving to functions the module publishes", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const registered = [...html.matchAll(/addEventListener\("(?:click|keydown)",\s*(kev\w+)\)/g)].map(
      (m) => m[1],
    );
    expect(registered.length, "no KEV listener is registered — the check is vacuous").toBeGreaterThan(0);
    for (const name of registered) expect(declaredFunctions("dashboard-kev.js")).toContain(name);
  });

  it("is loaded synchronously ahead of the inline script, and served by the whitelist", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const tag = /<script([^>]*)\ssrc="\/js\/dashboard-kev\.js"/.exec(html);
    expect(tag).not.toBeNull();
    expect(tag?.[1]).not.toMatch(/defer|type="module"|async/);
    expect(html.indexOf('src="/js/dashboard-kev.js"')).toBeLessThan(html.lastIndexOf("<script nonce="));
    expect(STATIC_ASSETS["/js/dashboard-kev.js"]).toBe("application/javascript; charset=utf-8");
  });
});
