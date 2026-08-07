import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { runInContext } from "node:vm";
import { functionBindingsOf, scriptFromSource, topLevelBindings } from "../helpers/dashboardAst.js";
import { globalNamesOf, globalsAddedBy, loadDashboardModule } from "../helpers/dashboardModule.js";
import { DASHBOARD, duplicateBindings, FEATURES, globalsOf, read, scripts } from "./featureManifest.js";

// Per-feature STRUCTURE: what each module publishes, what it keeps private, and that it moved as a
// unit. The lifecycle questions — is it called, when, does it wire anything — live in
// dashboardFeatureLifecycle.test.ts; the census seam's contract is in dashboardCensusSeam.test.ts.

describe("the global-name enumeration these checks rest on", () => {
  it("sees a leak published as a non-enumerable property", () => {
    const api: Record<string, unknown> = { window: {}, pushFindingToTicket: () => {} };
    Object.defineProperty(api, "debugTickets", { value: { pushSelect: null }, enumerable: false });
    expect(Object.keys(api), "the shape this test exists for is no longer non-enumerable").not.toContain(
      "debugTickets",
    );
    expect(globalsOf(api), "a non-enumerable global is still reachable by bare name").toContain(
      "debugTickets",
    );
  });

  // globalsAddedBy() diffs the same enumeration, so the LOAD-time gate in the describe.each below
  // inherits this fix or does not get it at all.
  it("is the enumeration globalsAddedBy diffs", () => {
    const sandbox: Record<string, unknown> = {};
    Object.defineProperty(sandbox, "debugTickets", { value: 1, enumerable: false });
    expect(globalNamesOf(sandbox)).toContain("debugTickets");
  });

  it("still reports an ordinary global exactly once", () => {
    expect(globalsOf({ window: {}, loadAnomalies: () => {} })).toEqual(["loadAnomalies"]);
  });
});

describe.each(FEATURES)("$file", (feat) => {
  // THESE RUN THE MODULE. The first version asserted on the file's TEXT — that it contained
  // `(function () {` and one `window.x = x` line per published name — and review showed what that
  // certifies: nothing. Changing `})();` to `});` leaves a valid, never-invoked function expression
  // that publishes not one global, and every text assertion still passed. So did leaking state as
  // `window.debugFeatureState`, and so did deleting a private declaration while its references
  // remained. These files sit outside the TypeScript build AND outside eslint, so actually running
  // them is the only check here that means anything.
  it("adds exactly the globals it promises, and nothing else", () => {
    expect(globalsAddedBy(feat.file).sort()).toEqual([...feat.publish].sort());
  });

  it("publishes a callable function for every name", () => {
    const api = loadDashboardModule<Record<string, unknown>>(feat.file);
    for (const name of feat.publish) {
      expect(typeof api[name], `${name} is not a function on the global object`).toBe("function");
    }
  });

  // THE POINT OF THE CLOSURE. A top-level `let` in a classic script joins the shared global lexical
  // environment, so "feature-local" would be a claim rather than a fact. Asked of the RUNNING
  // module: a bare reference from a second script in the same context must not resolve.
  it("puts its state out of reach of another script on the page", () => {
    const api = loadDashboardModule<Record<string, unknown>>(feat.file);
    for (const name of feat.private) {
      expect(() => runInContext(name, api as object), `${name} escaped the closure`).toThrow(
        new RegExp(`${name} is not defined`),
      );
    }
  });

  // Anything NOT on the publish list must be unreachable, which only holds if the page stopped
  // referring to it. A name left behind in the page resolves to undefined at call time.
  it("leaves nothing behind in the inline script", async () => {
    const src = await read(feat.file);
    // ONE CENSUS, ASKED OF BOTH SIDES. This was two questions: a regex over the module's text and
    // an AST walk over the inline script. They disagreed twice over. A regex reads text, so a
    // comment between the keyword and the name — `function /* moved */ initTicketIntegrations()` —
    // dropped the name and the duplicate went unnoticed; and both sides counted DECLARATIONS only,
    // so `const loadAnomalies = () => {}` restored in the page shadowed the module's published
    // function for every inline call site while the whole suite stayed green.
    //
    // functionBindingsOf() answers it once, for declarations AND function-valued bindings, and
    // still leaves the ACTIONS dispatch table alone — see its own note on why a property is not a
    // binding.
    expect(
      functionBindingsOf(scriptFromSource(feat.file, src)).length,
      "no functions found — the extraction produced an empty module",
    ).toBeGreaterThan(0);
    const inline = scripts.filter((s) => s.name.startsWith("dashboard.html#inline"));
    const leftBehind = duplicateBindings(feat.file, src, inline);
    expect(leftBehind, "the feature must move as a unit or not at all").toEqual([]);
  });

  // AND EACH PRIVATE NAME MUST ACTUALLY BE DECLARED.
  //
  // The out-of-reach check above cannot see this one: delete `let anomaliesTimer = null` and the
  // name simply becomes an implicit global the first time the function ASSIGNS to it. Nothing
  // happens at load, so the global set is unchanged and a bare reference still throws — the module
  // only starts leaking once the analyst uses it. Comments are stripped first, because a module
  // header that explains why a binding stayed behind is not a declaration.
  it("declares every one of its private bindings", async () => {
    const code = (await read(feat.file))
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"))
      .join("\n");
    for (const name of feat.private) {
      expect(code, `${name} is referenced but never declared — it would become an implicit global`).toMatch(
        new RegExp(`(?:let|const|var)[^;\n]*\\b${name}\\b`),
      );
    }
  });

  // EVERY script the page loads, not the inline blocks alone: a duplicate of one of these bindings
  // in another loaded /js/ file is the same page global, and scoping the search to the page missed it.
  it("takes its bindings with it, leaving none anywhere else", () => {
    const stranded = scripts
      .filter((s) => s.name !== `js/${feat.file}`)
      .flatMap((s) =>
        topLevelBindings(s)
          .filter((b) => feat.private.includes(b.name))
          .map((b) => `${s.name}:${b.line} ${b.name}`),
      );
    expect(stranded).toEqual([]);
  });

  it("is loaded ahead of the inline script and served by the whitelist", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain(`<script src="/js/${feat.file}"></script>`);
    const tag = html.indexOf(`src="/js/${feat.file}"`);
    const blocks = [...html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)];
    // The main block is the LONGEST one, not "the one containing render()". Anchoring on render
    // tied this assertion to a function #415 is in the business of moving out: the day it goes,
    // five suites fail with "could not locate the inline dashboard script" instead of with
    // whatever actually broke. Length stays true however much comes out of the block.
    const main = blocks.reduce((a, b) => (b[1].length > a[1].length ? b : a));
    expect(tag).toBeLessThan(main.index);
    expect(STATIC_ASSETS[`/js/${feat.file}`]).toBe("application/javascript; charset=utf-8");
  });

  it("stays a classic script", async () => {
    const src = await read(feat.file);
    expect(src).not.toMatch(/^\s*(?:export|import)\s/m);
  });
});
