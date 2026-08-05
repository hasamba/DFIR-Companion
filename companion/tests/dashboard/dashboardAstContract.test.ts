// The CONTRACT of tests/helpers/dashboardAst.ts, tested directly.
//
// WHY THIS FILE EXISTS. Six holes have been found in these gates across #415, and every one was
// found by a person reading the helper rather than by a test: the `async function` shape, the
// single-file scan, the direct-call-only reachability, the window-rooted namespace, the callback
// loop, and the detached method reference. The gates themselves stayed green throughout, because
// the page happened not to contain the shape being missed.
//
// So the helpers are now exercised on snippets that DO contain those shapes. Each case below is a
// bypass that review found in a real audit, kept as the regression test it should always have been —
// and each has a partner asserting what must NOT be reported, because a check that flags everything
// is as useless as one that flags nothing.

import { describe, expect, it } from "vitest";
import {
  buildCallGraph,
  callsByName,
  domAccessOutsideFunctions,
  functionBindingsOf,
  ownerEscapes,
  calleesInsideLoops,
  commitsInsideLoops,
  ownerCalls,
  reachableFrom,
  scriptFromSource,
  topLevelBindings,
  topLevelUnguardedRefs,
  unguardedRefs,
  unguardedTopLevelRefs,
} from "../helpers/dashboardAst.js";

const COMMITS = ["toggle", "addAll", "removeAll", "clear", "showAll", "hideAll"];

describe("the loop rule follows a wrapper, but not a deferred callback", () => {
  it("catches a commit several hops from a loop callee", () => {
    const s = scriptFromSource(
      "p.js",
      `
      function inner(x) { DfirSelection.events.toggle(x, true); }
      function outer(x) { inner(x); }
      function drive(xs) { for (const x of xs) outer(x); }`,
    );
    const committers = new Set(ownerCalls([s], "DfirSelection", COMMITS).map((c) => c.fn));
    const graph = buildCallGraph([s]);
    let caught = false;
    for (const callee of calleesInsideLoops([s])) {
      const reach = new Set([callee, ...reachableFrom(graph, [callee])]);
      for (const c of committers) if (reach.has(c)) caught = true;
    }
    expect(caught, "two-hop wrapper still invisible").toBe(true);
  });

  it("does not count a keystroke handler registered inside a loop", () => {
    const s = scriptFromSource(
      "p.js",
      `
      function commitIt() { DfirSelection.events.clear(); }
      ["a","b"].forEach((id) => document.getElementById(id).addEventListener("click", () => commitIt()));`,
    );
    const committers = new Set(ownerCalls([s], "DfirSelection", COMMITS).map((c) => c.fn));
    const graph = buildCallGraph([s]);
    const hits: string[] = [];
    for (const callee of calleesInsideLoops([s])) {
      const reach = new Set([callee, ...reachableFrom(graph, [callee])]);
      for (const c of committers) if (reach.has(c)) hits.push(`${callee}->${c}`);
    }
    expect(hits, "a keystroke handler is not a per-element commit").toEqual([]);
  });

  it("catches cell.set() inside a bulk operation", () => {
    const s = scriptFromSource(
      "m.js",
      `
      function idSet() {
        const cell = window.DfirState.cell(new Set());
        return { addAll(ids) { for (const id of ids) cell.set(new Set([id])); } };
      }`,
    );
    expect(commitsInsideLoops(s, ["commit", "set"]).map((c) => c.fn)).toContain("addAll");
  });

  it("catches a helper that commits, called from a bulk loop", () => {
    const s = scriptFromSource(
      "m.js",
      `
      function idSet() {
        const cell = window.DfirState.cell(new Set());
        const commit = (n) => cell.set(n);
        function put(x) { commit(new Set([x])); }
        return { hideAll(ids) { for (const id of ids) put(id); } };
      }`,
    );
    const found = commitsInsideLoops(s, ["commit", "set"]);
    expect(found.map((c) => `${c.fn} via ${c.via}`)).toContain("hideAll via put");
  });

  it("reports nothing against the real owner modules", async () => {
    const { readFile } = await import("node:fs/promises");
    for (const f of ["dashboard-selection.js", "dashboard-facets.js"]) {
      const src = await readFile(new URL(`../../../public/js/${f}`, import.meta.url), "utf8");
      expect(commitsInsideLoops(scriptFromSource(f, src), ["commit", "set"])).toEqual([]);
    }
  });

  // Every form review found walking past the gates, each kept as the regression test it should
  // always have been.
  it("catches a commit inside an iteration callback within a bulk operation", () => {
    const s = scriptFromSource(
      "m.js",
      `
      function idSet() {
        const cell = window.DfirState.cell(new Set());
        return { addAll(ids) { ids.forEach((id) => cell.set(new Set([id]))); } };
      }`,
    );
    expect(commitsInsideLoops(s, ["commit", "set"]).map((c) => c.fn)).toContain("addAll");
  });

  it.each([
    [
      "a synchronous IIFE",
      `for (const id of ids) (function () { DfirSelection.events.toggle(id, true); })();`,
    ],
    ["a parenthesised callback", `ids.forEach((id) => { DfirSelection.events.toggle(id, true); });`],
    [
      "one queued commit per item",
      `for (const id of ids) queueMicrotask(() => DfirSelection.events.toggle(id, true));`,
    ],
  ])("still counts %s as per-element", (_label, src) => {
    expect(ownerCalls([scriptFromSource("p.js", src)], "DfirSelection", COMMITS).some((c) => c.inLoop)).toBe(
      true,
    );
  });

  it.each([
    [
      "an inline listener",
      `for (const id of ids) el(id).addEventListener("click", () => DfirSelection.events.clear());`,
    ],
    [
      "a named handler",
      `function h() { DfirSelection.events.clear(); }\nfor (const id of ids) el(id).addEventListener("click", h);`,
    ],
    ["an on* assignment", `for (const id of ids) { el(id).onclick = () => DfirSelection.events.clear(); }`],
  ])("does not count %s, which runs on an event and not per element", (_label, src) => {
    const s = scriptFromSource("p.js", src);
    expect(ownerCalls([s], "DfirSelection", COMMITS).some((c) => c.inLoop)).toBe(false);
    const committers = new Set(
      ownerCalls([s], "DfirSelection", COMMITS)
        .map((c) => c.fn)
        .filter((f) => !f.startsWith("<")),
    );
    const graph = buildCallGraph([s]);
    const viaCallee = [...calleesInsideLoops([s])].some((c) => {
      const reach = new Set([c, ...reachableFrom(graph, [c])]);
      return [...committers].some((x) => reach.has(x));
    });
    expect(viaCallee).toBe(false);
  });

  it.each([
    ["a var in a for-of head", `for (var selectedEvents of sets) {}`],
    ["a logical-assignment global", `window.hiddenSources ??= new Set();`],
    ["a template-literal key", 'globalThis[`searchTerm`] = "";'],
  ])("counts %s as a binding", (_label, src) => {
    const name = ["selectedEvents", "hiddenSources", "searchTerm"].find((n) => src.includes(n))!;
    expect(topLevelBindings(scriptFromSource("p.js", src)).map((b) => b.name)).toContain(name);
  });

  it.each([
    ["a reflective invoke", `DfirSelection.events.toggle.call(null, "x");`],
    ["a method overwrite", `DfirSelection.events.toggle = function () {};`],
  ])("does not let %s past both gates", (_label, src) => {
    const s = scriptFromSource("p.js", src);
    const seen =
      ownerCalls([s], "DfirSelection", COMMITS).length > 0 || ownerEscapes([s], "DfirSelection").length > 0;
    expect(seen, "reaches a writable member and is reported by neither gate").toBe(true);
  });

  it("counts a computed global assignment as a binding", () => {
    for (const [src, name] of [
      [`globalThis["hiddenSources"] = new Set();`, "hiddenSources"],
      [`window["selectedEvents"] = new Set();`, "selectedEvents"],
      [`self["searchTerm"] = "";`, "searchTerm"],
    ] as const) {
      expect(
        topLevelBindings(scriptFromSource("p.js", src)).map((b) => b.name),
        src,
      ).toContain(name);
    }
  });
});

// ── THE GUARD ANALYSER READS THE BRANCH, NOT JUST THE CONDITION ──────────────────────────────────
//
// The seventh hole in these gates, and the first found by MUTATION rather than by reading.
// unguardedCalls() reported "guarded" for seven shapes that every one of them throws in when the
// module 404s, for two reasons that compound: its guard test asked only whether the condition
// MENTIONED `typeof N` anywhere, so the `then` of `if (typeof N === "undefined")` counted as safe;
// and its visitor matched only a CallExpression with an Identifier callee, so a bare reference
// passed as an argument and every `Namespace.method()` call were invisible before the guard
// question was even reached. All seven are rows below, alongside the guards that must NOT be
// reported — a gate that flags a correct guard gets switched off, which is the same as not having
// one.
describe("the guard analyser reads the branch, not just the condition", () => {
  const NAMES = new Set(["Foo", "Bar"]);
  const refs = (src: string): string[] =>
    unguardedTopLevelRefs(scriptFromSource("p.js", src), NAMES).map((r) => r.name);

  it.each([
    ["a bare call", `Foo();`],
    ["a bare reference passed as an argument", `el.addEventListener("click", Foo);`],
    ["a namespace-member call", `Foo.hydrate({});`],
    ["a bare reference in an initializer", `const f = Foo;`],
    ["a call in the THEN of a missing-test", `if (typeof Foo === "undefined") { Foo(); }`],
    ["a call in the wrong ternary arm", `const x = typeof Foo === "undefined" ? Foo() : null;`],
    ["a call inside a load-time IIFE", `(() => { Foo(); })();`],
    ["a call to the LEFT of its own guard", `const x = Foo() || typeof Foo === "function";`],
    ["a guard naming a different module", `if (typeof Bar === "function") Foo();`],
    ["the ELSE of a === function test", `if (typeof Foo === "function") { a(); } else { Foo(); }`],
    ["a call inside a template literal", "const s = `${Foo()}`;"],
    ["a spread of the bare name", `go(...Foo);`],
    // SHORTHAND IS A READ, not a property name. `{ Foo }` desugars to `{ Foo: Foo }` and evaluates
    // the binding, so it throws exactly like a bare reference — but the analyser grouped
    // ShorthandPropertyAssignment with PropertyAssignment, where excluding the name IS right, and
    // fell straight through the hole. isValueRef() at the top of the helper had it correct all
    // along and said so in a comment; two implementations of one rule, and the wrong one was wired.
    ["a shorthand property that evaluates the binding", `const wiring = { Foo };`],
    ["a shorthand inside a load-time IIFE", `(() => { register({ Foo }); })();`],
    ["a shorthand nested in a longhand value", `const wiring = { outer: { Foo } };`],
  ])("reports %s", (_label, src) => {
    expect(refs(src), "a missing module throws here and aborts the rest of the script").toContain("Foo");
  });

  it.each([
    ["an inverted !== undefined test", `if (typeof Foo !== "undefined") Foo();`],
    ["the ELSE of a === undefined test", `if (typeof Foo === "undefined") { fb(); } else { Foo(); }`],
    ["an ||-widened guard", `const x = typeof Foo === "undefined" || Foo();`],
    ["one name of an && chain", `if (typeof Foo === "function" && typeof Bar === "function") { Foo(); }`],
    ["the true arm of a ternary", `const x = typeof Foo === "function" ? Foo() : null;`],
    ["the false arm of a ternary", `const x = typeof Foo === "undefined" ? null : Foo();`],
    ["a bare reference as a guarded argument", `if (typeof Foo === "function") el.on("c", Foo);`],
    ["a bare reference in a guarded initializer", `if (typeof Foo !== "undefined") { const f = Foo; }`],
    ["a doubly-negated guard", `if (!(typeof Foo === "undefined")) Foo();`],
    ["a guarded namespace-member call", `if (typeof Foo !== "undefined") Foo.hydrate({});`],
    ["an && short-circuit", `typeof Foo === "function" && Foo();`],
    ["a guarded IIFE", `if (typeof Foo !== "undefined") (() => { Foo(); })();`],
  ])("accepts %s", (_label, src) => {
    expect(refs(src), "a real guard reported as a hazard — the gate would be crying wolf").not.toContain(
      "Foo",
    );
  });

  it.each([
    ["a call from inside a function declaration", `function go() { Foo(); }`],
    ["a call from inside a listener callback", `el.addEventListener("click", () => Foo());`],
    ["a call from inside an object method", `const o = { go() { Foo(); } };`],
    ["a property that shares the name", `const o = { Foo: 1 }; go(o.Foo);`],
    ["a parameter that shares the name", `function go(Foo) { return Foo; }`],
    // Both of these were REPORTED before the analyser deferred to isValueRef(). A gate that flags
    // correct code gets switched off, so a false positive costs the same as a false negative here.
    ["a renamed destructuring key", `const { Foo: local } = q;`],
    ["a loop label that shares the name", `Foo: for (;;) { break Foo; }`],
    // SHORTHAND IN A PATTERN IS A WRITE. TypeScript spells `{ Foo }` the same in `const w = { Foo }`
    // (a read, reported above) and `({ Foo } = src)` (an assignment, silent here) — and only the
    // read can throw when the module is missing. Paired with the reports rows on purpose: one rule
    // covering both directions is the only way this stays right.
    ["a destructuring assignment target", `let Foo; ({ Foo } = src);`],
    ["a destructuring assignment target with a default", `let Foo; ({ Foo = 1 } = src);`],
    ["a nested destructuring assignment target", `let Foo; ({ outer: { Foo } } = src);`],
    ["a destructuring target in a for-of", `let Foo; for ({ Foo } of xs) {}`],
  ])("ignores %s", (_label, src) => {
    expect(
      refs(src),
      "contained to one interaction, or not a reference to the global at all — reporting it would " +
        "bury the six that can abort the page",
    ).not.toContain("Foo");
  });
});

// The feature-module suite asks "did this module leave a duplicate of one of its functions behind
// in the page?" It harvests the module's declared names, then looks for those names in the inline
// script. The inline half always used the parser; the module half was a regex over the source, and
// a regex reads text. Every row below is a declaration the regex missed or misread — and a name
// missing from the census is a duplicate the gate cannot look for.
describe("the function census counts every binding, and only bindings", () => {
  const bound = (src: string): string[] =>
    functionBindingsOf(scriptFromSource("m.js", src)).map((b) => b.name);

  it.each([
    ["a plain declaration", `function wire() {}`],
    ["an async declaration", `async function wire() {}`],
    // Legal, and invisible to the /^\s*(?:async )?function (\w+)\s*\(/ this replaced.
    ["a comment between the keyword and the name", `function /* moved out */ wire() {}`],
    ["a comment between the name and its parens", `function wire /* (#415) */ () {}`],
    ["a newline between the keyword and the name", `function\nwire() {}`],
    ["a generator declaration", `function* wire() {}`],
    ["a declaration nested inside another function", `function outer() { function wire() {} }`],
    ["a declaration inside a block", `{ function wire() {} }`],
    // THE ONE THAT SHADOWS. A declaration-only census called these "names the module never owned";
    // they are top-level lexical bindings, and one restored in the inline script wins over the
    // module's published function at every call site in it.
    ["a function expression bound to a const", `const wire = function () {};`],
    ["an arrow bound to a const", `const wire = () => {};`],
    ["an async arrow bound to a let", `let wire = async () => {};`],
    ["a function expression bound to a var", `var wire = function () {};`],
    ["a named function expression bound to a const", `const wire = function inner() {};`],
  ])("sees %s", (_label, src) => {
    expect(bound(src), "a name missing from the census is a duplicate the gate cannot hunt").toContain(
      "wire",
    );
  });

  it.each([
    // A property is not a binding — nothing can shadow through one, and the ACTIONS dispatch table
    // is made of these. Counting them would make the census hunt names the module never owned.
    ["an arrow in an object property", `const ACTIONS = { wire: (el) => wire(el) };`],
    ["a method shorthand in an object literal", `const o = { wire() {} };`],
    ["a class method", `class C { wire() {} }`],
    ["an assignment onto window", `window.wire = function () {};`],
    ["a const bound to a non-function", `const wire = 42;`],
    ["the word function inside a string", `const s = "function wire() {}";`],
  ])("does not count %s", (_label, src) => {
    expect(bound(src)).not.toContain("wire");
  });
});

describe("the module-scope DOM check follows an alias and a helper that runs at load", () => {
  const wrap = (body: string) => `(function () {\n${body}\n})();`;
  const hits = (body: string) => domAccessOutsideFunctions(scriptFromSource("m.js", wrap(body)));

  it.each([
    ["a bare read at module scope", `const box = document.getElementById("notionOverlay");`],
    ["the optional-chained global spelling", `const box = window.document?.getElementById("notionOverlay");`],
    ["the computed global spelling", `const box = window["document"].getElementById("notionOverlay");`],
    ["an alias of the document", `const doc = document;\nconst box = doc.getElementById("notionOverlay");`],
    [
      "an alias of an alias, declared after its use",
      `function go() { d2.getElementById("notionCancel").onclick = function () {}; }\nconst doc = globalThis["document"];\nconst d2 = doc;\ngo();`,
    ],
    [
      "a helper the module calls on the way down",
      `function wire() { document.getElementById("notionCancel").onclick = function () {}; }\nwire();`,
    ],
    [
      "a helper two hops from load",
      `function inner() { document.getElementById("x").onclick = function () {}; }\nfunction outer() { inner(); }\nouter();`,
    ],
    [
      "a helper handed to a synchronous iteration",
      `function wire(id) { document.getElementById(id).onclick = function () {}; }\n["a", "b"].forEach(wire);`,
    ],
    [
      "an arrow helper called at load",
      `const wire = () => { document.getElementById("x").onclick = function () {}; };\nwire();`,
    ],
    ["a destructure off the document", `const { body } = document;\nvoid body;`],
  ])("reports %s", (_label, body) => {
    expect(hits(body), "a DOM touch that really happens at load went unreported").not.toEqual([]);
  });

  it("reports an IIFE spelled with .call", () => {
    const s = scriptFromSource(
      "m.js",
      `(function () { document.getElementById("x").onclick = null; }).call(this);`,
    );
    expect(domAccessOutsideFunctions(s)).not.toEqual([]);
  });

  it.each([
    [
      "a helper that is only published",
      `function wire() { document.getElementById("x").onclick = function () {}; }\nwindow.initThing = wire;`,
    ],
    [
      "a helper deferred to an event",
      `function wire() { document.getElementById("x").textContent = ""; }\nwindow.addEventListener("DOMContentLoaded", wire);`,
    ],
    [
      "a helper deferred to a timer",
      `function wire() { document.getElementById("x").textContent = ""; }\nsetTimeout(wire, 0);`,
    ],
    [
      "the shape dashboard-tickets.js actually uses",
      `function initTicketIntegrations() { const s = document.getElementById("pushSelect"); s.onchange = function () {}; }\nwindow.initTicketIntegrations = initTicketIntegrations;`,
    ],
    [
      "a helper reachable only from another uncalled helper",
      `function inner() { document.getElementById("x").textContent = ""; }\nfunction outer() { inner(); }\nwindow.outer = outer;`,
    ],
    [
      "a local named doc that is not the document",
      `const doc = { getElementById: function () { return null; } };\ndoc.getElementById("x");`,
    ],
    [
      "an element captured and used inside the same deferred function",
      `function init() { const doc = document; doc.getElementById("x").onclick = function () {}; }\nwindow.init = init;`,
    ],
  ])("says nothing about %s", (_label, body) => {
    expect(
      hits(body),
      "flagged work that does not run at load — the gate would block a correct module",
    ).toEqual([]);
  });
});

describe("the 'the page really calls it' check separates a call from a mention", () => {
  const asks = (src: string) => callsByName(scriptFromSource("p.js", src), "initTicketIntegrations");

  it.each([
    ["a bare call", `initTicketIntegrations();`],
    ["a guarded call", `if (typeof initTicketIntegrations === "function") initTicketIntegrations();`],
    ["a call inside a handler", `btn.onclick = function () { initTicketIntegrations(); };`],
  ])("finds %s", (_label, src) => {
    expect(asks(src)).toBe(true);
  });

  it.each([
    ["a commented-out call", `// initTicketIntegrations();\nrender();`],
    ["a mention inside a string", `showToast("initTicketIntegrations() has not run yet");`],
    ["a reference that is never invoked", `const f = initTicketIntegrations;`],
    ["a page that does not mention it", `render();`],
  ])("does not count %s", (_label, src) => {
    expect(asks(src), "a comment or a string is not a call").toBe(false);
  });
});

// ── THE MISSING-MODULE GUARD ─────────────────────────────────────────────────────────────────────
//
// The seventh, eighth and ninth holes. unguardedRefs() decides whether a tier-3 module's name is
// safe to touch at a given place, and the version it replaced asked only whether the word `typeof`
// appeared somewhere in an ancestor condition. Seven shapes that ALL throw when the module 404s were
// reported as guarded; mutating each of them into the real page turned the suite red zero times out
// of seven, while stripping a guard entirely DID turn it red — so the gate was wired, and every one
// of those greens was a live bypass.
//
// Each shape below is one of those seven, with the partner that must stay silent, because a checker
// that flags the correct spelling is as useless as one that flags nothing. The early-return idiom
// gets its own block: it is house style on this page and in js/graph-view.js, and punishing it would
// be the fastest way to get this gate deleted.

const guardCases: Array<[string, string, string]> = [
  ["an inverted test", `if (typeof N !== "function") N();`, `if (typeof N === "function") N();`],
  [
    "the else branch",
    `if (typeof N === "function") {} else { N(); }`,
    `if (typeof N === "function") { N(); } else {}`,
  ],
  [
    "a test widened by ||",
    `if (typeof N === "function" || ready) N();`,
    `if (typeof N === "function" && ready) N();`,
  ],
  [
    `a test against "undefined"`,
    `if (typeof N === "undefined") N();`,
    `if (typeof N === "undefined") {} else N();`,
  ],
  [
    "the far arm of a ternary",
    `const x = typeof N === "function" ? 0 : N();`,
    `const x = typeof N === "function" ? N() : 0;`,
  ],
  [
    "a bare reference handed to a registrar",
    `el.addEventListener("click", N);`,
    `if (typeof N === "function") el.addEventListener("click", N);`,
  ],
  ["a bare reference in an initialiser", `const h = N;`, `const h = typeof N === "function" ? N : null;`],
  [
    "the right of an || rather than an &&",
    `typeof N === "function" || N();`,
    `typeof N === "function" && N();`,
  ],
  ["a comparand that is not a literal", `if (typeof N === want) N();`, `if ("function" === typeof N) N();`],
  [
    "a negation that flips the wrong way",
    `if (!(typeof N === "function")) N();`,
    `if (!(typeof N === "undefined")) N();`,
  ],
  [
    "a namespace-member call on a missing module",
    `N.hydrate({ excludeTerms: [] });`,
    `if (typeof N === "function") N.hydrate({ excludeTerms: [] });`,
  ],
];

describe("the missing-module guard is a claim about a branch, not a mention of typeof", () => {
  it.each(guardCases)("reports %s", (_label, bypass) => {
    expect(unguardedRefs(scriptFromSource("p.js", bypass), "N")).toHaveLength(1);
  });

  it.each(guardCases)("says nothing about the correct spelling of %s", (_label, _bypass, correct) => {
    expect(unguardedRefs(scriptFromSource("p.js", correct), "N")).toEqual([]);
  });

  // THE IDIOM THAT MUST SURVIVE. `if (typeof N !== "function") return;` is correct code, it is what
  // js/graph-view.js and js/dashboard-geo.js do with their vendor scripts, and a checker that only
  // walks ANCESTORS cannot see it — the guard is a preceding sibling. Flagging it would make this
  // gate a nuisance rather than a fence.
  it.each([
    ["an early return", `function f() { if (typeof N !== "function") return; N(); }`],
    ["the undefined spelling", `function f() { if (typeof N === "undefined") return; N(); }`],
    ["a block that returns", `function f() { if (typeof N === "undefined") { warn(); return; } N(); }`],
    ["an early throw", `function f() { if (typeof N !== "function") throw new Error("gone"); N(); }`],
    ["a continue", `for (const x of xs) { if (typeof N !== "function") continue; N(x); }`],
    ["an else that returns", `function f() { if (typeof N === "function") {} else return; N(); }`],
  ])("accepts %s as a guard for the rest of the block", (_label, src) => {
    expect(unguardedRefs(scriptFromSource("p.js", src), "N")).toEqual([]);
  });

  it.each([
    ["the branch does not exit", `function f() { if (typeof N !== "function") log(); N(); }`],
    ["the use comes first", `function f() { N(); if (typeof N !== "function") return; }`],
    [
      "the guard is in another block",
      `function f() { if (typeof N !== "function") return; }\nfunction g() { N(); }`,
    ],
  ])("still reports the use when %s", (_label, src) => {
    expect(unguardedRefs(scriptFromSource("p.js", src), "N")).toHaveLength(1);
  });

  // A NAME IS NOT A VALUE. `obj.N` evaluates nothing and cannot throw, so reporting it would bury
  // the real hits — while `{ N }` and `obj[N]` DO read the binding and must stay visible.
  it.each([
    ["a property name", `obj.N = 1; const o = { N: 1 }; const { N: x } = q;`],
    ["a declaration name", `function N() {}`],
    ["the typeof operand itself", `if (typeof N === "function") {}`],
    ["a label", `N: for (;;) { break N; }`],
  ])("does not mistake %s for a use", (_label, src) => {
    expect(unguardedRefs(scriptFromSource("p.js", src), "N")).toEqual([]);
  });

  it.each([
    ["a shorthand property", `const o = { N };`],
    ["a computed access", `const v = obj[N];`],
  ])("does count %s, which reads the binding", (_label, src) => {
    expect(unguardedRefs(scriptFromSource("p.js", src), "N")).toHaveLength(1);
  });
});

// ── WHICH UNGUARDED USES WOULD TAKE THE WHOLE PAGE ───────────────────────────────────────────────
//
// An unguarded use inside a click handler costs that one interaction. An unguarded use at the top
// level of the inline script aborts every line after it — which is the failure this tier introduced
// and the only one worth stopping the build for. An IIFE counts as top level: it runs exactly where
// bare code would, and dashboard.html's DfirTimelineView.hydrate() sits inside one.
describe("top-level uses are the ones that abort the script", () => {
  it.each([
    ["a bare top-level call", `N();`],
    ["a load-time IIFE", `(function () { N(); })();`],
    ["an arrow IIFE", `(() => { N.hydrate(); })();`],
    ["a try with only a finally", `try { N(); } finally { done(); }`],
  ])("reports %s", (_label, src) => {
    expect(topLevelUnguardedRefs(scriptFromSource("p.js", src), "N")).toHaveLength(1);
  });

  it.each([
    ["a function body", `function f() { N(); }`],
    ["a listener registered at top level", `el.addEventListener("click", () => N());`],
    ["a try that catches", `try { N(); } catch (e) {}`],
    ["a guarded top-level call", `if (typeof N === "function") N();`],
  ])("does not report %s", (_label, src) => {
    expect(topLevelUnguardedRefs(scriptFromSource("p.js", src), "N")).toEqual([]);
  });
});

// ── A CALL THE PAGE NEVER MAKES IS NOT A CALL ────────────────────────────────────────────────────
//
// callsByName exists to prove the page really invokes an extracted initializer rather than merely
// containing its name in a comment. Review found two ways past it that a comment check would never
// have caught: putting the call inside a function nothing invokes, and putting it inside `if (false)`.
// Both leave the page never running the feature while the assertion stays green.
describe("callsByName counts only calls the page can reach", () => {
  const cb = (src: string): boolean => callsByName(scriptFromSource("p.js", src), "N");

  it.each([
    ["a top-level call", `N();`],
    ["a guarded top-level call", `if (typeof N === "function") N();`],
    ["a call from a function the page calls", `function live() { N(); }\nlive();`],
    ["a call two hops away", `function a() { N(); }\nfunction b() { a(); }\nb();`],
    ["a call from a top-level callback", `el.addEventListener("click", () => N());`],
    ["a handler merely referenced at top level", `function h() { N(); }\nel.onclick = h;`],
    ["a call inside a load-time IIFE", `(function () { N(); })();`],
  ])("counts %s", (_label, src) => {
    expect(cb(src)).toBe(true);
  });

  it.each([
    ["a comment", `// N();\nconst x = 1;`],
    ["a function nothing invokes", `function dead() { N(); }`],
    ["a handler installed by a function nothing invokes", `function w() { el.onclick = () => N(); }`],
    ["if (false)", `if (false) { N(); }`],
    ["if (0)", `if (0) N();`],
    ["the else of if (true)", `if (true) {} else { N(); }`],
    ["while (false)", `while (false) { N(); }`],
  ])("does not count %s", (_label, src) => {
    expect(cb(src)).toBe(false);
  });
});

// A GUARD IS NOT AN ESCAPE — the false positive the tier-3 guards themselves triggered.
//
// ownerEscapes exists to catch an owner namespace being aliased or reached dynamically, because
// either defeats the "one commit, one redraw" rule the owners enforce. It classified ANY bare
// reference outside a callee position as the namespace being passed somewhere. That was safe only
// while no such reference existed — and the moment `DfirTimelineView.hydrate()` was wrapped in
// `if (typeof DfirTimelineView !== "undefined")` so a 404 of its module could not blank the
// dashboard, the escape gate fired on all three guards at once.
//
// `typeof` does not even evaluate the binding. It cannot alias and it cannot reach dynamically;
// it is the ONLY operation that is safe on an undeclared name, which is the whole reason the
// guards are spelled that way. So it is excluded — and the partner case below keeps that exclusion
// from quietly swallowing the aliases this gate is actually for.
describe("a typeof guard on an owner is not an escape", () => {
  it.each([
    ["a bare guard", `if (typeof DfirScope !== "undefined") DfirScope.get();`],
    ["the undefined comparison", `if (typeof DfirScope === "undefined") warn();`],
    ["parenthesised", `if (typeof (DfirScope) !== "undefined") DfirScope.get();`],
    ["stored as a boolean", `const present = typeof DfirScope !== "undefined";`],
  ])("does not report %s", (_label, src) => {
    expect(ownerEscapes([scriptFromSource("p.js", src)], "DfirScope")).toEqual([]);
  });

  it.each([
    ["a const alias", `const s = DfirScope; s.get();`],
    ["passed as an argument", `register(DfirScope);`],
    ["a computed member", `DfirScope["get"]();`],
  ])("still reports %s", (_label, src) => {
    expect(ownerEscapes([scriptFromSource("p.js", src)], "DfirScope").length).toBeGreaterThan(0);
  });
});
