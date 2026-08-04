// Loads one of public/js/dashboard-*.js the way the browser actually loads it (#415).
//
// Those eight files are CLASSIC scripts, not ES modules, and deliberately so: dashboard.html's
// inline script calls their functions by bare name at 427 sites, one of them while the page is
// still parsing, so the declarations have to be real globals. See public/js/dashboard-escape.js
// for the full argument.
//
// The consequence for tests is that they cannot be `import`ed — a classic script has no exports.
// Running them in a vm context instead is not a workaround, it is a better test: it exercises the
// same contract the browser does. A file that fails to declare a global, or publishes a namespace
// missing a function the dashboard still calls, fails here. An `import` would have told us nothing
// about either, which is exactly how #414 shipped a module whose 29 passing unit tests coexisted
// with a Diagnostics panel that threw on every render.

import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import ts from "typescript";

/**
 * The dashboard's first-party client scripts, in the order dashboard.html tags them.
 *
 * dashboard-state.js is in the list but is not one of the eight helper modules: it is the state
 * store, and it is here because dashboardClientSource() below means "everything the dashboard's
 * own code lives in", not "everything #415 extracted".
 */
export const DASHBOARD_HELPER_FILES = [
  "dashboard-state.js",
  "dashboard-escape.js",
  "dashboard-time.js",
  "dashboard-text.js",
  "dashboard-glyphs.js",
  "dashboard-filters.js",
  "dashboard-ioc.js",
  "dashboard-values.js",
  "dashboard-fragments.js",
] as const;

/**
 * public/css/dashboard.css on its own.
 *
 * For suites whose subject IS the CSS — the Settings search and Essential-mode rules, which are
 * deliberately implemented as stylesheet rules rather than render-time branches so a late status
 * answer cannot miss them. Those read the stylesheet directly rather than the whole client source,
 * because a selector assertion that accidentally matched a string inside a JS module would pass
 * for the wrong reason.
 */
export function dashboardStylesheet(): string {
  return readFileSync(new URL("../../../public/css/dashboard.css", import.meta.url), "utf8");
}

/**
 * dashboard.html plus its stylesheet plus the eight helper files, concatenated.
 *
 * A dozen suites assert things about the dashboard by grepping dashboard.html, because until #415
 * every line of its client code was in that one file. It no longer is, and the distinction those
 * tests care about is "does the dashboard do this", not "is this string in that file" — so they
 * read the whole client source instead of one file of it.
 *
 * The stylesheet is in here for the same reason as the scripts. Several of those assertions are
 * about CSS: dashboardTicketPush pins that the Jira and ServiceNow chips are hidden by a rule on
 * <body> rather than a render-time branch, precisely because the status answer can arrive after
 * the findings have rendered. That check does not care which file the rule is in.
 *
 * Use this where the assertion is about BEHAVIOUR. Where it is about the markup — a section id, a
 * script tag, an inline handler attribute — keep reading dashboard.html on its own, or the check
 * starts scanning JavaScript and CSS for HTML and finds the wrong things.
 */
export function dashboardClientSource(): string {
  const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
  const html = read("../../../public/dashboard.html");
  // The dashboard-*.js scripts the page tags, read from the MARKUP rather than from a list.
  //
  // This was DASHBOARD_HELPER_FILES, and the list went stale exactly as a hard-coded list does: it
  // named the original eight helpers and none of the tier-2 owners or tier-3 feature modules, so
  // four suites asserting "the dashboard does X" broke the moment X moved into a file it did not
  // mention. dashboardScripts() reads the markup for the same reason.
  //
  // NOT "every first-party script", which an earlier version of this comment claimed: graph-view,
  // the command palette, settings-search, the a11y modules and every transitive import are outside
  // it. Use dashboardScripts() where the question is about all of the client code; this exists for
  // suites whose subject is the dashboard's own feature code.
  //
  // AND IT IS A CONCATENATION, so a location-sensitive assertion can pass on an occurrence in a
  // different file. Where a test cares WHERE something lives — the CSP nonce on inline blocks, the
  // report logo's FileReader — read that file directly instead.
  const tagged = [...html.matchAll(/<script[^>]*\ssrc="\/js\/(dashboard-[^"]+)"/g)].map((m) => m[1]);
  return [
    html,
    read("../../../public/css/dashboard.css"),
    ...tagged.map((f) => read(`../../../public/js/${f}`)),
  ].join("\n");
}

/**
 * The global object a loaded helper module sees, with its own `window` self-reference.
 *
 * `unknown`, not `any`. The first draft of this helper exported `Record<string, any>` behind an
 * `eslint-disable`, on the argument that the modules are plain JS with no .d.ts so there was
 * nothing to check against. That was the wrong trade twice over: it left every one of the ~300
 * helper calls in tests/dashboard unchecked — including the argument shapes those tests exist to
 * pin — and it put a suppression in a shared helper, where it spreads to every test written
 * against it. This repo's eslint config is deliberately small and fully enforced with no baseline
 * file, and a suppression in the one file everything imports is exactly how that erodes.
 *
 * Callers pass the surface they use as `T` instead (see `loadDashboardModule`), so each test file
 * states the contract it is testing and gets it checked. The single unavoidable cast lives at the
 * bottom of this file, where a vm sandbox becomes that `T`.
 */
export type DashboardGlobals = Record<string, unknown>;

/**
 * Names the sandbox borrows from THIS realm instead of using the vm's own copy.
 *
 * `Date` is the one that matters, and it has to be borrowed LIVE — hence a getter rather than a
 * copied reference. Two things stack up:
 *
 *   1. A vm context gets a fresh copy of every ECMAScript built-in, so a module calling
 *      `Date.now()` inside it is invisible to `vi.useFakeTimers()`, which patches only the test
 *      realm's Date. Six of these helpers are relative-time formatters whose entire behaviour is a
 *      function of "now", so without this they can only be tested against a moving clock.
 *   2. `useFakeTimers()` REPLACES `globalThis.Date` with a mock class. A sandbox that captured the
 *      real Date at load time keeps pointing at the real one, so the fake clock still does not
 *      reach it — and the module is loaded once at the top of a test file, long before any
 *      `beforeEach` installs the fake. Reading `globalThis.Date` per access is what makes a module
 *      loaded at import time still see a clock frozen later.
 *
 * `btoa`/`atob` are here for an unrelated reason: they are browser globals a vm context does not
 * provide at all (they are not part of the language), and arrayBufferToBase64 calls one. Anything
 * else a file expects from the browser — a stub FileReader, a fake element — goes in `extraGlobals`.
 */
const HOST_GLOBAL_NAMES = ["Date", "btoa", "atob", "console"] as const;

function borrowHostGlobals(sandbox: DashboardGlobals): void {
  for (const name of HOST_GLOBAL_NAMES) {
    Object.defineProperty(sandbox, name, {
      get: () => (globalThis as DashboardGlobals)[name],
      configurable: true,
      enumerable: true,
    });
  }
}

/**
 * Run `public/js/<file>` in a fresh context and hand back its globals.
 *
 * `preload` names sibling helpers to run first, for the handful of cross-file calls (fragments
 * reaches for esc/escAttr and cockpitAge). They resolve at CALL time in the browser, so tag order
 * there is documentation; here they have to actually be present.
 *
 * `extraGlobals` seeds anything else the file expects the browser to have supplied — a stub
 * FileReader, a fake element. Passing one is a statement that the function under test takes that
 * capability from the environment, which is worth having to write down.
 *
 * `T` IS THE POINT. Each caller declares the slice of the module's surface it uses — see the
 * `*Api` interfaces at the top of every tests/dashboard suite — and gets its calls type-checked
 * against it. Those interfaces are hand-written because the modules are plain JS with no .d.ts, so
 * they are a claim rather than a derivation; the runtime assertions in dashboardModules.test.ts
 * are what keep the claim honest, by checking that every declared function really is published.
 *
 * The signatures are deliberately as permissive as the functions really are (`unknown` where a
 * helper does `String(x)`, `| null` where it guards). Tightening them past what the JS accepts
 * would make the edge cases these suites exist to pin — `activityTimeAgo(null)`, `truncate(12345)`
 * — fail to compile, which would be the type system lying about the code under test.
 */
export function loadDashboardModule<T = DashboardGlobals>(
  file: string,
  preload: string[] = [],
  extraGlobals: DashboardGlobals = {},
): T {
  const sandbox = freshSandbox(extraGlobals);
  for (const dep of [...preload, file]) {
    const path = new URL(`../../../public/js/${dep}`, import.meta.url);
    runInContext(readFileSync(path, "utf8"), sandbox, { filename: dep });
  }
  // THE ONE CAST. A vm sandbox is a bag of properties the compiler cannot know; every other file
  // in tests/dashboard is fully typed because this line absorbs that once, here, on purpose.
  return sandbox as unknown as T;
}

/** An empty vm context seeded the way a loaded module expects to find one. */
function freshSandbox(extraGlobals: DashboardGlobals = {}): DashboardGlobals {
  const sandbox: DashboardGlobals = {};
  borrowHostGlobals(sandbox);
  Object.assign(sandbox, extraGlobals);
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  createContext(sandbox); // contextifies in place and returns the same object
  return sandbox;
}

/**
 * The names a file adds to the global object when it runs.
 *
 * For asserting that a module leaks NOTHING but its namespace. js/dashboard-state.js needs that:
 * its single-writer rule is enforced by counting `DfirState.setActiveView(` call sites, and a
 * top-level `const` in a classic script goes into the global LEXICAL environment — shared by every
 * other script on the page — even though it never appears on the global object. A helper hoisted
 * out of that file's IIFE would be writable by name from anywhere, with the call-site count still
 * reading one.
 *
 * Lexical bindings are invisible here by construction, so this checks the property side and the
 * companion test proves the lexical side by trying the bypass and expecting a ReferenceError.
 */
export function globalsAddedBy(file: string, preload: string[] = []): string[] {
  // `preload` for the same reason loadDashboardModule takes one, and it is not optional for every
  // module: js/dashboard-scope.js builds its cell from DfirState.cell at LOAD time, so without its
  // dependency present it does not merely fail to publish — it throws while loading. Baselining
  // AFTER the dependencies have run is what keeps the answer "what did THIS file add".
  const before = new Set(
    preload.length
      ? Object.keys(loadDashboardModule<DashboardGlobals>(preload[preload.length - 1], preload.slice(0, -1)))
      : Object.keys(freshSandbox()),
  );
  const after = loadDashboardModule<DashboardGlobals>(file, preload);
  return Object.keys(after).filter((name) => !before.has(name));
}

/**
 * Every top-level function the file declares, by name.
 *
 * AST-based since #462's audit. This began as `/^function (\w+)\s*\(/gm`, which was the same
 * mistake the state gates made: it sees `function foo(` and nothing else, so an `async function`
 * is invisible. That went unnoticed while the helper modules happened to contain none — and then
 * the first feature module arrived with ten of its twelve functions async, and the check that is
 * supposed to prove "every declared function is published" silently compared two names against
 * twelve.
 *
 * Top-level only, deliberately: this answers "what does this file promise to publish", and a
 * callback nested inside one of those functions promises nothing.
 */
export function declaredFunctions(file: string): string[] {
  const source = readFileSync(new URL(`../../../public/js/${file}`, import.meta.url), "utf8");
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const out: string[] = [];
  const visit = (n: ts.Node): void => {
    // Descend through an IIFE wrapper (js/dashboard-state.js has one) but not into real functions.
    if (ts.isFunctionDeclaration(n) && n.name) {
      out.push(n.name.text);
      return;
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);
  return out;
}
