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

export function dashboardClientSource(): string {
  const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
  return [
    read("../../../public/dashboard.html"),
    read("../../../public/css/dashboard.css"),
    ...DASHBOARD_HELPER_FILES.map((f) => read(`../../../public/js/${f}`)),
  ].join("\n");
}

/**
 * The global object a loaded helper module sees, with its own `window` self-reference.
 *
 * `any` rather than `unknown`, deliberately. These files are plain JS with no .d.ts, and the point
 * of the tests is to CALL the functions they declare — `Record<string, unknown>` would make every
 * one of the ~300 call sites in tests/dashboard a cast, which buys no safety and hides the shapes
 * the tests are there to pin. The same trade tests/reports/diagnosticsPanel.test.ts makes with its
 * `@ts-expect-error` on the module import.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type DashboardGlobals = Record<string, any>;

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
 */
export function loadDashboardModule(
  file: string,
  preload: string[] = [],
  extraGlobals: DashboardGlobals = {},
): DashboardGlobals {
  const sandbox: DashboardGlobals = {};
  borrowHostGlobals(sandbox);
  Object.assign(sandbox, extraGlobals);
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  createContext(sandbox);
  for (const dep of [...preload, file]) {
    const path = new URL(`../../../public/js/${dep}`, import.meta.url);
    runInContext(readFileSync(path, "utf8"), sandbox, { filename: dep });
  }
  return sandbox;
}

/**
 * Every top-level `function` the file declares must appear in its namespace.
 *
 * Parsed out of the source text rather than diffed against the context's own keys, because a vm
 * sandbox is pre-populated with the JS built-ins and telling those apart from the module's own
 * declarations is guesswork. The declarations are what the file promises; this checks it kept the
 * promise.
 */
export function declaredFunctions(file: string): string[] {
  const src = readFileSync(new URL(`../../../public/js/${file}`, import.meta.url), "utf8");
  return [...src.matchAll(/^function ([A-Za-z_$][\w$]*)\s*\(/gm)].map((m) => m[1]);
}
