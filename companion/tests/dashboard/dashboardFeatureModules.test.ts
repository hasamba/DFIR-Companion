import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { runInContext } from "node:vm";
import {
  callsAfter,
  callsByName,
  dashboardScripts,
  domAccessOutsideFunctions,
  functionsOf,
  moduleGlobals,
  scriptFromSource,
  topLevelBindings,
  unguardedTopLevelRefs,
} from "../helpers/dashboardAst.js";
import { globalNamesOf, globalsAddedBy, loadDashboardModule } from "../helpers/dashboardModule.js";

// TIER 3 (#415): whole features moved out of the inline script, each owning its own state.
//
// One suite for eight modules rather than eight suites, because the assertions are identical in
// shape and the differences that matter are data — which names each publishes, which state each
// keeps private. A per-module file would be eight copies of the same five checks.
//
// WHY THESE EIGHT, AND WHY AN IIFE. The measurement for this tier found nine features with ZERO
// escaping reads: every mutable binding they touch is read by nothing else, so the binding travels
// with the feature. That is the ADR's own plan for tier 3 — "they move into their feature's module
// as `let` at module scope and never become anyone's API" — with one correction. In a CLASSIC
// script a top-level `let` joins the shared global lexical environment, so it would still be
// reachable by name from every other script; js/dashboard-tagger.js and js/dashboard-kev.js got
// away with top-level declarations only because they hold no state. These do, so they are wrapped,
// and only the names the page actually calls are published.

const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

interface Feature {
  file: string;
  /** Names the inline script calls by bare name, so the module must put them on `window`. */
  publish: string[];
  /** State that must NOT be reachable from outside the closure. */
  private: string[];
  /** A published entry point that does the feature's load-time work, if it has one. */
  initializer?: string;
  /** Names that only exist AFTER the initializer has run. */
  postInitPublish?: string[];
}

const FEATURES: Feature[] = [
  {
    file: "dashboard-anomalies.js",
    publish: ["loadAnomalies", "scheduleAnomaliesReload", "markAnomalySpikeFalsePositive"],
    private: ["anomaliesData", "anomaliesTimer"],
  },
  {
    file: "dashboard-sessions.js",
    publish: ["loadSessions", "scheduleSessionsReload", "summarizeSession"],
    private: ["sessionsData", "sessionsTimer", "sessionSummaries"],
  },
  {
    file: "dashboard-compliance.js",
    publish: [
      "loadCompliance",
      "scheduleComplianceReload",
      "setComplianceDiscovered",
      "clearComplianceDiscovered",
      "toggleComplianceFramework",
    ],
    private: ["complianceData", "complianceTimer"],
  },
  {
    file: "dashboard-d3fend.js",
    publish: ["loadD3fend", "scheduleD3fendReload"],
    private: ["d3fendData", "d3fendTimer"],
  },
  {
    file: "dashboard-geo.js",
    publish: [
      "loadGeoMap",
      "scheduleGeoMapReload",
      "renderGeoView",
      "ensureGeoMap",
      "renderGeoMarkers",
      "geoFocusIp",
      "geoDownloadCsv",
    ],
    private: [
      "geoMapData",
      "geoMap",
      "geoLayer",
      "geoFlowLayer",
      "geoMapTimer",
      "geoMapInitializing",
      // Missing from the first inventory, which is its own argument for asserting the EXACT global
      // set rather than listing names by hand and hoping the list is complete.
      "geoTileUrl",
    ],
  },
  {
    file: "dashboard-custody.js",
    publish: ["initCustodyButtons", "loadCustody", "verifyCustodyOnOpen"],
    private: ["custodyRecords", "custodyFailedPaths", "custodyVerifiedAt"],
  },
  { file: "dashboard-backup.js", publish: ["loadCaseBackups", "restoreCaseBackup"], private: [] },
  {
    // The load-time-heavy one: everything it does on load is wrapped in initTicketIntegrations(),
    // which the page calls where the block used to sit. openIrisImportModal is published from
    // INSIDE that function, so it is not on this list — the exact-globals check below would
    // otherwise fail, which is the honest signal that it appears later rather than at load.
    file: "dashboard-tickets.js",
    publish: ["pushFindingToTicket", "bulkPushFindingsToTicket", "initTicketIntegrations"],
    private: [
      // The re-entry latch this PR added. It was missing from the first version of this list, and
      // moving it out to shared global scope passed every test in the file — the same lesson the
      // geoTileUrl note above records, one tier later.
      "initialised",
      "pushSelect",
      "notionHasDefault",
      "clickupDefaultList",
      "notionOverlay",
      "irisImportOverlay",
      "irisReconnectBtn",
      "clickupOverlay",
      "irisPushOverlay",
    ],
    // Everything this module does happens when the page calls initTicketIntegrations(), so the
    // checks that matter have to RUN it — see the block at the bottom of this file.
    initializer: "initTicketIntegrations",
    postInitPublish: ["openIrisImportModal"],
  },
  {
    file: "dashboard-collection-plan.js",
    publish: ["fetchCollectionResults", "renderCollectionPlan"],
    private: [],
  },
  {
    // The canvas chart. Like dashboard-tickets.js, all of its load-time work is DOM wiring —
    // eleven listeners on the canvas and toolbar plus a ResizeObserver — so it is wrapped in
    // initSwimlane() and the page calls it where the old IIFE sat. Unlike tickets the initializer
    // publishes nothing, so there is no postInitPublish list: all six names appear at load.
    //
    // swLocateInTable is NOT here on purpose. Its name says swimlane, its body scrolls a row in
    // #forensicTimeline, and both callers are inside jumpToEvent, which stayed in the page.
    file: "dashboard-swimlane.js",
    publish: [
      "loadSwimlane",
      "scheduleSwimlaneReload",
      "swRenderCanvas",
      "swSelToolbar",
      "swReflectSelection",
      "initSwimlane",
    ],
    private: [
      "SW_LANE_H",
      "SW_AXIS_H",
      "SW_DOT_R",
      "SW_SEV_TOKEN",
      "SW_LABEL_TOKEN",
      "SW_AXIS_LABEL",
      "swLanes",
      "swDataMinMs",
      "swDataMaxMs",
      "swViewStartMs",
      "swViewEndMs",
      "swDrag",
      "swDragMoved",
      "swDragStartX",
      "swDragViewStart",
      "swHoverEvId",
      "swSelEvId",
      "swTimer",
      "swRubber",
      "swTimeBrush",
    ],
    // The thirteen private FUNCTIONS (swFitView, swUpdateSubtitle, swZoomRatio, swTsToX, swXToTs,
    // swRenderLabels, swHitTest, swShowDetail, swUpdateZoomLabel, swSelectionChanged,
    // swFinishRubber, swScopeToView, swExportPng) are deliberately not on that list: it exists to
    // catch a binding that is assigned but never declared, and a function declaration cannot
    // become an implicit global. That they stay off `window` is already asserted by the
    // exact-globals check.
    initializer: "initSwimlane",
  },
];

/**
 * The names a loaded module put on the global object, ignoring the sandbox's own furniture.
 *
 * The vm context is seeded with `window`/`globalThis`, the host globals the loader borrows live
 * (Date, btoa, atob, console — see dashboardModule.ts) and whatever `extraGlobals` the caller
 * supplied. None of those are the module's doing.
 */
const SANDBOX_FURNITURE = new Set(["window", "globalThis", "Date", "btoa", "atob", "console"]);
const globalsOf = (api: Record<string, unknown>, seeded: string[] = []): string[] =>
  globalNamesOf(api).filter((k) => !SANDBOX_FURNITURE.has(k) && !seeded.includes(k));

// THE HELPER'S OWN CONTRACT.
//
// Both global-set checks in this file are only as good as the property enumeration under them, and
// the first one was `Object.keys`. That cannot see a global published as
// `Object.defineProperty(window, "debugTickets", { value: x, enumerable: false })` — which is
// exactly how you write a debug handle you would rather not have show up in a console dir() of the
// global object. The property is on `window`, every other script on the page can read it by bare
// name, and the exact-globals gate reported a clean module. Reachability has nothing to do with
// enumerability.
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

const read = (f: string) => readFile(new URL(`../../../public/js/${f}`, import.meta.url), "utf8");
const scripts = dashboardScripts();

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
    // ANY indentation: dashboard-tickets.js declares fourteen of its functions inside
    // initTicketIntegrations(), and an IIFE-level pattern saw none of them — so a duplicate left
    // behind in the page went unnoticed.
    const declared = [...src.matchAll(/^\s*(?:async )?function (\w+)\s*\(/gm)].map((m) => m[1]);
    expect(declared.length, "no functions found — the extraction produced an empty module").toBeGreaterThan(
      0,
    );
    const inline = scripts.filter((s) => s.name.startsWith("dashboard.html#inline"));
    // DECLARATIONS only. The ACTIONS dispatch table holds
    // `setComplianceDiscovered: (el) => setComplianceDiscovered(el)` entries whose arrow takes the
    // property's name — those must stay, since they are how a click reaches the module.
    const leftBehind = inline.flatMap((s) =>
      functionsOf(s)
        .filter((f) => f.declaration && declared.includes(f.name))
        .map((f) => `${s.name}:${f.line} ${f.name}`),
    );
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
    const main = blocks.find((m) => /\n\s*function render\s*\(/.test(m[1]));
    expect(main).toBeDefined();
    expect(tag).toBeLessThan(main!.index);
    expect(STATIC_ASSETS[`/js/${feat.file}`]).toBe("application/javascript; charset=utf-8");
  });

  it("stays a classic script", async () => {
    const src = await read(feat.file);
    expect(src).not.toMatch(/^\s*(?:export|import)\s/m);
  });
});

// ── RUNNING THE INITIALIZER ──────────────────────────────────────────────────────────────────────
//
// Everything above stops at module LOAD. For dashboard-tickets.js that is almost nothing: four DOM
// captures, seven status fetches, a dozen listener registrations and the fourth public function all
// appear only when initTicketIntegrations() runs. Review proved what load-time-only checks certify
// here — deleting `window.openIrisImportModal`, deleting the irisImportOverlay declaration, and
// leaking `window.debugTickets` from inside the initializer ALL passed the whole suite.
//
// So the initializer is executed against a DOM fixture and the global delta is asserted on both
// sides of it.
describe("initTicketIntegrations", () => {
  const feat = FEATURES.find((f) => f.file === "dashboard-tickets.js")!;
  const SEEDED = ["document", "fetch"];

  // EVERY control this feature owns, named. This was `listeners.length > 4`, and a threshold cannot
  // tell "all fifteen" from "any five": deleting the Notion backdrop listener, the Notion cancel
  // button, the ClickUp push button, the Notion mode radios or the IRIS reconnect handler each left
  // fourteen and passed. Naming them also catches the opposite mistake — a duplicate registration,
  // which a `>` can only ever read as more evidence of success.
  const WIRED = [
    "clickupCancel:onclick",
    "clickupOverlay:click",
    "clickupPushBtn:onclick",
    "irisImportCancel:onclick",
    "irisImportOverlay:click",
    "irisImportRun:onclick",
    "irisPushBtn:onclick",
    "irisPushCancel:onclick",
    "irisPushOverlay:click",
    "irisReconnectBtn:onclick",
    "notionCancel:onclick",
    "notionExportBtn:onclick",
    "notionMode:onchange",
    "notionOverlay:click",
    "pushSelect:onchange",
  ];

  // And every status probe. `fetched.length > 4` passed with any two of these deleted, which is a
  // Push menu missing two of its targets for every analyst whose server has them configured.
  const STATUS_PROBES = [
    "/clickup/status",
    "/iris/status",
    "/jira/status",
    "/misp/status",
    "/notion/status",
    "/servicenow/status",
    "/timesketch/status",
  ];

  /** Enough of a browser for the initializer to wire itself up, and a counter for what it fetched. */
  function fixture(breakOn: () => string | null = () => null) {
    const els = new Map<string, Record<string, unknown>>();
    const listeners: string[] = [];
    const fetched: string[] = [];
    const el = (id: string): Record<string, unknown> => {
      if (!els.has(id)) {
        els.set(id, {
          id,
          value: "",
          textContent: "",
          innerHTML: "",
          disabled: false,
          hidden: false,
          style: {},
          options: [],
          classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
          addEventListener: (type: string) => listeners.push(`${id}:${type}`),
          // Most of this feature wires itself with `el.onclick = …` rather than addEventListener,
          // so counting only the latter reported four handlers for a feature that installs dozens.
          set onclick(fn: unknown) {
            if (typeof fn === "function") listeners.push(`${id}:onclick`);
          },
          set onchange(fn: unknown) {
            if (typeof fn === "function") listeners.push(`${id}:onchange`);
          },
          appendChild() {},
          querySelector: () => null,
          querySelectorAll: () => [],
        });
      }
      return els.get(id) as Record<string, unknown>;
    };
    // The Notion mode radios are the ONE control this feature wires through a SELECTOR rather than
    // an id, and a querySelectorAll answering [] for everything made them invisible — the fixture
    // would have certified a Notion modal whose new-vs-existing switch was never wired.
    const BY_SELECTOR: Record<string, string[]> = { 'input[name="notionMode"]': ["notionMode"] };
    // A missing element is how this feature really breaks — `getElementById(x).onclick = …` on a
    // null throws — so the fixture can be told to fail one lookup and then be repaired.
    const getElementById = (id: string): Record<string, unknown> => {
      if (breakOn() === id) throw new Error(`markup missing: ${id}`);
      return el(id);
    };
    const document = {
      getElementById,
      querySelector: () => null,
      querySelectorAll: (sel: string) => (BY_SELECTOR[sel] ?? []).map(el),
      createElement: () => el("__created"),
      body: { classList: { add() {}, remove() {} }, insertBefore() {}, firstChild: null },
      addEventListener() {},
    };
    const fetchStub = (url: string) => {
      fetched.push(url);
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ configured: false }) });
    };
    return { document, fetch: fetchStub, listeners, fetched };
  }

  const load = () => {
    const fx = fixture();
    const api = loadDashboardModule<Record<string, unknown>>("dashboard-tickets.js", [], {
      document: fx.document,
      fetch: fx.fetch,
    });
    return { api, fx };
  };

  it("publishes nothing extra before it runs", () => {
    const { api } = load();
    expect(globalsOf(api, SEEDED).sort()).toEqual([...feat.publish].sort());
  });

  // THE CHECK THE LOAD-TIME ONES CANNOT MAKE. An extra `window.debugTickets` inside the initializer
  // is invisible until the initializer has actually run.
  it("adds exactly its post-init globals, and nothing else", () => {
    const { api } = load();
    (api[feat.initializer!] as () => void)();
    expect(globalsOf(api, SEEDED).sort()).toEqual([...feat.publish, ...feat.postInitPublish!].sort());
  });

  it("leaves the late-published entry point callable", () => {
    const { api } = load();
    (api[feat.initializer!] as () => void)();
    for (const name of feat.postInitPublish!) {
      expect(typeof api[name], `${name} is not callable after init`).toBe("function");
    }
  });

  it("keeps its state private even after wiring itself up", () => {
    const { api } = load();
    (api[feat.initializer!] as () => void)();
    for (const name of feat.private) {
      expect(() => runInContext(name, api as object), `${name} escaped the closure`).toThrow(
        new RegExp(`${name} is not defined`),
      );
    }
  });

  it("wires every control it owns, named one by one", () => {
    const { api, fx } = load();
    (api[feat.initializer!] as () => void)();
    expect(
      [...fx.listeners].sort(),
      "a control this feature owns is unwired, or wired twice — either way the analyst sees a " +
        "button that does the wrong thing, and no error anywhere",
    ).toEqual([...WIRED].sort());
  });

  it("asks the server about every push target it can offer", () => {
    const { api, fx } = load();
    (api[feat.initializer!] as () => void)();
    expect(
      [...fx.fetched].sort(),
      "a status probe is missing — that target never appears in the Push menu, however the server " +
        "is configured",
    ).toEqual([...STATUS_PROBES].sort());
  });

  // Hardening rather than a live bug: nothing calls it twice today, but it is a published entry
  // point, and a second run would re-fire every status request and stack a duplicate listener on
  // each overlay.
  it("is idempotent", () => {
    const { api, fx } = load();
    (api[feat.initializer!] as () => void)();
    const after = { fetched: fx.fetched.length, listeners: fx.listeners.length };
    (api[feat.initializer!] as () => void)();
    expect({ fetched: fx.fetched.length, listeners: fx.listeners.length }).toEqual(after);
  });

  // ...AND IDEMPOTENT IS NOT THE SAME AS LATCHED.
  //
  // The flag used to be set on the initializer's FIRST line, which made the test above pass for a
  // reason it never intended: a run that threw had already latched, so every later call returned —
  // silently, with no second error and nothing on screen — and the feature was dead for the life of
  // the page. Break the LAST section, repair the DOM, call again: the retry has to reach the wiring
  // the first run never got to.
  it("stays retryable after a run that threw", () => {
    let broken = true;
    const fx = fixture(() => (broken ? "irisPushCancel" : null));
    const api = loadDashboardModule<Record<string, unknown>>("dashboard-tickets.js", [], {
      document: fx.document,
      fetch: fx.fetch,
    });

    expect(() => (api[feat.initializer!] as () => void)()).toThrow(/irisPushCancel/);
    // The break has to be late enough to leave real wiring behind it, or the retry proves nothing.
    expect(fx.listeners, "nothing was wired before the break — move it later").not.toEqual([]);
    expect(fx.listeners).not.toContain("irisPushBtn:onclick");

    broken = false;
    (api[feat.initializer!] as () => void)();
    expect(
      fx.listeners,
      "the initializer latched on entry, so one missing element killed all seven ticket " +
        "integrations for the life of the page",
    ).toContain("irisPushBtn:onclick");
  });

  // ORDER, NOT JUST FINAL STATE.
  //
  // Every other check here asserts what is on the global object once the initializer has finished,
  // so moving `window.openIrisImportModal = …` back to the last line of init passes all of them.
  // The comment at that line claims something stronger — that the Import-case chooser keeps working
  // even when a LATER section throws — and the only way to observe an intermediate state is to stop
  // the initializer in the middle of one. The break is the first DOM read after the publication, so
  // this pins it to the IRIS-import section rather than merely "somewhere before the end".
  it("publishes the Import-case entry point before the wiring that follows it", () => {
    const fx = fixture(() => "irisReconnectBtn");
    const api = loadDashboardModule<Record<string, unknown>>("dashboard-tickets.js", [], {
      document: fx.document,
      fetch: fx.fetch,
    });

    expect(() => (api[feat.initializer!] as () => void)()).toThrow(/irisReconnectBtn/);
    expect(fx.listeners, "the run stopped before the Import-case section").toContain("irisImportRun:onclick");
    expect(fx.listeners, "the run did not stop where this test needs it to").not.toContain(
      "clickupCancel:onclick",
    );
    expect(
      typeof api.openIrisImportModal,
      "openIrisImportModal is published after the reconnect / ClickUp / IRIS-push wiring, so a throw " +
        "in any of them leaves the Import-case button calling a name that was never published",
    ).toBe("function");
  });
});

// ── A MISSING MODULE MUST NOT TAKE THE PAGE WITH IT ──────────────────────────────────────────────
//
// Each of these is a separate <script src>. Blocking just one in Chromium threw a ReferenceError at
// its call site, and because that call sits at the top level of the inline script the throw aborted
// EVERYTHING AFTER IT: URL case restoration never ran, unrelated toggles stayed unwired, and the
// dashboard sat disconnected. That failure mode did not exist while the code was inline, so it is a
// regression this tier introduced rather than a pre-existing risk.
describe("a feature script that fails to load", () => {
  const inline = dashboardScripts().filter((s) => s.name.startsWith("dashboard.html#inline"));

  // Every entry point whose throw is NOT contained to the interaction that caused it. Two shapes
  // qualify: a call at the top level of the inline script (the rest of the script never runs), and
  // a call at the head of a function whose own callers swallow the throw.
  //
  // renderCollectionPlan is the second shape, and it is why the ordering test below exists. render()
  // called it on its first line, and render()'s two callers are the bare `catch {}` in
  // proceedConnect's state load and ws.onmessage, which has no catch at all. A 404 on
  // js/dashboard-collection-plan.js therefore aborted the whole of render(): the analyst got
  // "connected (live)" over a dashboard whose summary was still "—", with nothing said anywhere.
  // THE SET OF NAMES IS DERIVED FROM THE MODULES, not written by hand. The hand-written list this
  // replaces named verifyCustodyOnOpen, which the page never calls at the top level, and omitted
  // every name that was a live hazard on the day it was written — the three bare
  // `addEventListener("click", kevImportUrl)` references and the three `DfirTimelineView.…()` calls.
  // Neither mistake could ever have failed the gate, because the gate only looked at the list.
  //
  // IN-FUNCTION REFERENCES ARE NOT THIS GATE'S BUSINESS, which is why deriving the set does not
  // drown it. The page reads these names some six hundred times from inside renderers and handlers,
  // and a throw there is contained to that one interaction. Only a reference EVALUATED AT LOAD can
  // abort the script and take the remaining wiring with it.
  const owners = moduleGlobals(scripts);

  // A derived gate's characteristic failure is harvesting nothing and passing vacuously, so the
  // harvest is asserted before anything is asserted with it.
  it("harvests the globals it is meant to be checking", () => {
    expect(owners.size, "no module globals found — the harvest is broken, not the page").toBeGreaterThan(100);
    for (const name of [
      "DfirTimelineView", // an IIFE-wrapped namespace, published as `window.DfirTimelineView`
      "initCustodyButtons", // a bare top-level function declaration
      "initSwimlane",
      "initTicketIntegrations",
      "kevImportUrl",
      "loadCaseBackups",
    ]) {
      expect([...owners.keys()], `${name} is published by a module but was not harvested`).toContain(name);
    }
  });

  // Two modules publishing one name is a silent last-tag-wins overwrite, and it would also make
  // "is this name guarded" ambiguous to answer. There are none today; this is what keeps it so.
  it("has no two modules publishing the same global", () => {
    const clashes = [...owners]
      .filter(([, files]) => files.length > 1)
      .map(([name, files]) => `${name}: ${files.join(" + ")}`);
    expect(
      clashes,
      "the later <script> tag silently wins and the earlier module's version is simply gone",
    ).toEqual([]);
  });

  it("guards every top-level reference to a name only a module declares", () => {
    const names = new Set(owners.keys());
    const bad = inline.flatMap((s) =>
      unguardedTopLevelRefs(s, names).map(
        (r) => `${s.name}:${r.line} ${r.name} (${owners.get(r.name)?.join(", ") ?? "?"})`,
      ),
    );
    expect(
      bad,
      "each of these is evaluated while the page is loading, with nothing establishing that the " +
        "name resolves. If that module 404s the reference throws a ReferenceError and THE REST OF " +
        "THE INLINE SCRIPT NEVER RUNS — case restoration, the WebSocket, every listener after this " +
        'point. Wrap the site in `if (typeof NAME !== "undefined")`, and where the analyst would ' +
        "otherwise meet a dead control say so with dfirFeatureUnavailable() rather than skipping " +
        "it in silence.",
    ).toEqual([]);
  });

  // THE ORDER, WHICH A GUARD ALONE DOES NOT FIX. render() is the page's ONLY writer of
  // DfirState.lastState, and a dozen refresh paths are `if (DfirState.lastState())
  // render(DfirState.lastState())` — every one of them is a silent no-op until that write has
  // happened once. So nothing that can throw may run ahead of it, guarded or not: a guard a later
  // edit drops puts the page straight back where it was. Asserted as the general rule rather than
  // about one name, because the next call inserted there will have a different one.
  it("writes the case state before render() calls anything at all", () => {
    const render = inline.flatMap(functionsOf).find((f) => f.declaration && f.name === "render");
    expect(render, "no render() declaration in the inline script").toBeDefined();
    const calls = callsAfter(render!.node, 0).sort((a, b) => a.pos - b.pos);
    const save = calls.find((c) => c.name === "setLastState");
    expect(save, "render() no longer writes DfirState.setLastState").toBeDefined();
    expect(
      calls.filter((c) => c.pos < save!.pos).map((c) => c.name),
      "a call runs ahead of the state save — if it throws, lastState stays null and every " +
        "`if (DfirState.lastState()) render(...)` refresh in the page is dead for the session",
    ).toEqual([]);
  });

  it("says so on screen rather than failing silently", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toMatch(/function dfirFeatureUnavailable\(/);
    // A missing feature must be distinguishable from a feature with nothing to show.
    expect(html).toMatch(/featureWarnings/);
    // Painted is not announced: role="alert" is what makes a screen reader read the chip out.
    expect(html).toMatch(/box\.setAttribute\("role", "alert"\)/);
    // And once per feature — the Case-backups guard fires on every click of a live button.
    expect(html).toMatch(/if \(warned\.has\(label\)\) return;/);
    // THE DEDUPE STATE MAY NOT BE A TOP-LEVEL `const`. It was, and Chromium proved what that costs:
    // the earliest caller is the Timeline-filters guard 8,137 lines ABOVE the declaration, so the
    // read happened inside the `const`'s temporal dead zone and threw AFTER the console line and
    // BEFORE the chip — the page logged the missing feature and then died of the very top-level
    // abort this entire guard exists to prevent, taking ~16,200 lines of wiring with it.
    expect(html).not.toMatch(/const dfirFeaturesWarned\b/);
  });
});

// ── THE TWO THINGS THAT DELIBERATELY DID NOT MOVE ────────────────────────────────────────────────
describe("what stayed behind, on purpose", () => {
  // `sessionsCollapsed` lives inside the sessions block but the timeline header's collapse-all
  // control reads it, so it is shared state, not this feature's. Taking it would have broken that
  // control silently — the census that drove this tier did not see the reference, because it counts
  // calls between top-level functions and that one is a listener.
  it("leaves sessionsCollapsed in the page, where its other reader is", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toMatch(/let sessionsCollapsed = false;/);
    // Asserted against CODE, not the file text: this module's own header explains why
    // sessionsCollapsed stayed behind, and a raw substring check trips over that explanation —
    // which is the sixth time in this issue that a mechanical check has caught its own prose.
    const code = (await read("dashboard-sessions.js"))
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"))
      .join("\n");
    expect(code).not.toContain("sessionsCollapsed");
  });

  // THE PAGE MUST REALLY CALL IT, and the module must really defer its DOM work.
  //
  // The first version checked that the HTML CONTAINED the text "initTicketIntegrations();" and that
  // an indentation-sensitive regex found no `const x = document.` — and review walked past both:
  // commenting the call out left the text present (a comment satisfying a check on prose, for the
  // eighth time in this issue), and moving a listener into the module with
  // `window.document?.getElementById(...)` slipped the regex while dying at browser load. Both
  // questions are structural, so both are asked of the AST.
  it("is called from the page as a real call, not a comment", () => {
    const inline = dashboardScripts().filter((s) => s.name.startsWith("dashboard.html#inline"));
    const called = inline.some((s) => callsByName(s, "initTicketIntegrations"));
    expect(called, "no CALL to initTicketIntegrations in the page — a comment does not count").toBe(true);
  });

  it("touches no DOM outside a function", async () => {
    const module = scriptFromSource("dashboard-tickets.js", await read("dashboard-tickets.js"));
    const offenders = domAccessOutsideFunctions(module);
    expect(
      offenders,
      "a DOM read at module scope runs before the markup exists — the captures would be null and " +
        "the listeners would attach to nothing, with no error anywhere",
    ).toEqual([]);
  });

  // initCustodyButtons ran at its old position in the inline script, AFTER the custody markup.
  // These modules are <head> scripts, so auto-running it would query for buttons that do not exist
  // yet and wire nothing at all — a feature that silently stops working, with no error.
  it("calls initCustodyButtons from the page rather than on module load", async () => {
    const src = await read("dashboard-custody.js");
    expect(src, "an auto-running IIFE would fire before the markup exists").not.toMatch(
      /\(function initCustodyButtons/,
    );
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain("initCustodyButtons();");
  });
});
