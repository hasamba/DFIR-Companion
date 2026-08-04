import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { runInContext } from "node:vm";
import {
  callsByName,
  dashboardScripts,
  domAccessOutsideFunctions,
  functionsOf,
  scriptFromSource,
  topLevelBindings,
  unguardedCalls,
} from "../helpers/dashboardAst.js";
import { globalsAddedBy, loadDashboardModule } from "../helpers/dashboardModule.js";

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
  Object.keys(api).filter((k) => !SANDBOX_FURNITURE.has(k) && !seeded.includes(k));

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

  /** Enough of a browser for the initializer to wire itself up, and a counter for what it fetched. */
  function fixture() {
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
    const document = {
      getElementById: el,
      querySelector: () => null,
      querySelectorAll: () => [],
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

  it("actually wires the overlays and asks the server what is configured", () => {
    const { api, fx } = load();
    (api[feat.initializer!] as () => void)();
    expect(fx.fetched.length, "no status request — the Push menu would never populate").toBeGreaterThan(4);
    expect(fx.listeners.length, "no listener registered — every control would be dead").toBeGreaterThan(4);
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

  // The entry points called where a throw would abort the rest of the script, rather than from
  // inside a handler where it is contained to that one interaction.
  const ENTRY_POINTS = ["initTicketIntegrations", "initCustodyButtons", "verifyCustodyOnOpen"];

  it.each(ENTRY_POINTS)("guards every tier-3 entry point: %s", (name) => {
    const bad = inline.flatMap((s) => unguardedCalls(s, name).map((line) => `${s.name}:${line}`));
    expect(
      bad,
      `${name}() is called without a typeof guard — if its script 404s this throws and takes the ` +
        "rest of the inline script with it",
    ).toEqual([]);
  });

  it("says so on screen rather than failing silently", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toMatch(/function dfirFeatureUnavailable\(/);
    // A missing feature must be distinguishable from a feature with nothing to show.
    expect(html).toMatch(/featureWarnings/);
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
