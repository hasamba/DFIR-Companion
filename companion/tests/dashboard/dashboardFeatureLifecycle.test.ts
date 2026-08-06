import ts from "typescript";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { runInContext } from "node:vm";
import { describe, expect, it } from "vitest";
import {
  callsAfter,
  dashboardScripts,
  domAccessOutsideFunctions,
  functionsOf,
  loadTimeCallsTo,
  moduleGlobals,
  scriptFromSource,
  unguardedTopLevelRefs,
} from "../helpers/dashboardAst.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { DASHBOARD, FEATURES, globalsOf, NON_FEATURES, read, scripts } from "./featureManifest.js";

// LIFECYCLE: when each feature's code runs, and what happens when its file does not arrive.
// Split out of dashboardFeatureModules.test.ts at the repo's 800-line limit (#415).

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

describe("what stayed behind, on purpose", () => {
  // `sessionsCollapsed` used to live in the page, and this test used to assert that it stayed —
  // on the reasoning that "the collapse-all control reads it, so it is shared state". Re-reading
  // that control is what overturned it: it toggles .ses-collapsed on #sec-sessions and relabels
  // its own button, and nothing else touches the flag. It read as shared only because it sits in
  // the page's delegated-click block, forty features deep. An element's address is not its owner.
  it("keeps sessionsCollapsed with the feature whose control is its only reader", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html, "the page still declares it").not.toMatch(/let sessionsCollapsed = false/);
    expect(html, "the page asks for the operation instead").toContain("toggleSessionsCollapse(e.target)");
    // Asserted against CODE, not file text: a comment naming the binding would satisfy a raw
    // substring search, which is the sixth time in this issue a mention has passed for a use.
    const code = (await read("dashboard-sessions.js"))
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"))
      .join("\n");
    expect(code).toContain("let sessionsCollapsed = false");
    expect(code, "and it stays private — only the operation is published").not.toContain(
      "window.sessionsCollapsed",
    );
  });

  // THE PAGE MUST REALLY CALL IT, and the module must really defer its DOM work.
  //
  // The first version checked that the HTML CONTAINED the text "initTicketIntegrations();" and that
  // an indentation-sensitive regex found no `const x = document.` — and review walked past both:
  // commenting the call out left the text present (a comment satisfying a check on prose, for the
  // eighth time in this issue), and moving a listener into the module with
  // `window.document?.getElementById(...)` slipped the regex while dying at browser load. Both
  // questions are structural, so both are asked of the AST.
  // ONE FEATURE OF TEN ran these. They were written for dashboard-tickets.js and hardcoded to it,
  // so the other nine were named in the manifest and never actually examined. Nothing in either is
  // ticket-specific. The reachability version of the call check that used to sit here is gone — see
  // "calls %s exactly once, at load" below for why callsByName() was the wrong question.

  it.each(FEATURES.map((f) => f.file))("%s touches no DOM outside a function", async (file) => {
    const module = scriptFromSource(file, await read(file));
    const offenders = domAccessOutsideFunctions(module);
    expect(
      offenders,
      "a DOM read at module scope runs before the markup exists — the captures would be null and " +
        "the listeners would attach to nothing, with no error anywhere",
    ).toEqual([]);
  });

  // AND NO INITIALIZER AUTO-RUNS. Every one of these is a <head> script, so a module that invoked
  // its own initializer would query for markup that does not exist yet and wire nothing — a feature
  // that silently stops working, with no error.
  //
  // ASKED OF THE AST. This was two regexes over the file's text, and review walked through both:
  // `if (typeof document !== "undefined") (initCustodyButtons)();` self-runs in a real browser and
  // matched neither, and `.call(...)` was a second spelling past them. The inverse failed too — a
  // COMMENT containing `(function initCustodyButtons() {})()` failed the suite for no reason, which
  // is the ninth time in this issue a check on prose has tripped over prose.
  it.each(FEATURES.filter((f) => f.initializer).map((f) => [f.file, f.initializer!] as const))(
    "%s does not auto-run %s on load",
    async (file, initializer) => {
      const module = scriptFromSource(file, await read(file));
      expect(
        loadTimeCallsTo(module, initializer),
        "the module calls its own initializer at load, before the markup it wires exists",
      ).toEqual([]);
    },
  );

  // THE PAGE MUST CALL IT AT LOAD, EXACTLY ONCE.
  //
  // callsByName() answers "is this reachable", which is a different question and the wrong one:
  // review moved the swimlane's call under `addEventListener("dfir-never", …)` and the gate stayed
  // green while the chart never initialised. It also passed a SECOND guarded call, and these
  // initializers are not idempotent — custody and the swimlane stack listeners, and the swimlane
  // stacks a ResizeObserver.
  it.each(FEATURES.filter((f) => f.initializer).map((f) => [f.file, f.initializer!] as const))(
    "%s: the page calls %s exactly once, at load",
    (_file, initializer) => {
      const inline = dashboardScripts().filter((s) => s.name.startsWith("dashboard.html#inline"));
      const sites = inline.flatMap((s) => loadTimeCallsTo(s, initializer).map((l) => `${s.name}:${l}`));
      expect(
        sites,
        "not called on a path that runs at load — a listener, a dead function or a comment does not " +
          "initialise the feature; two calls stack its listeners",
      ).toHaveLength(1);
    },
  );

  // THE MANIFEST MUST NOT BE THE SOURCE OF TRUTH FOR WHAT EXISTS.
  //
  // Every check above keys on the manifest, so a feature MISSING from it is not checked at all —
  // review deleted the Backup row plus added a real defect and the suite went green on 115 tests.
  // Comparing manifest names against names found in the page does not fix that: both sides can omit
  // the same feature and agree. So the expected set comes from the PAGE'S SCRIPT TAGS, which is the
  // one place a shipped feature cannot hide, and every dashboard-*.js it loads must be classified.
  it("classifies every dashboard module the page loads", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const loaded = [...html.matchAll(/<script[^>]*\ssrc="\/js\/(dashboard-[^"]+)"/g)].map((m) => m[1]);
    expect(loaded.length, "no dashboard-*.js tags found — this check would pass vacuously").toBeGreaterThan(
      10,
    );
    const unclassified = loaded.filter((f) => !FEATURES.some((x) => x.file === f) && !NON_FEATURES.has(f));
    expect(
      unclassified,
      "a dashboard module the page loads is in neither FEATURES nor NON_FEATURES, so nothing in " +
        "this file examines it — add it to one",
    ).toEqual([]);
  });

  // AND EVERY INITIALIZER THE PAGE GUARDS BELONGS TO THE MODULE THAT PUBLISHES IT. Review moved
  // initCustodyButtons's metadata onto the Anomalies row and all 124 tests passed, because the old
  // check compared two deduplicated NAME sets and never asked which file owns which name.
  it("attributes every initializer to the module that actually publishes it", () => {
    const owners = moduleGlobals(scripts);
    for (const feat of FEATURES.filter((f) => f.initializer)) {
      expect(
        owners.get(feat.initializer!) ?? [],
        `${feat.initializer} is declared on the ${feat.file} row but that module does not publish it`,
      ).toContain(`js/${feat.file}`);
    }
  });
});

// ── RUNNING initMcp() ────────────────────────────────────────────────────────────────────────────
//
// Review of the extraction PR found the gap this closes: initMcp() installs thirteen handlers, and
// the committed checks only proved the function EXISTS and is CALLED once. Deleting the server
// select, the agent run and the manual run handlers passed all 215 relevant tests — the same
// failure mode #479 records for the swimlane, one feature later.
//
// A threshold would not have caught it either. `listeners.length > 8` cannot tell "all thirteen"
// from "any nine", and reads a duplicate registration as more evidence of success. So every control
// is named.
describe("initMcp", () => {
  // id -> the property MCP wires it through. Written out rather than derived from the module,
  // because a list derived from the thing it checks agrees with it by construction.
  const CONTROLS: Array<[string, string]> = [
    ["mcpRunServer", "onchange"],
    ["mcpRunTool", "onchange"],
    ["mcpRunListToolsBtn", "onclick"],
    ["mcpRunArgs", "oninput"],
    ["mcpRunBrowseBtn", "onclick"],
    ["mcpRunFile", "onchange"],
    ["mcpRunTarget", "oninput"],
    ["mcpAgentBtn", "onclick"],
    ["mcpRunBtn", "onclick"],
    ["mcpPreviewImportBtn", "onclick"],
    ["mcpPreviewDiscardBtn", "onclick"],
    ["mcpRunCancelBtn", "onclick"],
    ["mcpRunRetryBtn", "onclick"],
  ];

  function fixture() {
    const wired: string[] = [];
    const els = new Map<string, Record<string, unknown>>();
    const el = (id: string): Record<string, unknown> => {
      if (!els.has(id)) {
        const node: Record<string, unknown> = {
          id,
          value: "",
          textContent: "",
          innerHTML: "",
          disabled: false,
          hidden: false,
          dataset: {},
          style: {},
          options: [],
          files: [],
          classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
          appendChild() {},
          querySelector: () => null,
          querySelectorAll: () => [],
          addEventListener: (type: string) => wired.push(`${id}:${type}`),
        };
        // MCP wires with `el.onclick = …` / `.onchange =` / `.oninput =`, not addEventListener.
        for (const prop of ["onclick", "onchange", "oninput"]) {
          Object.defineProperty(node, prop, {
            set(fn: unknown) {
              if (typeof fn === "function") wired.push(`${id}:${prop}`);
            },
            get: () => undefined,
            configurable: true,
          });
        }
        els.set(id, node);
      }
      return els.get(id) as Record<string, unknown>;
    };
    const doc = {
      getElementById: (id: string) => el(id),
      createElement: () => el("<created>"),
      querySelector: () => null,
      querySelectorAll: () => [],
      addEventListener() {},
    };
    return { wired, doc };
  }

  it("wires every control it owns, named one by one", () => {
    const { wired, doc } = fixture();
    const api = loadDashboardModule<{ initMcp: () => void }>("dashboard-mcp.js", [], {
      document: doc,
      fetch: () => new Promise(() => {}),
      setTimeout: () => 0,
    });
    api.initMcp();
    for (const [id, prop] of CONTROLS) {
      expect(
        wired,
        `${id} lost its ${prop} handler — the control is dead and nothing else says so`,
      ).toContain(`${id}:${prop}`);
    }
  });

  it("wires nothing before the page calls it", () => {
    // The module is a <head> script: anything it wired at load would be querying markup that does
    // not exist yet and binding to nothing, silently.
    const { wired, doc } = fixture();
    loadDashboardModule("dashboard-mcp.js", [], {
      document: doc,
      fetch: () => new Promise(() => {}),
      setTimeout: () => 0,
    });
    expect(wired, "the module wired controls at load, before #sec-mcp exists").toEqual([]);
  });
});

// ── THE TAX EVERY EXTRACTION PAYS, AND NOBODY ENFORCED ───────────────────────────────────────────
//
// Moving a feature out creates names the page calls BARE — `scheduleBeaconsReload()` sits in the
// middle of the load-time refresh chain — and a ReferenceError there takes every later call in the
// same statement with it. js/dashboard-facade.js exists to stop that, by stubbing those names when
// their file is absent.
//
// Nothing checked that an extraction actually updated it. This was found the only way it could be:
// blocking the new module in a browser and noticing the page said nothing. Four panels went dark
// silently, and the refresh chain past them would have died on the next case load.
//
// So: every name a feature module publishes and the page then calls WITHOUT a typeof guard must be
// in the facade's list. Guarded names are exempt — a guard is the other correct answer, and is what
// the initializers use so they can report.
describe("every module name the page calls bare is stubbed by the facade", () => {
  const facadeSrc = readFileSync(new URL("../../../public/js/dashboard-facade.js", import.meta.url), "utf8");
  const stubbed = new Set([...facadeSrc.matchAll(/^\s*"([A-Za-z_$][\w$]*)",/gm)].map((m) => m[1]));

  it("harvests the facade's list", () => {
    expect(stubbed.size, "no stubbed names parsed — this check would pass vacuously").toBeGreaterThan(15);
    expect(stubbed, "the list this check is built on lost a known member").toContain(
      "scheduleSwimlaneReload",
    );
  });

  it("covers every feature name in the load-time refresh fan-out", () => {
    // THE FAN-OUT IS THE HAZARD, and it is checked directly rather than approximated.
    //
    // Two statements in the page call ~20 refreshes in a row — once on case restore, once in the
    // WebSocket "state" handler. A ReferenceError at any one of them takes every LATER call in the
    // same statement with it, which is the bug #475 fixed and the reason the facade exists.
    //
    // Not "every unguarded reference": a name reached from a click handler throws into that one
    // interaction and is contained, which is the documented design, and there are eleven such names
    // today. Not unguardedTopLevelRefs() either — the first version of this check used it and
    // passed the mutation it was written for, because these calls sit one hop inside a handler,
    // which is the blind spot #476 records. A chain is identifiable on its own terms: a single
    // statement making three or more …Reload() calls.
    const inline = scripts.filter((s) => s.name.startsWith("dashboard.html#inline"));
    const inChains = new Set<string>();
    for (const s of inline) {
      const visit = (n: ts.Node): void => {
        if (ts.isExpressionStatement(n) || ts.isBlock(n)) {
          const calls = [...n.getText(s.ast).matchAll(/\b([a-zA-Z_$][\w$]*)\s*\(/g)].map((m) => m[1]);
          const reloads = calls.filter((c) => /Reload$/.test(c));
          if (reloads.length >= 3) for (const c of calls) inChains.add(c);
        }
        ts.forEachChild(n, visit);
      };
      ts.forEachChild(s.ast, visit);
    }
    expect(inChains.size, "no refresh fan-out found — this check would pass vacuously").toBeGreaterThan(10);

    // A STUB IS NOT THE ONLY CORRECT ANSWER. A typeof guard at the call site is the other one, and
    // is what verifyCustodyOnOpen uses — deliberately, so a missing custody module never blocks a
    // case connect. Either satisfies this; having neither is the bug.
    const published = new Set(FEATURES.flatMap((f) => f.publish));
    const guarded = new Set(
      inline.flatMap((s) =>
        [...s.source.matchAll(/typeof\s+([A-Za-z_$][\w$]*)\s*===\s*"function"/g)].map((m) => m[1]),
      ),
    );
    const uncovered = [...inChains]
      .filter((n) => published.has(n) && !stubbed.has(n) && !guarded.has(n))
      .sort();
    expect(
      uncovered,
      "these feature names sit in a load-time refresh chain and the facade does not stub them — one " +
        "missing module ends the chain, and every refresh after it is silently skipped. Add them to " +
        "STUBBED in js/dashboard-facade.js",
    ).toEqual([]);
  });
});
