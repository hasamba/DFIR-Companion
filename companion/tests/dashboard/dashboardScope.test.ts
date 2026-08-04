import { readFile } from "node:fs/promises";
import { runInContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { projectScope as serverProjectScope } from "../../src/analysis/scopeProject.js";
import { NO_SCOPE, type ScopeWindow } from "../../src/analysis/scope.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { ScopeApi } from "./dashboardApi.js";
import {
  dashboardScripts,
  functionsOf,
  getterMutations,
  setterRefs,
  topLevelBindings,
} from "../helpers/dashboardAst.js";
import { globalsAddedBy, loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-scope.js — the first TIER 2 cell to move (#415).
//
// Tier 1 was a cache with one writer each, and its gate is a call-site count. This one is not that
// shape and the gate cannot be that gate: the investigation window has THREE legitimate writers,
// because it is server-persisted state that arrives by three routes (case-load GET, the analyst's
// POST, another client's websocket broadcast) and each route refreshes something different.
//
// So the enforceable rule here is not "how many" but "WHICH". The allowlist below is the design
// decision written down where CI can see it: a fourth writer, or one of these three moving to
// another function, is a change to who owns the window and has to be argued for rather than
// noticed later.
//
// The other reason this file exists is parity. src/analysis/scopeProject.ts is the same projection
// written a second time, and the inline copy called itself "the client-side mirror" of it for as
// long as it sat in dashboard.html, where nothing could execute it. Now something can.

const MODULE = new URL("../../../public/js/dashboard-scope.js", import.meta.url);
const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

/** A stand-in for the three elements the module writes. */
function stubDom() {
  const els: Record<string, { value: string; textContent: string; style: { color: string } }> = {
    scopeStart: { value: "", textContent: "", style: { color: "" } },
    scopeEnd: { value: "", textContent: "", style: { color: "" } },
    scopeInfo: { value: "", textContent: "", style: { color: "" } },
  };
  return { els, document: { getElementById: (id: string) => els[id] ?? null } };
}

/**
 * The module as the browser loads it: after dashboard-state.js, whose cell() it builds on at load
 * time, and after dashboard-time.js, whose isoToUtcInput() it calls.
 */
function loadScopeModule(dom = stubDom()) {
  const api = loadDashboardModule<ScopeApi>(
    "dashboard-scope.js",
    ["dashboard-state.js", "dashboard-time.js"],
    { document: dom.document },
  );
  return { api, dom };
}

describe("the window itself", () => {
  it("starts empty, meaning every event is in scope", () => {
    const { api } = loadScopeModule();
    expect(api.DfirScope.get()).toEqual({ start: null, end: null });
    expect(api.DfirScope.isEmpty()).toBe(true);
  });

  // The difference from tier 1, and a deliberate one. dashboard-state.js hands back the live
  // snapshot and argues that deep-freezing a whole case state per fetch is not free. A two-field
  // object written three times is a different trade, so the hazard tier 1 documented is closed.
  it("hands back a frozen window, so a reader cannot edit it in place", () => {
    const { api } = loadScopeModule();
    api.DfirScope.confirm("2026-05-20T00:00:00.000Z", null);
    const w = api.DfirScope.get();
    expect(Object.isFrozen(w)).toBe(true);
    try {
      (w as { start: string | null }).start = "tampered";
    } catch {
      // A strict-mode realm throws; a sloppy one silently no-ops. Either is a rejected write.
    }
    expect(api.DfirScope.get().start).toBe("2026-05-20T00:00:00.000Z");
  });

  it("normalises every falsy bound to null", () => {
    const { api } = loadScopeModule();
    // The three former call sites spelled this two ways — `s.start || null` and `msg.start ?? null`.
    // They differ only for "", which the server's norm() turns into null before sending.
    api.DfirScope.confirm("", undefined);
    expect(api.DfirScope.get()).toEqual({ start: null, end: null });
  });
});

describe("contains", () => {
  const withWindow = () => {
    const { api } = loadScopeModule();
    api.DfirScope.confirm("2026-05-15T00:00:00Z", "2026-05-25T00:00:00Z");
    return api.DfirScope;
  };

  it("keeps everything when no window is set", () => {
    const { api } = loadScopeModule();
    expect(api.DfirScope.contains("1999-01-01T00:00:00Z")).toBe(true);
  });

  it("excludes timestamps outside the bounds and keeps the ones inside", () => {
    const s = withWindow();
    expect(s.contains("2026-05-10T00:00:00Z")).toBe(false);
    expect(s.contains("2026-05-20T00:00:00Z")).toBe(true);
    expect(s.contains("2026-05-30T00:00:00Z")).toBe(false);
  });

  // The rule that matters for real evidence: plenty of forensic artefacts have no usable timestamp,
  // and dropping them from a scoped view would hide evidence rather than narrow it.
  it("keeps an undated event, because it cannot be proven out of scope", () => {
    const s = withWindow();
    expect(s.contains("not-a-date")).toBe(true);
    expect(s.contains("")).toBe(true);
  });
});

// ── PARITY ───────────────────────────────────────────────────────────────────────────────────────
//
// The client projection and src/analysis/scopeProject.ts are the same rule written twice. This runs
// the REAL server function — imported, not re-implemented — against the browser module loaded in a
// vm, over the same inputs. Re-implementing the server's rule here is exactly the mistake this
// issue already corrected once, for the false-positive filter.
describe("the client projection matches the server's", () => {
  function fixture(): InvestigationState {
    return {
      ...emptyState("c1"),
      forensicTimeline: [
        {
          id: "e1",
          timestamp: "2026-05-20T09:00:00Z",
          description: "early phish",
          severity: "High",
          mitreTechniques: ["T1566"],
          relatedFindingIds: ["f1"],
          sourceScreenshots: [],
        },
        {
          id: "e2",
          timestamp: "2026-05-25T12:00:00Z",
          description: "in-window exec",
          severity: "Critical",
          mitreTechniques: ["T1059"],
          relatedFindingIds: ["f2"],
          sourceScreenshots: [],
        },
        {
          id: "e3",
          timestamp: "not-a-date",
          description: "undated artefact",
          severity: "Medium",
          mitreTechniques: [],
          relatedFindingIds: [],
          sourceScreenshots: [],
        },
      ],
      findings: [
        {
          id: "f1",
          severity: "High",
          title: "phishing",
          description: "out of window",
          relatedIocs: ["i001"],
          mitreTechniques: ["T1566"],
          sourceScreenshots: [],
          firstSeen: "",
          lastUpdated: "",
          status: "open",
        },
        {
          id: "f2",
          severity: "Critical",
          title: "execution",
          description: "in window",
          relatedIocs: ["i002"],
          mitreTechniques: ["T1059"],
          sourceScreenshots: [],
          firstSeen: "",
          lastUpdated: "",
          status: "confirmed",
        },
        {
          id: "f3",
          severity: "Low",
          title: "unbacked",
          description: "no event backs it",
          relatedIocs: [],
          mitreTechniques: [],
          sourceScreenshots: [],
          firstSeen: "",
          lastUpdated: "",
          status: "open",
        },
      ],
      iocs: [
        { id: "i001", type: "file", value: "phish.docx", firstSeen: "" },
        { id: "i002", type: "process", value: "powershell.exe", firstSeen: "" },
        { id: "i003", type: "ip", value: "10.0.0.9", firstSeen: "" },
      ],
      mitreTechniques: [
        { id: "T1566", name: "Phishing", findingIds: ["f1"] },
        { id: "T1059", name: "Command and Scripting Interpreter", findingIds: ["f2"] },
        { id: "T1005", name: "Data from Local System", findingIds: [] },
      ],
    };
  }

  // Every shape that exercises a different branch, including the two degenerate ones.
  const WINDOWS: Array<[string, ScopeWindow]> = [
    ["no window", NO_SCOPE],
    ["lower bound only", { start: "2026-05-22T00:00:00Z", end: null }],
    ["upper bound only", { start: null, end: "2026-05-22T00:00:00Z" }],
    ["both bounds", { start: "2026-05-19T00:00:00Z", end: "2026-05-26T00:00:00Z" }],
    ["inverted, so nothing is in scope", { start: "2026-05-26T00:00:00Z", end: "2026-05-19T00:00:00Z" }],
    ["an unparseable bound", { start: "garbage", end: null }],
  ];

  it.each(WINDOWS)("agrees with the server: %s", (_label, window) => {
    const { api } = loadScopeModule();
    api.DfirScope.confirm(window.start, window.end);
    const client = api.DfirScope.project(fixture());
    const server = serverProjectScope(fixture(), window);
    expect(client).toEqual(server);
  });

  it("returns the very same object when no window is set, as the server does", () => {
    const { api } = loadScopeModule();
    const state = fixture();
    expect(api.DfirScope.project(state)).toBe(state);
    const s = fixture();
    expect(serverProjectScope(s, NO_SCOPE)).toBe(s);
  });

  it("does not mutate the state it is given", () => {
    const { api } = loadScopeModule();
    const state = fixture();
    api.DfirScope.confirm("2026-05-22T00:00:00Z", null);
    api.DfirScope.project(state);
    expect(state.findings).toHaveLength(3);
    expect(state.iocs).toHaveLength(3);
    expect(state.mitreTechniques[0].findingIds).toEqual(["f1"]);
  });
});

// ── THE TWO COMMIT SHAPES ────────────────────────────────────────────────────────────────────────
//
// receive/confirm exist because the three writers disagree about the two <input> controls, and that
// disagreement is not incidental: on the POST path the controls are where the window came FROM, so
// writing them back would overwrite what the analyst typed with a round-tripped copy of it.
describe("receive and confirm differ exactly where the call sites did", () => {
  it("receive pushes the window into the two controls", () => {
    const { api, dom } = loadScopeModule();
    api.DfirScope.receive("2026-05-20T08:30:00.000Z", "2026-05-21T00:00:00.000Z");
    expect(dom.els.scopeStart.value).toBe("2026-05-20T08:30");
    expect(dom.els.scopeEnd.value).toBe("2026-05-21T00:00");
  });

  // THE CONTROL VALUES MUST NOT BE THE ROUND-TRIP OF THE COMMITTED WINDOW. The first version of
  // this test pre-set them to "2026-05-20T08:30" and committed that same instant, so a confirm()
  // that DID write the controls wrote back the identical string and the test still passed. It was
  // asserting "the value is right" while claiming to assert "nothing wrote it". Mutation testing
  // caught it; the sentinel is what makes the two distinguishable.
  it("confirm leaves the controls exactly as the analyst left them", () => {
    const { api, dom } = loadScopeModule();
    dom.els.scopeStart.value = "TYPED-BY-THE-ANALYST";
    dom.els.scopeEnd.value = "ALSO-UNTOUCHED";
    api.DfirScope.confirm("2026-05-20T08:30:00.000Z", "2026-05-21T00:00:00.000Z");
    expect(dom.els.scopeStart.value).toBe("TYPED-BY-THE-ANALYST");
    expect(dom.els.scopeEnd.value).toBe("ALSO-UNTOUCHED");
  });

  // The reason renderScopeInfo() moved in rather than staying a function the writers must remember
  // to call: an owner that can be written without repainting its own indicator is a bug waiting to
  // be written, and its three former call sites were exactly these three writers.
  it.each(["receive", "confirm"] as const)("%s repaints the indicator as part of committing", (op) => {
    const { api, dom } = loadScopeModule();
    api.DfirScope[op]("2026-05-20T00:00:00.000Z", null);
    expect(dom.els.scopeInfo.textContent).toContain("active:");
    expect(dom.els.scopeInfo.style.color).toBe("#ffd93b");

    api.DfirScope[op](null, null);
    expect(dom.els.scopeInfo.textContent).toBe("none (all events)");
    expect(dom.els.scopeInfo.style.color).toBe("#9aa4b2");
  });
});

// ── THE GATE ─────────────────────────────────────────────────────────────────────────────────────
describe("who may write the window", () => {
  const scripts = dashboardScripts();

  // THE ALLOWLIST. Not a count — a count would let a writer move from applyScope into some other
  // function without anyone noticing, and "which function owns this write" is the whole question
  // for a cell with more than one writer.
  const WRITERS = [
    { op: "receive", owner: "loadScope", why: "the case-load GET" },
    { op: "receive", owner: "proceedConnect", why: "another client's scope_changed broadcast" },
    { op: "confirm", owner: "applyScope", why: "this analyst's POST" },
  ] as const;

  it.each(["receive", "confirm"] as const)(
    "%s is only ever called directly, never stashed or reached dynamically",
    (op) => {
      const refs = setterRefs(scripts, op, "DfirScope");
      expect(refs.length, `DfirScope.${op} is never called`).toBeGreaterThan(0);
      const bad = refs.filter((r) => r.form !== "direct-call");
      expect(
        bad,
        `a reference this analysis cannot follow defeats the allowlist below; found ` +
          bad.map((r) => `${r.script}:${r.line} (${r.form})`).join(", "),
      ).toEqual([]);
    },
  );

  it("is written from exactly the three functions that own a refresh path", () => {
    const found = (["receive", "confirm"] as const).flatMap((op) =>
      setterRefs(scripts, op, "DfirScope").map((ref) => {
        const script = scripts.find((s) => s.name === ref.script)!;
        const owner = functionsOf(script)
          .filter((f) => {
            const end = script.ast.getLineAndCharacterOfPosition(f.node.getEnd()).line + 1;
            return f.line <= ref.line && end >= ref.line;
          })
          // The innermost named function: these writes sit inside .then()/onmessage callbacks.
          .map((f) => f.name)
          .filter((n) => !n.startsWith("<"))
          .pop();
        return `${op} <- ${owner}`;
      }),
    );
    expect(
      found.sort(),
      "the investigation window has three writers by design, one per refresh path " +
        "(see js/dashboard-scope.js). A new one changes who owns the window.",
    ).toEqual(WRITERS.map((w) => `${w.op} <- ${w.owner}`).sort());
  });

  // The binding is GONE, not merely wrapped. While a top-level `scope` still existed every gate
  // above could pass with the old variable still being read.
  //
  // Asked of the AST, not of the text. The first version of this was
  // `expect(html).not.toMatch(/^\s*let scope = \{/m)` — one spelling of one initialiser. `let scope
  // = null`, `let scope;`, `const scope = …` and `var scope` all passed it, and any of them is the
  // second source of truth this migration exists to remove.
  it("leaves no top-level `scope` binding behind, in any spelling", () => {
    const offenders = scripts
      .filter((s) => s.name.startsWith("dashboard.html#inline"))
      .flatMap((s) =>
        topLevelBindings(s)
          .filter((b) => b.name === "scope")
          .map((b) => `${s.name}:${b.line}`),
      );
    expect(
      offenders,
      "the investigation window is owned by js/dashboard-scope.js; a top-level `scope` in the page " +
        "is a second source of truth regardless of how it is declared",
    ).toEqual([]);
  });

  it("leaves none of the moved functions behind", () => {
    const moved = new Set(["inScope", "projectScope", "renderScopeInfo"]);
    const offenders = scripts
      .filter((s) => s.name.startsWith("dashboard.html#inline"))
      .flatMap((s) =>
        functionsOf(s)
          .filter((f) => moved.has(f.name))
          .map((f) => `${s.name}:${f.line} ${f.name}`),
      );
    expect(offenders).toEqual([]);
  });

  // THE OTHER HALF OF FREEZING. Object.freeze stops the state being corrupted; it does NOT stop the
  // code being written, because a classic script is not strict mode and the assignment silently
  // no-ops. That is a caller whose intent vanished, every later read returning the old value, and a
  // green CI — strictly worse than the throw a strict realm would have raised. The module's header
  // claims this gate exists, so it had better.
  it("never writes through get() to the window it returned", () => {
    const offenders = getterMutations(scripts, "DfirScope", "get").map(
      (m) => `${m.script}:${m.line} (${m.form}) ${m.text}`,
    );
    expect(
      offenders,
      "DfirScope.get() returns a frozen window; assigning to it silently does nothing in a " +
        "non-strict classic script. Commit through receive()/confirm() instead.",
    ).toEqual([]);
  });
});

describe("nothing but the namespace escapes", () => {
  it("adds only DfirScope to the global object", () => {
    // Baselined after its dependencies have run, so this is what THIS file added and nothing else.
    expect(globalsAddedBy("dashboard-scope.js", ["dashboard-state.js", "dashboard-time.js"])).toEqual([
      "DfirScope",
    ]);
  });

  // The lexical half, invisible to globalsAddedBy: a top-level `const` in a classic script joins
  // the shared lexical environment and is writable by name from any later script. This is the hole
  // that made the tier-1 single-writer gate decorative until dashboard-state.js grew its IIFE.
  it("puts the cell out of reach of a second script on the page", () => {
    const { api } = loadScopeModule();
    api.DfirScope.confirm("2026-05-20T00:00:00.000Z", null);
    expect(() => runInContext("dfirScope.set({ start: 'smuggled', end: null })", api as object)).toThrow(
      /dfirScope is not defined/,
    );
    expect(() => runInContext("commit('smuggled', null)", api as object)).toThrow(/commit is not defined/);
    expect(api.DfirScope.get().start).toBe("2026-05-20T00:00:00.000Z");
  });

  // No `set`, and no `onScopeChange`. Both would re-open the design: one generic setter cannot
  // express three refresh paths, and one subscriber would have to fire the union of them.
  it("publishes no generic setter and no change subscription", () => {
    const { api } = loadScopeModule();
    const surface = Object.keys(api.DfirScope).sort();
    expect(surface).toEqual(["confirm", "contains", "get", "isEmpty", "project", "receive"]);
  });
});

describe("wiring", () => {
  it("is loaded by dashboard.html, ahead of the inline script, and served by the whitelist", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain('<script src="/js/dashboard-scope.js"></script>');
    const tag = html.indexOf('src="/js/dashboard-scope.js"');
    // AFTER the store whose cell() it builds on at load time.
    expect(html.indexOf('src="/js/dashboard-state.js"')).toBeLessThan(tag);
    // ...and BEFORE the inline script that calls it. Asserting only the first half let the tag move
    // anywhere later in the document — including past the inline script, where every DfirScope call
    // is a ReferenceError. These are synchronous classic scripts, so document order IS load order.
    //
    // The block is found by looking INSIDE each one, not with a single regex spanning the file: a
    // pattern like /<script[^>]*>[\s\S]*?function render\s*\(/ happily starts at the first tiny
    // bootstrap block in <head> and runs past its </script> to find render() in a later one, which
    // is how the first version of this assertion pointed at offset 652 instead of the real script.
    const blocks = [...html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)];
    const main = blocks.find((m) => /\n\s*function render\s*\(/.test(m[1]));
    expect(main, "could not locate the inline dashboard script").toBeDefined();
    expect(tag).toBeLessThan(main!.index);
    expect(STATIC_ASSETS["/js/dashboard-scope.js"]).toBe("application/javascript; charset=utf-8");
  });

  it("stays a classic script, like the helpers the inline script calls by name", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).not.toContain('<script type="module" src="/js/dashboard-scope.js">');
    const src = await readFile(MODULE, "utf8");
    expect(src).not.toMatch(/^\s*(?:export|import)\s/m);
  });
});
