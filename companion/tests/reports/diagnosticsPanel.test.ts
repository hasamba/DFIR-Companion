import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  DIAG_LEVEL_COLOR,
  diagAiCostBucketRow,
  diagCard,
  diagFmtAge,
  diagFmtBytes,
  diagFmtCost,
  diagRow,
  renderAiCostCard,
  renderOperationalDiagnostics,
  renderPerImporterHealth,
  // @ts-expect-error -- plain JS module with no .d.ts; the shapes are pinned by the tests below.
} from "../../../public/js/diagnostics-panel.js";

// The first slice of dashboard.html's 19k-line inline script to become a module (#384).
//
// It could move because it builds HTML STRINGS from a report object — no DOM, no fetch, no shared
// dashboard state. That is also why it is testable at all: none of this was reachable from a test
// while it lived inside a <script> tag, and writing these tests is what established what the
// functions actually accept. `diagFmtAge` takes MILLISECONDS, not a timestamp; a cost bucket keys
// its models under `byModel`, not a list. Both surprised me, which is the point.

const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);
const MODULE = new URL("../../../public/js/diagnostics-panel.js", import.meta.url);

describe("esc drift guard", () => {
  it("keeps the module's escape identical to the dashboard's inline one", async () => {
    // The inline script has 661 call sites for `esc`, so it cannot move in this pass and the module
    // carries its own copy. Two implementations of an XSS-critical primitive are a real hazard —
    // #387 exists because of unsafe DOM sinks — so this asserts they cannot drift apart.
    const [html, module] = await Promise.all([readFile(DASHBOARD, "utf8"), readFile(MODULE, "utf8")]);
    const bodyOf = (src: string): string => {
      const start = src.indexOf("function esc(s) {");
      expect(start, "esc(s) not found").toBeGreaterThan(-1);
      const end = src.indexOf("}", src.indexOf(".replace(/>/g", start));
      return src
        .slice(start, end + 1)
        .split("\n")
        .map((l) => l.trim())
        .join("");
    };
    expect(bodyOf(module)).toBe(bodyOf(html));
  });
});

describe("diagFmtBytes", () => {
  it.each([
    [0, "0 B"],
    [1023, "1023 B"],
    [1024, "1.0 KB"],
    [5 * 1024 * 1024, "5.0 MB"],
    [150 * 1024, "150 KB"], // >= 100 drops the decimal, so the column stays narrow
  ])("formats %i as %s", (input, expected) => {
    expect(diagFmtBytes(input)).toBe(expected);
  });

  it("renders an em dash for absent or nonsensical sizes", () => {
    // The report comes off disk; an older case may not carry the field at all.
    for (const bad of [null, undefined, NaN, -1, Infinity]) expect(diagFmtBytes(bad)).toBe("—");
  });
});

describe("diagFmtAge", () => {
  it.each([
    [5_000, "5s"],
    [90_000, "1m"],
    [3 * 3_600_000, "3h"],
    [50 * 3_600_000, "2d"],
  ])("formats %i ms as %s", (ms, expected) => {
    expect(diagFmtAge(ms)).toBe(expected);
  });

  it("treats absent or non-positive durations as zero rather than throwing", () => {
    for (const bad of [null, undefined, 0, -1, NaN]) expect(diagFmtAge(bad)).toBe("0s");
  });
});

describe("diagFmtCost", () => {
  it("keeps four decimals below a dollar", () => {
    // Sub-cent AI costs are the common case; "$0.00" would be useless for exactly the runs an
    // operator is trying to account for.
    expect(diagFmtCost(0.0012)).toBe("$0.0012");
  });

  it("drops to two decimals at a dollar and above", () => {
    expect(diagFmtCost(12.345)).toBe("$12.35");
  });

  it("says n/a when no cost was recorded", () => {
    expect(diagFmtCost(null)).toBe("n/a");
    expect(diagFmtCost(undefined)).toBe("n/a");
  });
});

describe("row and card primitives", () => {
  it("escapes the label, which can carry evidence-derived text", () => {
    const html = diagRow("<img src=x onerror=alert(1)>", "safe");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });

  it("does NOT escape the value, because callers pass markup deliberately", () => {
    // Documented rather than asserted-against: diagRow's value is a formatted HTML fragment (see
    // renderOperationalDiagnostics' hotspot rows). Callers escape their own interpolations — this
    // test exists so that contract is stated somewhere a reader will find it.
    expect(diagRow("k", "<b>bold</b>")).toContain("<b>bold</b>");
  });

  it("escapes the card title and embeds the rows it is given", () => {
    const card = diagCard("<script>x</script>", diagRow("k", "v"));
    expect(card).not.toContain("<script>x");
    expect(card).toContain("k");
  });
});

const bucket = (over = {}) => ({
  totalCalls: 3,
  totalCostUSD: 0.42,
  hasCost: true,
  hasTokens: true,
  totalInputTokens: 1000,
  totalOutputTokens: 200,
  byModel: {},
  ...over,
});

describe("diagAiCostBucketRow", () => {
  it("summarises calls, cost and tokens on one row", () => {
    const html = diagAiCostBucketRow("synthesis", bucket());
    expect(html).toContain("synthesis");
    expect(html).toContain("3 call(s)");
    expect(html).toContain("$0.4200");
  });

  it("nests a per-model breakdown when models are recorded", () => {
    const html = diagAiCostBucketRow("extract", {
      ...bucket(),
      byModel: { "gpt-x": { calls: 1, costUSD: 0.01, hasCost: true, hasTokens: false } },
    });
    expect(html).toContain("gpt-x");
    expect(html).toContain("1 model(s)");
  });

  it("omits the breakdown entirely when no models are recorded", () => {
    expect(diagAiCostBucketRow("extract", bucket())).not.toContain("<details");
  });
});

describe("renderAiCostCard", () => {
  const cost = () => ({ vision: bucket(), synthesis: bucket(), other: bucket() });

  it("totals the three buckets", () => {
    const html = renderAiCostCard(cost());
    expect(html).toContain("AI cost — this case");
    expect(html).toContain("9 call(s)"); // 3 buckets x 3 calls
  });

  it("renders nothing at all when there is no cost report", () => {
    expect(renderAiCostCard(null)).toBe("");
  });
});

describe("renderOperationalDiagnostics", () => {
  it("says disabled plainly, which is not an error state", () => {
    for (const input of [null, undefined, { enabled: false }]) {
      const html = renderOperationalDiagnostics(input);
      expect(html).toContain("disabled");
      expect(html).toContain("core behavior is unchanged");
    }
  });

  it("renders the full panel when metrics are on", () => {
    const html = renderOperationalDiagnostics({
      enabled: true,
      sampleCount: 12,
      retentionDays: 30,
      imports: { accepted: 5, rejected: 1, promoted: 2 },
      queries: { p50Ms: 3, p95Ms: 9, unindexed: 0 },
      jobs: { queued: 0, running: 1, retries: 0, stalled: 0 },
      ai: { calls: 2, p95Ms: 900, retries: 0, rateLimits: 0 },
      exports: { count: 1, p95Ms: 50, outputBytes: 2048 },
      websocket: { active: 1, reconnects: 0, dropped: 0, rejects: 0 },
      capacity: { databaseBytes: 4096 },
      warnings: ["disk is filling"],
    });
    expect(html).toContain("Retention");
    expect(html).toContain("2.0 KB"); // exports.outputBytes through diagFmtBytes
    expect(html).toContain("disk is filling");
  });

  it("escapes warning text", () => {
    const html = renderOperationalDiagnostics({
      enabled: true,
      sampleCount: 0,
      retentionDays: 1,
      imports: { accepted: 0, rejected: 0, promoted: 0 },
      queries: { p50Ms: 0, p95Ms: 0, unindexed: 0 },
      jobs: { queued: 0, running: 0, retries: 0, stalled: 0 },
      ai: { calls: 0, p95Ms: 0, retries: 0, rateLimits: 0 },
      exports: { count: 0, p95Ms: 0, outputBytes: 0 },
      websocket: { active: 0, reconnects: 0, dropped: 0, rejects: 0 },
      capacity: {},
      warnings: ["<script>alert(1)</script>"],
    });
    expect(html).not.toContain("<script>alert(1)");
  });
});

describe("renderPerImporterHealth", () => {
  it("escapes a spec filename, which is operator-supplied", () => {
    const html = renderPerImporterHealth({
      importers: [],
      loadErrors: [{ file: "<img src=x onerror=alert(1)>.yml", errors: [{ path: "a", message: "b" }] }],
    });
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img");
  });

  it("reports how many spec load errors there are", () => {
    const html = renderPerImporterHealth({
      importers: [],
      loadErrors: [
        { file: "a.yml", errors: [{ path: "x", message: "bad" }] },
        { file: "b.yml", errors: [{ path: "y", message: "worse" }] },
      ],
    });
    expect(html).toContain("Spec load errors (2)");
  });
});

describe("DIAG_LEVEL_COLOR", () => {
  it("covers every level the panel can report", () => {
    // renderDiagnostics is still inline and indexes this map directly, so a missing key would
    // render an undefined colour rather than fail loudly.
    expect(Object.keys(DIAG_LEVEL_COLOR).sort()).toEqual(["critical", "danger", "none", "warning"]);
  });
});

// ---------------------------------------------------------------------------------------------
// THE WIRING, which the tests above cannot see.
//
// Every test in this file imports the module directly, so all 29 passed while the page was broken:
// the first cut published only the four top-level renderers on window.DfirDiagnostics, but
// renderDiagnostics, diagComputeSizes, loadCaseStats and loadCaseBackups still made 46 BARE calls
// to diagRow/diagCard/diagFmtBytes/diagFmtAge. An ES module's declarations are not globals, so
// every one was a ReferenceError and the Diagnostics panel threw the moment it rendered.
//
// Unit tests over an extracted module are structurally incapable of catching that. These two are
// the join between the module and the page, and they are the shape every future dashboard
// extraction needs.
// ---------------------------------------------------------------------------------------------
describe("dashboard wiring", () => {
  const readDashboard = (): Promise<string> =>
    readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  const readModule = (): Promise<string> =>
    readFile(new URL("../../../public/js/diagnostics-panel.js", import.meta.url), "utf8");

  it("publishes every function the module defines", async () => {
    const source = await readModule();
    const defined = [...source.matchAll(/^function ([A-Za-z0-9_]+)/gm)].map((m) => m[1]);
    const published = /window\.DfirDiagnostics = \{([\s\S]*?)\};/.exec(source)?.[1] ?? "";

    // Publishing everything is deliberate rather than tidy: a helper that stays unpublished is
    // invisible until the page calls it, and the page is what no unit test loads.
    const missing = defined.filter((name) => !new RegExp(`\\b${name},`).test(published));
    expect(missing).toEqual([]);
  });

  it("binds the namespace in every inline function that calls into the module", async () => {
    const [page, source] = await Promise.all([readDashboard(), readModule()]);
    // Names the module defines AND the inline script does not. `esc` is deliberately defined in
    // both -- 661 inline call sites, and a module cannot read the inline scope -- so an inline
    // `esc(...)` resolves locally and is correct. Only names that exist ONLY in the module can
    // produce the ReferenceError this test exists to catch.
    const inlineDefined = new Set(
      [...page.matchAll(/^ {4}(?:async )?function ([A-Za-z0-9_]+)/gm)].map((m) => m[1]),
    );
    const defined = [...source.matchAll(/^function ([A-Za-z0-9_]+)/gm)]
      .map((m) => m[1])
      .filter((name) => !inlineDefined.has(name));

    // Walk the page's top-level inline functions, and for each one collect the module names it
    // calls WITHOUT qualifying, then require that the function bound them from the namespace.
    const lines = page.split("\n");
    const offenders: string[] = [];
    let current = "";
    let bound = new Set<string>();
    for (const line of lines) {
      const decl = /^ {4}(?:async )?function ([A-Za-z0-9_]+)/.exec(line);
      if (decl) {
        current = decl[1];
        bound = new Set();
      }
      const binding = /const \{([^}]*)\} = window\.DfirDiagnostics;/.exec(line);
      if (binding) for (const n of binding[1].split(",")) bound.add(n.trim());
      for (const name of defined) {
        if (!new RegExp(`(?<![.\\w])${name}\\(`).test(line)) continue;
        if (bound.has(name)) continue;
        offenders.push(`${current} calls ${name}() without binding it from window.DfirDiagnostics`);
      }
    }
    expect([...new Set(offenders)]).toEqual([]);
  });
});
