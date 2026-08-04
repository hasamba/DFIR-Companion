import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { dashboardScripts, functionsOf, topLevelBindings } from "../helpers/dashboardAst.js";

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
    private: ["geoMapData", "geoMap", "geoLayer", "geoFlowLayer", "geoMapTimer", "geoMapInitializing"],
  },
  {
    file: "dashboard-custody.js",
    publish: ["initCustodyButtons", "loadCustody", "verifyCustodyOnOpen"],
    private: ["custodyRecords", "custodyFailedPaths", "custodyVerifiedAt"],
  },
  { file: "dashboard-backup.js", publish: ["loadCaseBackups", "restoreCaseBackup"], private: [] },
  {
    file: "dashboard-collection-plan.js",
    publish: ["fetchCollectionResults", "renderCollectionPlan"],
    private: [],
  },
];

const read = (f: string) => readFile(new URL(`../../../public/js/${f}`, import.meta.url), "utf8");
const scripts = dashboardScripts();

describe.each(FEATURES)("$file", (feat) => {
  it("declares and publishes every name the page calls", async () => {
    const src = await read(feat.file);
    for (const name of feat.publish) {
      expect(src, `${name} is published but never declared`).toMatch(new RegExp(`function ${name}\\s*\\(`));
      expect(src, `${name} is declared but never published`).toContain(`window.${name} = ${name};`);
    }
  });

  // THE POINT OF THE CLOSURE. A top-level `let` in a classic script is reachable by name from every
  // later script, so "feature-local" would be a claim rather than a fact. Wrapped, it is a fact.
  it("keeps its state inside the closure", async () => {
    const src = await read(feat.file);
    expect(src.trimStart(), "the module must be wrapped").toMatch(/\(function \(\) \{/);
    for (const name of feat.private) {
      expect(src, `${name} must be declared`).toMatch(new RegExp(`\\b${name}\\b`));
      expect(src, `${name} must not be published`).not.toContain(`window.${name}`);
    }
  });

  // Anything NOT on the publish list must be unreachable, which only holds if the page stopped
  // referring to it. A name left behind in the page resolves to undefined at call time.
  it("leaves nothing behind in the inline script", async () => {
    const src = await read(feat.file);
    const declared = [...src.matchAll(/^ {2}(?:async )?function (\w+)\s*\(/gm)].map((m) => m[1]);
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

  it("takes its bindings with it, leaving none in the page", () => {
    const inline = scripts.filter((s) => s.name.startsWith("dashboard.html#inline"));
    const stranded = inline.flatMap((s) =>
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
