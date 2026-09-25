import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import type { FacetsApi, IocApi, IocFilterInputs } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1649. The IOC panel sent the analyst back to page 1 whenever anything re-drew the list: a
// websocket state push, or one of the three IOC metadata loaders (sources / provenance / risk)
// landing after the case opened. renderIocs reset the page on EVERY call except the pager's own,
// so a Next click that raced one of those loaders stayed on "1–50 of 57" — the flaky US-183 e2e,
// and the same jump an analyst saw while paging during an import.
//
// The rule now: the page resets only when what the analyst filters on changes (or the case
// changes). A refresh keeps the page, clamped into range if the list shrank.

const ioc = loadDashboardModule<IocApi>("dashboard-ioc.js", ["dashboard-escape.js"]);

const base: IocFilterInputs = {
  caseId: "case-a",
  scope: { start: null, end: null },
  search: "",
  excludeTerms: [],
  flaggedOnly: false,
  hiddenTypes: [],
  corroboration: 0,
  provenance: "all",
  risk: 0,
  hideFpNoIntel: true,
  signalOnly: true,
  hideSystemPaths: true,
};

describe("resolveIocPage — which page a render lands on (#1649)", () => {
  const key = ioc.iocFilterKey(base);

  it("keeps page 2 across a refresh that leaves the filters alone", () => {
    const r = ioc.resolveIocPage({ page: 1, pageSize: 50, total: 57, key, lastKey: key });
    expect(r).toEqual({ page: 1, totalPages: 2, start: 50, end: 57 });
  });

  it("keeps the page when a refresh ADDS IOCs — an import landing while the analyst pages", () => {
    const r = ioc.resolveIocPage({ page: 1, pageSize: 50, total: 80, key, lastKey: key });
    expect(r).toEqual({ page: 1, totalPages: 2, start: 50, end: 80 });
  });

  it("goes back to page 1 when a filter changed", () => {
    const next = ioc.iocFilterKey({ ...base, search: "192.0.2." });
    const r = ioc.resolveIocPage({ page: 1, pageSize: 50, total: 57, key: next, lastKey: key });
    expect(r).toEqual({ page: 0, totalPages: 2, start: 0, end: 50 });
  });

  it("starts on page 1 on the first render, when there is no previous key", () => {
    const r = ioc.resolveIocPage({ page: 1, pageSize: 50, total: 57, key, lastKey: null });
    expect(r.page).toBe(0);
  });

  it("clamps to the last page when a refresh shrinks the list", () => {
    expect(ioc.resolveIocPage({ page: 3, pageSize: 50, total: 57, key, lastKey: key })).toEqual({
      page: 1,
      totalPages: 2,
      start: 50,
      end: 57,
    });
    expect(ioc.resolveIocPage({ page: 1, pageSize: 50, total: 50, key, lastKey: key })).toEqual({
      page: 0,
      totalPages: 1,
      start: 0,
      end: 50,
    });
  });

  it("shows one empty page, not a negative one, when nothing is left", () => {
    expect(ioc.resolveIocPage({ page: 1, pageSize: 50, total: 0, key, lastKey: key })).toEqual({
      page: 0,
      totalPages: 1,
      start: 0,
      end: 0,
    });
  });

  it("treats page size 0 as All — one page holding everything", () => {
    expect(ioc.resolveIocPage({ page: 2, pageSize: 0, total: 57, key, lastKey: key })).toEqual({
      page: 0,
      totalPages: 1,
      start: 0,
      end: 57,
    });
  });

  it("honours a page the caller already reset (a page-size change) under a stable key", () => {
    const r = ioc.resolveIocPage({ page: 0, pageSize: 100, total: 257, key, lastKey: key });
    expect(r).toEqual({ page: 0, totalPages: 3, start: 0, end: 100 });
  });
});

describe("iocFilterKey — what counts as a filter change (#1649)", () => {
  const key = ioc.iocFilterKey(base);

  it.each<[string, Partial<IocFilterInputs>]>([
    ["the case", { caseId: "case-b" }],
    ["the scope window", { scope: { start: "2026-01-01T00:00:00Z", end: null } }],
    ["the search text", { search: "evil" }],
    ["the exclude terms", { excludeTerms: ["noise"] }],
    ["flagged-only", { flaggedOnly: true }],
    ["the hidden IOC types", { hiddenTypes: ["hash"] }],
    ["the corroboration lens", { corroboration: 2 }],
    ["the provenance lens", { provenance: "detection" }],
    ["the risk lens", { risk: 3 }],
    ["Hide FP/no-intel", { hideFpNoIntel: false }],
    ["Signal only", { signalOnly: false }],
    ["Hide OS system paths", { hideSystemPaths: false }],
  ])("changes with %s", (_label, change) => {
    expect(ioc.iocFilterKey({ ...base, ...change })).not.toBe(key);
  });

  it("does not depend on the order hidden types or exclude terms were chosen in", () => {
    expect(ioc.iocFilterKey({ ...base, hiddenTypes: ["hash", "ip"], excludeTerms: ["a", "b"] })).toBe(
      ioc.iocFilterKey({ ...base, hiddenTypes: ["ip", "hash"], excludeTerms: ["b", "a"] }),
    );
  });

  it("cannot be forged by separator characters inside a value", () => {
    expect(ioc.iocFilterKey({ ...base, excludeTerms: ["a,b"] })).not.toBe(
      ioc.iocFilterKey({ ...base, excludeTerms: ["a", "b"] }),
    );
    expect(ioc.iocFilterKey({ ...base, search: 'x","caseId":"case-b' })).not.toBe(
      ioc.iocFilterKey({ ...base, search: "x", caseId: "case-b" }),
    );
  });

  it("reads a missing lens as its no-filter default, so a module that failed to load resets nothing", () => {
    const partial = { ...base } as Partial<IocFilterInputs>;
    delete partial.provenance;
    delete partial.risk;
    expect(ioc.iocFilterKey(partial as IocFilterInputs)).toBe(key);
  });
});

describe("the hidden IOC types a key reads are the analyst's choice, not today's data (#1649)", () => {
  // Keying on "hidden types that are present" would reset the page when a refresh removed or
  // brought back every IOC of a hidden type — a data change, not an analyst action.
  it("lists every hidden type, including one no IOC currently has", () => {
    const { DfirFacets } = loadDashboardModule<FacetsApi>("dashboard-facets.js", ["dashboard-state.js"]);
    DfirFacets.iocTypes.hideAll(["url", "hash"]);
    expect(DfirFacets.iocTypes.hiddenNames()).toEqual(["hash", "url"]);
    DfirFacets.iocTypes.toggle("hash", false);
    expect(DfirFacets.iocTypes.hiddenNames()).toEqual(["url"]);
  });

  it("hands out a copy, so a caller cannot edit the facet through it", () => {
    const { DfirFacets } = loadDashboardModule<FacetsApi>("dashboard-facets.js", ["dashboard-state.js"]);
    DfirFacets.iocTypes.hideAll(["url"]);
    DfirFacets.iocTypes.hiddenNames().push("ip");
    expect(DfirFacets.iocTypes.has("ip")).toBe(false);
  });
});

describe("renderIocs no longer resets the page on every call (#1649)", () => {
  const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);
  const body = async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const start = html.indexOf("    function renderIocs(");
    expect(start, "renderIocs must still be declared inline").toBeGreaterThan(0);
    return html.slice(start, html.indexOf("\n    }\n", start));
  };

  it("routes the page through resolveIocPage with a filter key", async () => {
    const src = await body();
    expect(src).toContain("resolveIocPage(");
    expect(src).toContain("iocFilterKey(");
  });

  it("has no unconditional reset to page 1 left in it", async () => {
    // The pre-#1649 line was `if (!_iocKeepPage) iocPage = 0;` — true for every caller but the pager.
    expect(await body()).not.toMatch(/\biocPage\s*=\s*0\b/);
    expect(await body()).not.toContain("_iocKeepPage");
  });
});
