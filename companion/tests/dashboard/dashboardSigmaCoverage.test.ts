// public/js/dashboard-sigma-coverage.js — the Sigma coverage card in the Hunt Workbench (#2217).
// Origin labels come from imported evidence (an attacker can shape an artifact name), so the card
// must never write HTML from them. Each row pivots into the super-timeline, filtered to its origin.
import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { declaredFunctions, loadDashboardModule } from "../helpers/dashboardModule.js";

const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);
const MODULE = new URL("../../../public/js/dashboard-sigma-coverage.js", import.meta.url);
const CONNECT = new URL("../../../public/js/dashboard-case-connect.js", import.meta.url);

// ── A minimal DOM: enough for createElement / textContent / appendChild / click. ───────────────
interface FakeEl {
  tagName: string;
  children: FakeEl[];
  className: string;
  type: string;
  title: string;
  disabled: boolean;
  style: Record<string, string>;
  textContent: string;
  listeners: Record<string, (() => void)[]>;
  appendChild(c: FakeEl): FakeEl;
  addEventListener(t: string, fn: () => void): void;
  setAttribute(n: string, v: string): void;
  attrs: Record<string, string>;
}

function fakeEl(tag: string): FakeEl {
  let text = "";
  const el: FakeEl = {
    tagName: tag.toUpperCase(),
    children: [],
    className: "",
    type: "",
    title: "",
    disabled: false,
    style: {},
    attrs: {},
    listeners: {},
    get textContent() {
      return text + el.children.map((c) => c.textContent).join("");
    },
    set textContent(v: string) {
      text = String(v);
      el.children = [];
    },
    appendChild(c) {
      el.children.push(c);
      return c;
    },
    addEventListener(t, fn) {
      (el.listeners[t] ??= []).push(fn);
    },
    setAttribute(n, v) {
      el.attrs[n] = String(v);
    },
  };
  return el;
}

const walk = (el: FakeEl): FakeEl[] => [el, ...el.children.flatMap(walk)];

interface CoverageApi {
  loadSigmaCoverage: (caseId?: string) => Promise<void>;
  initSigmaCoverage: () => void;
  filterSuperTimelineToOrigin?: (origin: string, all: string[]) => void;
}

const HOSTILE = '<img src=x onerror="alert(1)">';
const reply = {
  enabled: true,
  graded: 1,
  total: 3,
  rows: [
    {
      origin: "AWS CloudTrail",
      events: 40,
      state: "covered",
      sigmaSources: [
        { id: "aws-cloudtrail", label: "AWS CloudTrail", loaded: 28, disabled: 2, refused: 1, status: 0 },
      ],
    },
    { origin: HOSTILE, events: 3, state: "not-graded", sigmaSources: [] },
    {
      origin: "Web Access Log",
      events: 7,
      state: "no-loaded-rules",
      caveat: "graded by the web server OR the web proxy rules, chosen per import from the log's shape",
      sigmaSources: [
        { id: "web-server", label: "web server access logs", loaded: 0, disabled: 2, refused: 0, status: 0 },
      ],
    },
  ],
};

function harness(body: unknown = reply, caseValue = "INC-1") {
  const elements: Record<string, FakeEl | { value: string; addEventListener: () => void }> = {
    caseId: { value: caseValue, addEventListener: () => undefined },
    sigmaCoverage: fakeEl("div"),
    sigmaCoverageHeadline: fakeEl("span"),
    sigmaCoverageRefresh: fakeEl("button"),
  };
  const created: FakeEl[] = [];
  const fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => body }));
  const pivot = vi.fn();
  const api = loadDashboardModule<CoverageApi>("dashboard-sigma-coverage.js", [], {
    document: {
      readyState: "loading",
      addEventListener: () => undefined,
      getElementById: (id: string) => elements[id] ?? null,
      createElement: (tag: string) => {
        const el = fakeEl(tag);
        created.push(el);
        return el;
      },
    },
    fetch,
    filterSuperTimelineToOrigin: pivot,
  });
  return { api, elements, created, fetch, pivot, box: elements.sigmaCoverage as FakeEl };
}

describe("the Sigma coverage card", () => {
  it("never renders server strings as HTML", async () => {
    const src = await readFile(MODULE, "utf8");
    expect(src).not.toMatch(/\.innerHTML\s*=|insertAdjacentHTML|outerHTML\s*=/);
  });

  it("declares its loader and initializer", () => {
    const fns = declaredFunctions("dashboard-sigma-coverage.js");
    for (const name of ["initSigmaCoverage", "loadSigmaCoverage", "renderSigmaCoverage"])
      expect(fns).toContain(name);
  });

  it("is loaded, served, wires itself once, and sits inside the Hunt Workbench", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const src = await readFile(MODULE, "utf8");
    expect(html).toContain('<script src="/js/dashboard-sigma-coverage.js"></script>');
    expect(STATIC_ASSETS["/js/dashboard-sigma-coverage.js"]).toMatch(/javascript/);
    expect(
      src.match(/addEventListener\("DOMContentLoaded", initSigmaCoverage, \{ once: true \}\)/g),
    ).toHaveLength(1);
    const start = html.indexOf('<section id="sec-hunt-workbench"');
    const end = html.indexOf("</section>", start);
    const section = html.slice(start, end);
    for (const id of ["sigmaCoverage", "sigmaCoverageHeadline", "sigmaCoverageRefresh"])
      expect(section).toContain(`id="${id}"`);
  });

  it("reloads when a case opens and when the super-timeline changes", async () => {
    const connect = await readFile(CONNECT, "utf8");
    expect(connect).toContain('["sigmaCoverage", () => loadSigmaCoverage(caseId)]');
    expect(connect.match(/loadSigmaCoverage\(caseId\)/g)?.length).toBeGreaterThanOrEqual(2);
  });

  it("fetches the case's coverage and renders a headline and one row per origin", async () => {
    const h = harness();
    await h.api.loadSigmaCoverage("INC-1");
    expect(h.fetch).toHaveBeenCalledWith("/cases/INC-1/sigma/coverage");
    expect((h.elements.sigmaCoverageHeadline as FakeEl).textContent).toBe(
      "1 of 3 ingested sources have Sigma rules running",
    );
    const rows = walk(h.box).filter((e) => e.tagName === "TR");
    expect(rows).toHaveLength(4); // header + three origins
    expect(h.box.textContent).toContain("28 loaded");
    expect(h.box.textContent).toContain("Not graded by Sigma");
    expect(h.box.textContent).toContain("No loaded rules");
    expect(h.box.textContent).toContain("chosen per import");
  });

  it("renders a hostile origin as text, never as markup", async () => {
    const h = harness();
    await h.api.loadSigmaCoverage("INC-1");
    expect(h.created.some((e) => e.tagName === "IMG")).toBe(false);
    expect(walk(h.box).some((e) => e.tagName === "TD" && e.textContent === HOSTILE)).toBe(true);
  });

  it("pivots a row into the super-timeline with every origin the card knows", async () => {
    const h = harness();
    await h.api.loadSigmaCoverage("INC-1");
    const buttons = walk(h.box).filter((e) => e.tagName === "BUTTON");
    expect(buttons).toHaveLength(3);
    for (const fn of buttons[1].listeners.click ?? []) fn();
    expect(h.pivot).toHaveBeenCalledWith(HOSTILE, ["AWS CloudTrail", HOSTILE, "Web Access Log"]);
  });

  it("says when Sigma grading is switched off", async () => {
    const off = {
      enabled: false,
      graded: 0,
      total: 1,
      rows: [{ origin: "AWS CloudTrail", events: 1, state: "sigma-off", sigmaSources: [] }],
    };
    const h = harness(off);
    await h.api.loadSigmaCoverage("INC-1");
    expect((h.elements.sigmaCoverageHeadline as FakeEl).textContent).toMatch(/switched off/);
    expect(h.box.textContent).toContain("Sigma grading is switched off");
  });

  it("asks for a case when none is open, and does not fetch", async () => {
    const h = harness(reply, "");
    await h.api.loadSigmaCoverage();
    expect(h.fetch).not.toHaveBeenCalled();
    expect(h.box.textContent).toMatch(/Open a case/);
  });

  it("drops an answer for a case the analyst has left", async () => {
    const h = harness();
    (h.elements.caseId as { value: string }).value = "INC-2";
    await h.api.loadSigmaCoverage("INC-1");
    expect(walk(h.box).filter((e) => e.tagName === "TR")).toHaveLength(0);
  });
});

// The pivot target: the super-timeline's origin filter is an EXCLUDE model, so the setter must know
// every origin of the case, or a never-loaded panel would exclude nothing and show everything.
describe("filterSuperTimelineToOrigin", () => {
  it("excludes every other origin of the case and reveals the panel", async () => {
    const urls: string[] = [];
    const reveal = vi.fn();
    const elements: Record<string, unknown> = {
      caseId: { value: "INC-1" },
      superTimelineMsg: { textContent: "", style: { color: "" } },
      stFrom: { value: "" },
      stTo: { value: "" },
    };
    const api = loadDashboardModule<CoverageApi>(
      "dashboard-super-timeline.js",
      ["dashboard-state.js", "dashboard-escape.js", "dashboard-time.js", "dashboard-timeline-view.js"],
      {
        URLSearchParams,
        revealSection: reveal,
        document: {
          getElementById: (id: string) => elements[id] ?? null,
          addEventListener: () => undefined,
          querySelectorAll: () => [],
        },
        fetch: (url: string) => {
          urls.push(url);
          return new Promise(() => undefined);
        },
      },
    );
    api.filterSuperTimelineToOrigin?.("Web Access Log", ["AWS CloudTrail", "Web Access Log", "Unknown"]);
    expect(reveal).toHaveBeenCalledWith("sec-super-timeline");
    expect(urls).toHaveLength(1);
    const q = new URLSearchParams(urls[0].split("?")[1]);
    expect(q.get("exclude")?.split(",").sort()).toEqual(["AWS CloudTrail", "Unknown"]);
    expect(q.get("offset")).toBe("0");
  });
});
