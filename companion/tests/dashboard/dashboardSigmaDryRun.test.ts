// public/js/dashboard-sigma-dryrun.js — "Dry-run on this case" on the Sigma paste card (#2211).
// Matched event ids and field names come from the rule and from imported evidence, so the result is
// built with textContent only. A field the stored events cannot answer must be named on screen.
import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);
const MODULE = new URL("../../../public/js/dashboard-sigma-dryrun.js", import.meta.url);

interface FakeEl {
  tagName: string;
  id: string;
  children: FakeEl[];
  className: string;
  type: string;
  title: string;
  disabled: boolean;
  value: string;
  textContent: string;
  listeners: Record<string, (() => void)[]>;
  appendChild(c: FakeEl): FakeEl;
  addEventListener(t: string, fn: () => void): void;
}

function fakeEl(tag: string): FakeEl {
  let text = "";
  const el: FakeEl = {
    tagName: tag.toUpperCase(),
    id: "",
    children: [],
    className: "",
    type: "",
    title: "",
    disabled: false,
    value: "",
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
  };
  return el;
}

const walk = (el: FakeEl): FakeEl[] => [el, ...el.children.flatMap(walk)];

interface DryRunApi {
  runSigmaDryRun: () => Promise<void>;
  renderSigmaDryRun: (box: FakeEl, body: unknown) => void;
}

const HOSTILE = '<img src=x onerror="alert(1)">';
const reply = {
  ok: true,
  dryRun: {
    ok: true,
    category: "process_creation",
    eventCategory: "process",
    datasets: ["forensic", "super"],
    scanned: 500,
    eligible: 120,
    matched: 2,
    undecided: 3,
    sampleIds: ["e1", HOSTILE],
    truncated: true,
    maxRows: 200000,
    fields: [
      { field: "Image", storedAs: "process.executable", checkable: true, carried: 120 },
      { field: "ParentImage", storedAs: "process.parent.executable", checkable: true, carried: 0 },
      { field: "OriginalFileName", checkable: false, carried: 0 },
    ],
  },
};

function harness(body: unknown = reply, opts: { caseValue?: string; yaml?: string; ok?: boolean } = {}) {
  const elements: Record<string, FakeEl> = {};
  for (const id of ["caseId", "sigmaYamlIn", "sigmaDryRunRes", "sigmaDryRunBtn"])
    elements[id] = fakeEl("div");
  elements.caseId.value = opts.caseValue ?? "INC-1";
  elements.sigmaYamlIn.value = opts.yaml ?? "title: t\n";
  const created: FakeEl[] = [];
  const fetch = vi.fn(async () => ({
    ok: opts.ok ?? true,
    status: opts.ok === false ? 500 : 200,
    json: async () => body,
  }));
  const jump = vi.fn();
  const close = vi.fn();
  const api = loadDashboardModule<DryRunApi>("dashboard-sigma-dryrun.js", [], {
    document: {
      getElementById: (id: string) => elements[id] ?? null,
      createElement: (tag: string) => {
        const el = fakeEl(tag);
        created.push(el);
        return el;
      },
    },
    fetch,
    jumpToEvent: jump,
    closeHuntModal: close,
  });
  return { api, elements, created, fetch, jump, close, box: elements.sigmaDryRunRes };
}

describe("the Sigma dry-run result", () => {
  it("never renders server strings as HTML and does not start itself", async () => {
    const src = await readFile(MODULE, "utf8");
    expect(src).not.toMatch(/\.innerHTML\s*=|insertAdjacentHTML|outerHTML\s*=/);
    expect(src).not.toMatch(/DOMContentLoaded/);
  });

  it("is loaded and served", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain('<script src="/js/dashboard-sigma-dryrun.js"></script>');
    expect(STATIC_ASSETS["/js/dashboard-sigma-dryrun.js"]).toMatch(/javascript/);
  });

  it("posts the pasted rule to the case's dry-run route and renders the counts", async () => {
    const h = harness();
    await h.api.runSigmaDryRun();
    expect(h.fetch).toHaveBeenCalledWith(
      "/cases/INC-1/sigma/dry-run",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ yaml: "title: t\n" }) }),
    );
    const text = h.box.textContent;
    expect(text).toContain("Would match 2 of 120 process events in this case");
    expect(text).toContain("500 events scanned");
    expect(text).toMatch(/stopped at 200000 events/);
    expect(text).toMatch(/3 events could not be decided/);
    expect(text).toMatch(/ParentImage.*no event in this case keeps it/);
    expect(text).toMatch(/OriginalFileName.*not checkable here/);
    expect(text).toMatch(/Image: 120 of 120/);
    expect(h.elements.sigmaDryRunBtn.disabled).toBe(false);
  });

  it("renders a hostile event id as text and opens it in the timeline on click", async () => {
    const h = harness();
    await h.api.runSigmaDryRun();
    expect(h.created.some((e) => e.tagName === "IMG")).toBe(false);
    const links = walk(h.box).filter((e) => e.tagName === "BUTTON");
    expect(links.map((l) => l.textContent)).toEqual(["e1", HOSTILE]);
    for (const fn of links[1].listeners.click ?? []) fn();
    expect(h.close).toHaveBeenCalled();
    expect(h.jump).toHaveBeenCalledWith(HOSTILE, expect.stringMatching(/super-timeline/));
  });

  it("lists the refusals when the dry-run cannot test the rule", async () => {
    const h = harness({
      ok: false,
      dryRun: { ok: false, refusals: [{ path: "logsource.category", message: `image_load ${HOSTILE}` }] },
    });
    await h.api.runSigmaDryRun();
    expect(h.box.textContent).toContain("logsource.category");
    expect(h.box.textContent).toContain(HOSTILE);
    expect(h.created.some((e) => e.tagName === "IMG")).toBe(false);
  });

  it("shows a server error as one line", async () => {
    const h = harness({ error: "boom" }, { ok: false });
    await h.api.runSigmaDryRun();
    expect(h.box.textContent).toMatch(/Dry-run failed: boom/);
  });

  it("asks for a case and for a rule before it fetches", async () => {
    const noCase = harness(reply, { caseValue: "" });
    await noCase.api.runSigmaDryRun();
    expect(noCase.fetch).not.toHaveBeenCalled();
    expect(noCase.box.textContent).toMatch(/connect to a case/i);
    const noRule = harness(reply, { yaml: "  " });
    await noRule.api.runSigmaDryRun();
    expect(noRule.fetch).not.toHaveBeenCalled();
    expect(noRule.box.textContent).toMatch(/paste a Sigma rule/i);
  });
});
