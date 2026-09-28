import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildAttackMatrix, type MatrixHit } from "../../src/analysis/attackMatrix.js";
import { EMPTY_ATTACK_MATRIX, type AttackMatrixData } from "../../src/analysis/attackMatrixData.js";
import type { MitreMatrixApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The Matrix view's drawing, its per-viewer choices, and the one promise it makes to the List
// view: when the switch says List, #mitre is exactly what it always was (#1764).

const HOSTILE = "<img src=x onerror=alert(1)>";

const DATA: AttackMatrixData = {
  source: "test",
  attackVersion: "19.1",
  generated: "2026-09-28",
  tactics: [
    { id: "TA0002", shortname: "execution", name: "Execution" },
    { id: "TA0003", shortname: "persistence", name: "Persistence" },
  ],
  techniques: [
    {
      id: "T1059",
      name: "Command and Scripting Interpreter",
      tactics: ["execution"],
      platforms: ["Windows"],
    },
    { id: "T1059.001", name: "PowerShell", tactics: ["execution"], platforms: ["Windows"], parent: "T1059" },
    {
      id: "T1053",
      name: "Scheduled Task/Job",
      tactics: ["execution", "persistence"],
      platforms: ["Windows"],
    },
    {
      id: "T1053.005",
      name: "Scheduled Task",
      tactics: ["execution"],
      platforms: ["Windows"],
      parent: "T1053",
    },
    { id: "T1053.003", name: "Cron", tactics: ["execution"], platforms: ["Linux"], parent: "T1053" },
    { id: "T1547", name: HOSTILE, tactics: ["persistence"], platforms: ["Windows"] },
  ],
};

interface FakeEl {
  id: string;
  innerHTML: string;
  textContent: string;
  value?: string;
  checked?: boolean;
  disabled?: boolean;
  hidden?: boolean;
  attrs: Record<string, string>;
  classes: Set<string>;
  setAttribute(k: string, v: string): void;
  getAttribute(k: string): string | null;
  classList: { toggle(c: string, on: boolean): void };
  querySelector(): null;
  addEventListener(): void;
}
function fakeEl(id: string): FakeEl {
  const el: FakeEl = {
    id,
    innerHTML: "UNTOUCHED",
    textContent: "",
    attrs: {},
    classes: new Set(),
    setAttribute: (k, v) => void (el.attrs[k] = v),
    getAttribute: (k) => el.attrs[k] ?? null,
    classList: { toggle: (c, on) => void (on ? el.classes.add(c) : el.classes.delete(c)) },
    querySelector: () => null,
    addEventListener: () => {},
  };
  return el;
}

function storage(init: Record<string, string> = {}) {
  const data = { ...init };
  return {
    data,
    getItem: (k: string) => (k in data ? data[k] : null),
    setItem: (k: string, v: string) => void (data[k] = v),
  };
}

function load(opts: { store?: unknown; fetchImpl?: unknown } = {}) {
  const ids = [
    "mitre",
    "sec-mitre",
    "mitrePopover",
    "mitreViewMatrix",
    "mitreViewList",
    "mitrePlatform",
    "mitreHitsOnly",
    "mitrePlatformCtl",
    "mitreHitsOnlyCtl",
    "mitreExpandCtl",
  ];
  const els = new Map(ids.map((id) => [id, fakeEl(id)]));
  const document = { getElementById: (id: string) => els.get(id) ?? null, addEventListener: () => {} };
  const g = loadDashboardModule<{ initMitreMatrix(): void; DfirMitreMatrix?: MitreMatrixApi }>(
    "dashboard-mitre-matrix.js",
    ["dashboard-escape.js"],
    {
      document,
      localStorage: opts.store ?? storage(),
      fetch: opts.fetchImpl ?? (() => new Promise(() => {})),
    },
  );
  g.initMitreMatrix();
  return { api: g.DfirMitreMatrix!, els };
}

const hit = (id: string, worst: MatrixHit["worst"], extra: Partial<MatrixHit> = {}): MatrixHit => ({
  id,
  worst,
  findingIds: [],
  eventIds: [],
  ...extra,
});

describe("the List view stays exactly as it was", () => {
  it("keeps today's row template, byte for byte, in render()", () => {
    const src = readFileSync(new URL("../../../public/js/dashboard-render.js", import.meta.url), "utf8");
    expect(src).toContain(
      '`<div class="mitre-row">${mitreLinks([m.id])} <span>${esc(m.name)}</span><span class="mitre-findings">${esc(m.findingIds.join(", "))}</span></div>`,',
    );
    // #1767: an empty List says so in a sentence instead of a bare dash.
    expect(src).toContain('.join("") || mitreEmptyHtml();');
    // With the matrix module missing, the List is what render() draws.
    expect(src).toMatch(/if \(window\.DfirMitreMatrix\) \{[\s\S]*?\} else renderMitreList\(\);/);
  });

  it("hands #mitre to the List painter when the switch says List, and writes nothing itself", () => {
    const { api, els } = load({ store: storage({ "dfir.mitreView": "list" }) });
    let calls = 0;
    api.renderPanel({ rows: [], findings: [], ft: [], renderList: () => void calls++ });
    expect(calls).toBe(1);
    expect(els.get("mitre")!.innerHTML).toBe("UNTOUCHED");
    expect(els.get("mitreViewList")!.attrs["aria-pressed"]).toBe("true");
    // The matrix-only controls are hidden in List view, not left as dead gray controls.
    expect(els.get("mitrePlatformCtl")!.hidden).toBe(true);
    expect(els.get("mitreHitsOnlyCtl")!.hidden).toBe(true);
    expect(els.get("mitreExpandCtl")!.hidden).toBe(true);
  });
});

describe("per-viewer choices", () => {
  it("defaults to Matrix, Windows, all cells", () => {
    expect(load().api.prefs()).toEqual({ view: "matrix", platform: "windows", hitsOnly: false });
  });

  it("shows the matrix-only controls in Matrix view", () => {
    const { api, els } = load({ store: storage({ "dfir.mitreView": "matrix" }) });
    api.renderPanel({ rows: [], findings: [], ft: [], renderList: () => {} });
    expect(els.get("mitrePlatformCtl")!.hidden).toBe(false);
    expect(els.get("mitreHitsOnlyCtl")!.hidden).toBe(false);
  });

  it("reads stored choices and ignores unknown values", () => {
    const stored = load({
      store: storage({ "dfir.mitreView": "list", "dfir.mitrePlatform": "linux", "dfir.mitreHitsOnly": "1" }),
    });
    expect(stored.api.prefs()).toEqual({ view: "list", platform: "linux", hitsOnly: true });
    const junk = load({
      store: storage({
        "dfir.mitreView": "grid",
        "dfir.mitrePlatform": "amiga",
        "dfir.mitreHitsOnly": "yes",
      }),
    });
    expect(junk.api.prefs()).toEqual({ view: "matrix", platform: "windows", hitsOnly: false });
  });

  it("survives blocked storage", () => {
    const blocked = {
      getItem: () => {
        throw new Error("SecurityError");
      },
      setItem: () => {
        throw new Error("SecurityError");
      },
    };
    expect(load({ store: blocked }).api.prefs()).toEqual({
      view: "matrix",
      platform: "windows",
      hitsOnly: false,
    });
  });
});

describe("drawing the matrix", () => {
  const { api } = load();
  const draw = (hits: MatrixHit[], opts = { platform: "windows" as const, hitsOnly: false }, data = DATA) =>
    api.matrixHtml(buildAttackMatrix(data, hits, opts), hits);

  it("labels a hit cell with id, name, severity and counts, and shows badge and letter", () => {
    const html = draw([hit("T1059.001", "High", { findingIds: ["f1", "f2", "f3"], eventIds: ["e1", "e2"] })]);
    expect(html).toContain('aria-label="T1059.001 PowerShell, High, 3 findings, 2 events"');
    expect(html).toMatch(/mm-hit mm-sev-High[^>]*data-tid="T1059.001"/);
    expect(html).toContain('<span class="mm-badge" aria-hidden="true" title="3 findings, 2 events">5</span>');
    expect(html).toContain('<span class="mm-sevl" aria-hidden="true" title="Worst severity: High">H</span>');
  });

  it("opens a parent with a hit child and shows the worst of both; leaves others closed", () => {
    const html = draw([
      hit("T1059", "Low", { eventIds: ["e0"] }),
      hit("T1059.001", "Critical", { eventIds: ["e1"] }),
    ]);
    expect(html).toContain(
      'aria-label="T1059 Command and Scripting Interpreter, Critical, 0 findings, 2 events"',
    );
    expect(html).toContain('title="0 findings, 2 events (with its sub-techniques)"');
    expect(html).toContain('data-toggle="T1059" tabindex="-1" aria-expanded="true"');
    expect(html).toContain('data-tid="T1059.001"');
    // T1053 has no hit: closed, "+1" (Cron is Linux-only and filtered out under Windows).
    expect(html).toContain('data-toggle="T1053" tabindex="-1" aria-expanded="false"');
    expect(html).toContain(">+1</button>");
    expect(html).not.toContain('data-tid="T1053.005"');
  });

  it("writes a hostile technique name as text", () => {
    const html = draw([hit("T1547", "High")]);
    expect(html).not.toContain(HOSTILE);
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("hides gray cells and empty columns under Hits only", () => {
    const html = draw([hit("T1059.001", "Medium")], { platform: "windows", hitsOnly: true });
    expect(html).not.toContain("not seen in this case");
    expect(html).not.toContain("Persistence");
  });

  it("shows only the severities present in the legend, and the version stamp", () => {
    const html = draw([hit("T1059.001", "Medium"), hit("T1547", "Critical")]);
    expect(html).toContain(">Medium</span>");
    expect(html).toContain(">Critical</span>");
    expect(html).not.toContain(">Low</span>");
    expect(html).toContain("ATT&amp;CK Enterprise v19.1");
    // The numbers explain themselves: a key under the legend, hover text on each column count.
    expect(html).toContain(
      "Cell number = findings + events · letter = worst severity · column number = techniques seen",
    );
    expect(html).toContain('title="1 technique seen in this tactic"');
  });

  it("with no catalogue, says so and puts every hit in Unmapped", () => {
    const hits = [{ ...hit("T1059.001", "High"), name: "PowerShell" }, hit("T9999", "Low")];
    const html = draw(hits, { platform: "windows", hitsOnly: false }, EMPTY_ATTACK_MATRIX);
    expect(html).toContain("ATT&amp;CK catalogue not available — showing case techniques only");
    expect(html).toContain('<span class="mm-tactic">Unmapped</span>');
    expect(html).toContain('data-tid="T1059.001"');
    expect(html).toContain('data-tid="T9999"');
    expect(html).not.toContain("ATT&amp;CK Enterprise v");
  });

  it("shows the note and an empty Unmapped column for an empty catalogue and no hits", () => {
    const html = draw([], { platform: "windows", hitsOnly: false }, EMPTY_ATTACK_MATRIX);
    expect(html).toContain("catalogue not available");
    expect(html).toContain('<span class="mm-tactic">Unmapped</span>');
  });
});

describe("the popover", () => {
  const { api } = load();
  const ctx = (findings: unknown[] = [], ft: unknown[] = []) => ({
    catalogue: DATA,
    findingsById: new Map(findings.map((f) => [(f as { id: string }).id, f])),
    eventsById: new Map(ft.map((e) => [(e as { id: string }).id, e])),
  });

  it("writes a hostile finding title and event description as text", () => {
    const html = api.popoverHtml(
      {
        id: "T1059.001",
        name: "PowerShell",
        agg: hit("T1059.001", "High", { findingIds: ["f1"], eventIds: ["e1"] }),
      },
      ctx(
        [{ id: "f1", title: HOSTILE, severity: "High" }],
        [{ id: "e1", timestamp: "2026-01-01", description: HOSTILE }],
      ),
    );
    expect(html).not.toContain(HOSTILE);
    expect(html).toContain('data-jump-finding="f1"');
    expect(html).toContain('data-jump-event="e1"');
  });

  it("links to attack.mitre.org and names the parent's tactics for a sub-technique", () => {
    const html = api.popoverHtml(
      { id: "T1053.005", name: "Scheduled Task", agg: hit("T1053.005", "Low") },
      ctx(),
    );
    expect(html).toContain('href="https://attack.mitre.org/techniques/T1053/005/"');
    expect(html).toContain("Tactics: Execution, Persistence");
    expect(html).toContain("Worst severity: Low");
  });

  it("lists the first 50 events, then says how many more", () => {
    const ids = Array.from({ length: 57 }, (_, i) => `e${i}`);
    const html = api.popoverHtml(
      { id: "T1059", name: "x", agg: hit("T1059", "Info", { eventIds: ids }) },
      ctx(),
    );
    expect(html.match(/data-jump-event=/g)).toHaveLength(50);
    expect(html).toContain("and 7 more");
  });

  it("says when the analyst accepted a technique nothing supports", () => {
    const html = api.popoverHtml(
      { id: "T1583", name: "Acquire", agg: hit("T1583", "Info", { analystAccepted: true }) },
      ctx(),
    );
    expect(html).toContain("Accepted by analyst");
    expect(html).toContain("not in the bundled catalogue");
  });
});

describe("the catalogue fetch", () => {
  it("fetches once, then paints the matrix into #mitre", async () => {
    let calls = 0;
    const fetchImpl = () => {
      calls++;
      return Promise.resolve({ ok: true, json: () => Promise.resolve(DATA) });
    };
    const { api, els } = load({ fetchImpl });
    const rows = [{ id: "T1059.001", name: "PowerShell", findingIds: [] }];
    const args = { rows, findings: [], ft: [], renderList: () => {} };
    api.renderPanel(args);
    expect(els.get("mitre")!.textContent).toContain("Loading");
    await new Promise((r) => setTimeout(r, 0));
    expect(els.get("mitre")!.innerHTML).toContain('data-tid="T1059.001"');
    expect(els.get("sec-mitre")!.classes.has("mm-matrix-on")).toBe(true);
    api.renderPanel(args);
    expect(calls).toBe(1);
  });

  it("Expand all and Collapse all override every parent, including the automatic open", async () => {
    const fetchImpl = () => Promise.resolve({ ok: true, json: () => Promise.resolve(DATA) });
    const { api, els } = load({ fetchImpl });
    const rows = [{ id: "T1059.001", name: "PowerShell", findingIds: [] }];
    api.renderPanel({ rows, findings: [], ft: [], renderList: () => {} });
    await new Promise((r) => setTimeout(r, 0));
    const html = () => els.get("mitre")!.innerHTML;
    // T1059 opens by itself (a hit sub-technique); T1053 has none and starts closed.
    expect(html()).toContain('data-toggle="T1059" tabindex="-1" aria-expanded="true"');
    expect(html()).toContain('data-toggle="T1053" tabindex="-1" aria-expanded="false"');
    api.setAllExpanded(false);
    expect(html()).toContain('data-toggle="T1059" tabindex="-1" aria-expanded="false"');
    api.setAllExpanded(true);
    expect(html()).toContain('data-toggle="T1059" tabindex="-1" aria-expanded="true"');
    expect(html()).toContain('data-toggle="T1053" tabindex="-1" aria-expanded="true"');
  });

  it("falls back to Unmapped with the note when the fetch fails", async () => {
    const { api, els } = load({ fetchImpl: () => Promise.reject(new Error("offline")) });
    api.renderPanel({
      rows: [{ id: "T1059", name: "Cmd", findingIds: [] }],
      findings: [],
      ft: [],
      renderList: () => {},
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(els.get("mitre")!.innerHTML).toContain("catalogue not available");
    expect(els.get("mitre")!.innerHTML).toContain('data-tid="T1059"');
  });
});
