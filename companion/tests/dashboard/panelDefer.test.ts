// #2854: a heavy panel whose section the active view profile or the section-visibility settings
// hide is not fetched on case open and not re-derived on live pushes. Revealing the section loads
// it once, with the latest data; a case switch never lets a deferred load paint into another case,
// and a revealed panel never shows the previous case's content while its own load is on the way.
import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { runPanelLoaders } from "../../../public/js/case-load-progress.js";

const JS = new URL("../../../public/js/", import.meta.url);
const read = (f: string) => readFileSync(new URL(f, JS), "utf8").replace(/\r\n/g, "\n");
const settle = () => new Promise((r) => setTimeout(r, 0));
const flushAll = async () => {
  for (let i = 0; i < 4; i++) await settle();
};

interface DeferApi {
  DfirPanelDefer: {
    skip(key: string, caseId: string): boolean;
    eagerOnly<T extends [string, ...unknown[]]>(entries: T[]): T[];
    flushRevealed(): void;
    reset(): void;
    panels(): Record<string, [string, string]>;
  };
  loadHostRanking(caseId: string): void;
}

interface FakeSection {
  id: string;
  dataset: Record<string, string>;
  innerHTML: string;
}

interface Answer {
  ok?: boolean;
  status?: number;
  body?: unknown;
  fail?: boolean;
}

function page(opts: { hidden?: string[]; caseId?: string; noVisibility?: boolean } = {}) {
  const vis: Record<string, boolean> = {};
  for (const id of opts.hidden ?? []) vis[id] = false;
  const revealed = new Set<string>();
  const els = new Map<string, FakeSection | { value: string }>();
  const section = (id: string): FakeSection => {
    let s = els.get(id) as FakeSection | undefined;
    if (!s) {
      s = { id, dataset: {}, innerHTML: "" };
      els.set(id, s);
    }
    return s;
  };
  const caseEl = { value: opts.caseId ?? "CASE-A" };
  els.set("caseId", caseEl);
  // Every request the page makes, with a hand on when it answers.
  const requests: { url: string; answer(a?: Answer): void }[] = [];
  const fetch = (url: string) =>
    new Promise((resolve, reject) => {
      requests.push({
        url,
        answer: (a: Answer = {}) => {
          if (a.fail) return reject(new Error("offline"));
          const ok = a.ok ?? true;
          resolve({ ok, status: a.status ?? (ok ? 200 : 500), json: async () => a.body ?? {} });
        },
      });
    });
  // A stand-in for js/case-load-progress.js's reloader: it runs the loader only for the case on
  // screen, which is the guard the real one applies after a retire.
  const reloads: string[] = [];
  let onScreen: string | undefined;
  const DfirCaseLoadProgress = {
    runPanelReload: (key: string, caseId: string, run: () => void) => {
      reloads.push(key);
      if (onScreen !== undefined && caseId !== onScreen) return;
      run();
    },
  };
  // Two synthetic loaders that use the real guard: one panel with two independent requests, and a
  // second panel that shares its section (as attack mitigations and D3FEND share sec-d3fend).
  const paints: string[] = [];
  // The sandbox itself, once loaded: the tracked reveal load patches ITS fetch, as the browser's.
  let sb: Record<string, unknown> = {};
  const globals: Record<string, unknown> = {
    document: {
      getElementById: (id: string) => (id.startsWith("sec-") ? section(id) : (els.get(id) ?? section(id))),
    },
    fetch,
    setTimeout: (fn: () => void, ms: number) => globalThis.setTimeout(fn, ms),
    clearTimeout: (t: unknown) => globalThis.clearTimeout(t as number),
    DfirCaseLoadProgress,
    loadCloudCoverage(caseId: string) {
      const self = sb as unknown as DeferApi;
      if (self.DfirPanelDefer.skip("cloudCoverage", caseId)) return;
      const f = sb.fetch as (u: string) => Promise<{ json(): Promise<unknown> }>;
      f(`/cases/${caseId}/cloud-coverage`)
        .then((r) => r.json())
        .then(() => paints.push(`coverage:${caseId}`))
        .catch(() => {});
      f(`/cases/${caseId}/cloud-weaknesses`)
        .then((r) => r.json())
        .then(() => paints.push(`weak:${caseId}`))
        .catch(() => {});
    },
    loadD3fend(caseId: string) {
      const self = sb as unknown as DeferApi;
      if (self.DfirPanelDefer.skip("d3fend", caseId)) return;
      const f = sb.fetch as (u: string) => Promise<{ json(): Promise<unknown> }>;
      f(`/cases/${caseId}/d3fend-countermeasures`)
        .then((r) => r.json())
        .then(() => paints.push(`d3fend:${caseId}`))
        .catch(() => {});
    },
    loadAttackMitigations(caseId: string) {
      const self = sb as unknown as DeferApi;
      if (self.DfirPanelDefer.skip("attackMitigations", caseId)) return;
      const f = sb.fetch as (u: string) => Promise<{ json(): Promise<unknown> }>;
      f(`/cases/${caseId}/attack-mitigations`)
        .then((r) => r.json())
        .then(() => paints.push(`mitigations:${caseId}`))
        .catch(() => {});
    },
  };
  if (!opts.noVisibility) {
    Object.assign(globals, {
      loadSectionsVis: () => vis,
      isSectionVisible: (id: string, v: Record<string, boolean>) => v[id] !== false,
      isSectionRevealed: (id: string) => revealed.has(id),
    });
  }
  const api = loadDashboardModule<DeferApi>(
    "dashboard-panel-defer.js",
    ["dashboard-escape.js", "dashboard-host-ranking.js"],
    globals,
  );
  sb = api as unknown as Record<string, unknown>;
  const d = api.DfirPanelDefer;
  return {
    api,
    d,
    requests,
    reloads,
    paints,
    section,
    urls: () => requests.map((r) => r.url),
    hide: (id: string) => {
      vis[id] = false;
      d.flushRevealed();
    },
    // What every reveal path ends in: the visibility changes, then applySectionsVis() runs and
    // calls flushRevealed().
    show: (id: string) => {
      vis[id] = true;
      d.flushRevealed();
    },
    paletteReveal: (id: string) => {
      revealed.add(id);
      d.flushRevealed();
    },
    // proceedConnect: #caseId changes, the reloader is retired (which resets the deferrals).
    switchCase: (id: string) => {
      caseEl.value = id;
      onScreen = id;
      d.reset();
    },
  };
}

describe("a hidden section's heavy panel is not fetched on case open (#2854)", () => {
  it("skips the hidden panel and loads the visible one", () => {
    const p = page({ hidden: ["sec-hostranking"] });
    p.api.loadHostRanking("CASE-A");
    expect(p.urls()).toEqual([]);
    p.show("sec-hostranking");
    expect(p.urls()).toEqual(["/cases/CASE-A/host-ranking"]);
  });

  it("a visible panel loads exactly as before", () => {
    const p = page();
    p.api.loadHostRanking("CASE-A");
    expect(p.urls()).toEqual(["/cases/CASE-A/host-ranking"]);
  });

  it("fails open: without the section-visibility functions every panel loads", () => {
    const p = page({ hidden: ["sec-hostranking"], noVisibility: true });
    p.api.loadHostRanking("CASE-A");
    expect(p.urls()).toEqual(["/cases/CASE-A/host-ranking"]);
  });

  it("eagerOnly drops the hidden deferred entries so the strip counts only real loads", () => {
    const p = page({ hidden: ["sec-hostranking", "sec-geomap"] });
    const ran: string[] = [];
    const entries: [string, () => void][] = [
      ["custody", () => ran.push("custody")],
      ["hostRanking", () => ran.push("hostRanking")],
      ["geoMap", () => ran.push("geoMap")],
      ["d3fend", () => ran.push("d3fend")],
    ];
    const kept = p.d.eagerOnly(entries);
    expect(kept.map(([k]) => k)).toEqual(["custody", "d3fend"]);
    const tally = runPanelLoaders(kept, null);
    expect(tally.total).toBe(2);
    expect(tally.settled.size).toBe(2);
    // ...and the dropped ones load when their section is shown.
    p.show("sec-hostranking");
    expect(p.urls()).toEqual(["/cases/CASE-A/host-ranking"]);
  });

  it("a loader that the guard skips issues no request, so a run settles it at once", () => {
    const p = page({ hidden: ["sec-hostranking"] });
    const tally = runPanelLoaders([["hostRanking", () => p.api.loadHostRanking("CASE-A")]], null);
    expect(tally.settled.has("hostRanking")).toBe(true);
    expect(p.urls()).toEqual([]);
  });
});

describe("revealing a section loads it once (#2854)", () => {
  it("through the palette's in-memory reveal", () => {
    const p = page({ hidden: ["sec-hostranking"] });
    p.api.loadHostRanking("CASE-A");
    p.paletteReveal("sec-hostranking");
    expect(p.urls()).toEqual(["/cases/CASE-A/host-ranking"]);
    expect(p.reloads).toEqual(["hostRanking"]); // through the page's shared request cap
  });

  it("several live pushes while hidden give one load on reveal, and a second reveal none", () => {
    const p = page({ hidden: ["sec-hostranking"] });
    for (let i = 0; i < 3; i++) p.api.loadHostRanking("CASE-A");
    p.show("sec-hostranking");
    p.hide("sec-hostranking");
    p.show("sec-hostranking");
    expect(p.urls()).toEqual(["/cases/CASE-A/host-ranking"]);
  });

  it("a direct load after the section became visible supersedes the queued reveal", () => {
    const p = page({ hidden: ["sec-hostranking"] });
    p.api.loadHostRanking("CASE-A");
    // Visible again, but applySectionsVis has not run yet; a direct call (a refresh) loads it.
    (p.api as unknown as { loadSectionsVis(): Record<string, boolean> }).loadSectionsVis()[
      "sec-hostranking"
    ] = true;
    p.api.loadHostRanking("CASE-A");
    p.d.flushRevealed();
    expect(p.urls()).toEqual(["/cases/CASE-A/host-ranking"]);
  });

  it("flushRevealed with nothing pending does nothing (it runs on every render)", () => {
    const p = page();
    p.d.flushRevealed();
    expect(p.reloads).toEqual([]);
  });
});

describe("a case switch while a panel is deferred (#2854)", () => {
  it("drops the old case's pending load; the reveal loads the case on screen", () => {
    const p = page({ hidden: ["sec-hostranking"] });
    p.api.loadHostRanking("CASE-A");
    p.switchCase("CASE-B");
    p.show("sec-hostranking");
    expect(p.urls()).toEqual([]); // nothing was pending for B yet
    p.hide("sec-hostranking");
    p.api.loadHostRanking("CASE-B");
    p.show("sec-hostranking");
    expect(p.urls()).toEqual(["/cases/CASE-B/host-ranking"]);
  });

  it("a cancelled load (no case on screen) loads nothing on reveal", () => {
    const p = page({ hidden: ["sec-hostranking"] });
    p.api.loadHostRanking("CASE-A");
    p.switchCase("");
    p.show("sec-hostranking");
    expect(p.urls()).toEqual([]);
  });
});

describe("a revealed panel never shows the previous case's content (#2854)", () => {
  async function loadedForA(hidden: string[] = []) {
    const p = page({ hidden });
    p.api.loadHostRanking("CASE-A");
    p.requests[0].answer({ body: { ranks: [] } });
    await flushAll();
    return p;
  }

  it("masks a hidden panel loaded for another case, and unmasks when this case's answer has painted", async () => {
    const p = await loadedForA();
    p.switchCase("CASE-B");
    p.hide("sec-hostranking");
    p.api.loadHostRanking("CASE-B");
    const sec = p.section("sec-hostranking");
    expect(sec.dataset.panelStale).toMatch(/Loading/);
    p.show("sec-hostranking");
    expect(sec.dataset.panelStale).toMatch(/Loading/); // the request is out, nothing painted yet
    p.requests[1].answer({ body: { ranks: [] } });
    await flushAll();
    expect(sec.dataset.panelStale).toBeUndefined();
  });

  it("does not mask a panel that was never loaded on this page", () => {
    const p = page({ hidden: ["sec-hostranking"] });
    p.api.loadHostRanking("CASE-A");
    expect(p.section("sec-hostranking").dataset.panelStale).toBeUndefined();
  });

  it("keeps the mask, with a failure line, when this case's load fails", async () => {
    const p = await loadedForA();
    p.switchCase("CASE-B");
    p.hide("sec-hostranking");
    p.api.loadHostRanking("CASE-B");
    p.show("sec-hostranking");
    p.requests[1].answer({ ok: false, status: 503 });
    await flushAll();
    expect(p.section("sec-hostranking").dataset.panelStale).toMatch(/could not be loaded/);
  });

  it("a 501 is an answer (the route is not configured), not a failure", async () => {
    const p = await loadedForA();
    p.switchCase("CASE-B");
    p.hide("sec-hostranking");
    p.api.loadHostRanking("CASE-B");
    p.show("sec-hostranking");
    p.requests[1].answer({ ok: false, status: 501 });
    await flushAll();
    expect(p.section("sec-hostranking").dataset.panelStale).toBeUndefined();
  });

  it("a later push after a failed reveal retries through a tracked load and can clear the mask", async () => {
    const p = await loadedForA();
    p.switchCase("CASE-B");
    p.hide("sec-hostranking");
    p.api.loadHostRanking("CASE-B");
    p.show("sec-hostranking");
    p.requests[1].answer({ fail: true });
    await flushAll();
    p.api.loadHostRanking("CASE-B"); // visible, masked: becomes a tracked load
    await flushAll();
    expect(p.urls()).toEqual([
      "/cases/CASE-A/host-ranking",
      "/cases/CASE-B/host-ranking",
      "/cases/CASE-B/host-ranking",
    ]);
    p.requests[2].answer({ body: { ranks: [] } });
    await flushAll();
    expect(p.section("sec-hostranking").dataset.panelStale).toBeUndefined();
  });

  it("waits for EVERY request of the section: two fetches in one panel, two panels in one section", async () => {
    const p = page();
    p.api.DfirPanelDefer.skip("cloudCoverage", "CASE-A"); // marks it loaded on this page
    (p.api as unknown as { loadCloudCoverage(c: string): void }).loadCloudCoverage("CASE-A");
    (p.api as unknown as { loadD3fend(c: string): void }).loadD3fend("CASE-A");
    (p.api as unknown as { loadAttackMitigations(c: string): void }).loadAttackMitigations("CASE-A");
    for (const r of p.requests) r.answer();
    await flushAll();
    p.switchCase("CASE-B");
    p.hide("sec-cloud-coverage");
    p.hide("sec-d3fend");
    const a = p.api as unknown as {
      loadCloudCoverage(c: string): void;
      loadD3fend(c: string): void;
      loadAttackMitigations(c: string): void;
    };
    a.loadCloudCoverage("CASE-B");
    a.loadD3fend("CASE-B");
    a.loadAttackMitigations("CASE-B");
    p.show("sec-cloud-coverage");
    p.show("sec-d3fend");
    const fresh = p.requests.slice(4);
    expect(fresh.map((r) => r.url)).toEqual([
      "/cases/CASE-B/cloud-coverage",
      "/cases/CASE-B/cloud-weaknesses",
      "/cases/CASE-B/d3fend-countermeasures",
      "/cases/CASE-B/attack-mitigations",
    ]);
    fresh[0].answer();
    fresh[2].answer();
    await flushAll();
    expect(p.section("sec-cloud-coverage").dataset.panelStale).toMatch(/Loading/);
    expect(p.section("sec-d3fend").dataset.panelStale).toMatch(/Loading/);
    fresh[1].answer();
    fresh[3].answer();
    await flushAll();
    expect(p.section("sec-cloud-coverage").dataset.panelStale).toBeUndefined();
    expect(p.section("sec-d3fend").dataset.panelStale).toBeUndefined();
  });

  it("two panels of one section retrying on separate timers: one success does not unmask over a failure", async () => {
    const p = page();
    const a = p.api as unknown as { loadD3fend(c: string): void; loadAttackMitigations(c: string): void };
    a.loadD3fend("CASE-A");
    a.loadAttackMitigations("CASE-A");
    for (const r of p.requests) r.answer();
    await flushAll();
    p.switchCase("CASE-B");
    p.hide("sec-d3fend");
    a.loadD3fend("CASE-B");
    a.loadAttackMitigations("CASE-B");
    p.show("sec-d3fend");
    p.requests[2].answer({ fail: true });
    p.requests[3].answer({ fail: true });
    await flushAll();
    expect(p.section("sec-d3fend").dataset.panelStale).toMatch(/could not be loaded/);
    // The two debounced reloads fire separately, each becoming its own tracked load.
    a.loadD3fend("CASE-B");
    await flushAll();
    a.loadAttackMitigations("CASE-B");
    await flushAll();
    expect(p.urls().slice(4)).toEqual([
      "/cases/CASE-B/d3fend-countermeasures",
      "/cases/CASE-B/attack-mitigations",
    ]);
    p.requests[5].answer(); // mitigations: fine
    p.requests[4].answer({ fail: true }); // D3FEND: still failing, A's countermeasures still drawn
    await flushAll();
    expect(p.section("sec-d3fend").dataset.panelStale).toMatch(/could not be loaded/);
    a.loadD3fend("CASE-B");
    await flushAll();
    p.requests[6].answer();
    await flushAll();
    expect(p.section("sec-d3fend").dataset.panelStale).toBeUndefined();
  });

  it("an answer for a case the analyst has left neither paints nor unmasks", async () => {
    const p = await loadedForA();
    p.switchCase("CASE-B");
    p.hide("sec-hostranking");
    p.api.loadHostRanking("CASE-B");
    p.show("sec-hostranking");
    p.switchCase("CASE-C"); // B's reveal load is still out
    p.requests[1].answer({ body: { ranks: [] } });
    await flushAll();
    expect(p.section("sec-hostranking").dataset.panelStale).toMatch(/Loading/);
  });

  it("an untracked load for another case forgets the owner, so going back masks again", async () => {
    const p = await loadedForA(); // A loaded, visible, untracked
    p.switchCase("CASE-B");
    p.hide("sec-hostranking");
    p.api.loadHostRanking("CASE-B");
    p.show("sec-hostranking");
    p.requests[1].answer({ body: { ranks: [] } });
    await flushAll(); // B owns it now (tracked success)
    p.switchCase("CASE-C");
    p.api.loadHostRanking("CASE-C"); // visible, untracked: C's content, owner unknown
    p.switchCase("CASE-B");
    p.hide("sec-hostranking");
    p.api.loadHostRanking("CASE-B");
    expect(p.section("sec-hostranking").dataset.panelStale).toMatch(/Loading/);
  });
});

// ── source pins: the wiring that the behaviour above depends on ────────────────────────────────
const GUARD = (key: string) =>
  new RegExp(
    `typeof DfirPanelDefer !== "undefined" && DfirPanelDefer\\.skip\\("${key}", caseId\\)\\) return;`,
  );

describe("the deferral is wired into every deferred loader and every reveal path (#2854)", () => {
  const p = page();
  const panels = p.d.panels();

  it.each(Object.entries(panels))("%s's loader carries the guard", (key, [, loader]) => {
    const file = readdirJs().find((f) => new RegExp(`function ${loader}\\(`).test(read(f)));
    expect(file, loader).toBeTruthy();
    const src = read(file!);
    const start = src.search(new RegExp(`function ${loader}\\(`));
    const body = src.slice(start, start + 2500);
    expect(body).toMatch(GUARD(key));
  });

  it("every deferred key is a case-open loader with the same loader name", () => {
    const connect = read("dashboard-case-connect.js");
    for (const [key, [, loader]] of Object.entries(panels)) {
      expect(connect, key).toMatch(new RegExp(`\\["${key}", \\(\\) => ${loader}\\(caseId\\)\\]`));
    }
  });

  it("the eager loaders stay eager (their data or cleanup is used outside their section)", () => {
    for (const key of [
      "cockpit",
      "assetGraph",
      "iocProvenance",
      "iocRisk",
      "iocSources",
      "iocProvenanceChains",
      "hypotheses",
      "secondLook",
      "hostDuplicates",
      "superTimeline",
    ]) {
      expect(panels[key], key).toBeUndefined();
    }
  });

  it("the case-open fan-out passes through eagerOnly, and a retire resets the deferrals", () => {
    expect(read("dashboard-case-connect.js")).toMatch(
      /DfirPanelDefer \|\| \{ eagerOnly: \(l\) => l \}\)\.eagerOnly\(CASE_PANEL_LOADERS\)/,
    );
    expect(read("case-load-progress.js")).toMatch(/DfirPanelDefer\.reset\(\)/);
  });

  it("applySectionsVis ends by flushing revealed panels, and the reveal set is readable", () => {
    const src = read("dashboard-section-order.js");
    const body = src.slice(
      src.indexOf("function applySectionsVis("),
      src.indexOf("function renderSecChecks("),
    );
    expect(body).toMatch(/DfirPanelDefer\.flushRevealed\(\)/);
    expect(src).toMatch(/window\.isSectionRevealed = /);
  });

  it("the two gap jumps reveal their section instead of scrolling to a hidden one", () => {
    const src = read("dashboard-data-act.js");
    expect(src).toMatch(/revealSection\("sec-gaps"\)/);
    expect(src).toMatch(/revealSection\("sec-evidence-gaps"\)/);
  });
});

function readdirJs(): string[] {
  return readdirSync(JS).filter((f) => f.endsWith(".js"));
}
