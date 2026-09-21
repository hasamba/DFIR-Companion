// "Story so far" in the Now cockpit (#1487): the attack chain, the freshness tag and the two-sentence
// conclusion the server derives from the forensic timeline, rendered above the workspaces row.
//
// Runs js/dashboard-cockpit.js in the vm harness with a fake `document`, a fake `fetch` and the
// page globals it reads by bare name, so these assertions are about the markup the browser gets —
// not a string grep of the source. renderCockpit is private to the module, so each render goes
// through loadCockpit, which is the path the browser takes too.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Stage {
  tactic: string;
  firstSeenAt: string;
  host: string | null;
  eventCount: number;
  eventIds: string[];
}
interface Story {
  stages: Stage[];
  conclusion: string;
  attackerPath: string;
  synthesizedAt: string | null;
  staleEventCount: number;
}
interface Snapshot {
  caseId: string;
  generatedAt: string;
  phase: string;
  sections: Record<string, unknown[]>;
  parked: unknown[];
  story?: Story;
}
interface FakeEl {
  innerHTML: string;
  textContent: string;
}
interface Api {
  loadCockpit(caseId: string): Promise<void>;
  cockpitStoryStage(el: { dataset: Record<string, string> }): void;
  cockpitStoryOpen(el: { dataset: Record<string, string> }): void;
}

const NOW = new Date("2026-06-10T12:00:00Z");

function stage(over: Partial<Stage>): Stage {
  return {
    tactic: "Execution",
    firstSeenAt: "2026-06-10T03:12:00Z",
    host: "WS-01",
    eventCount: 4,
    eventIds: ["e1", "e2"],
    ...over,
  };
}

function story(over: Partial<Story> = {}): Story {
  return {
    stages: [
      stage({ tactic: "Initial Access", firstSeenAt: "2026-06-10T03:12:00Z", host: "WS-01" }),
      stage({ tactic: "Execution", firstSeenAt: "2026-06-10T03:15:30Z", host: null, eventCount: 1 }),
      stage({
        tactic: "Lateral Movement",
        firstSeenAt: "2026-06-10T09:40:00Z",
        host: "DC-01",
        eventCount: 12,
      }),
    ],
    conclusion: "The host was compromised through a phishing macro. The actor moved to the DC.",
    attackerPath: "Macro launched PowerShell. PowerShell staged a beacon.",
    synthesizedAt: "2026-06-10T11:46:00Z",
    staleEventCount: 0,
    ...over,
  };
}

function snapshot(over: Partial<Snapshot> = {}): Snapshot {
  return {
    caseId: "CASE-1",
    generatedAt: "2026-06-10T12:00:00Z",
    phase: "triage",
    sections: {},
    parked: [],
    ...over,
  };
}

function harness() {
  const body: FakeEl = { innerHTML: "", textContent: "" };
  const caseInput = { value: "" };
  const calls: Record<string, unknown[][]> = { filter: [], view: [], reveal: [] };
  let next: Snapshot | null = null;
  const api = loadDashboardModule<Api>(
    "dashboard-cockpit.js",
    ["dashboard-escape.js", "dashboard-time.js", "dashboard-fragments.js"],
    {
      lastCockpit: null,
      lastCockpitRenderSignature: "",
      document: {
        getElementById: (id: string) => (id === "cockpitBody" ? body : id === "caseId" ? caseInput : null),
      },
      investigatorName: () => "",
      fetch: async () => ({ ok: true, json: async () => next }),
      // The page's own globals the module resolves at call time. `setTimeout` is not an ECMAScript
      // built-in, so the sandbox has none; a synchronous one keeps the reveal assertion simple.
      setTimeout: (fn: () => void) => fn(),
      DASHBOARD_VIEWS: [{ id: "lead" }, { id: "triage" }],
      applyDashboardView: (view: unknown, opts: unknown) => calls.view.push([view, opts]),
      revealSection: (id: string) => calls.reveal.push([id]),
      filterTimelineToEventIds: (ids: string[], label: string) => calls.filter.push([ids, label]),
    },
  );
  return {
    api,
    body,
    calls,
    /** Serve `snap` from the fake endpoint and paint it, the way the page does. */
    render: async (snap: Snapshot) => {
      next = snap;
      caseInput.value = snap.caseId;
      await api.loadCockpit(snap.caseId);
    },
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

describe("cockpit story — chain", () => {
  it("renders the stages in server order, above the workspaces row", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const html = h.body.innerHTML;
    const names = [...html.matchAll(/class="now-stage-name">([^<]+)</g)].map((m) => m[1]);
    expect(names).toEqual(["Initial Access", "Execution", "Lateral Movement"]);
    expect(html.indexOf('class="now-story"')).toBeLessThan(html.indexOf('class="now-workspaces"'));
    // Two arrows join three chips.
    expect(html.match(/now-stage-arrow/g)).toHaveLength(2);
  });

  it("shows HH:MM UTC when every stage sits on one day, host and count on each chip", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const html = h.body.innerHTML;
    expect(html).toContain('<span class="now-stage-meta">03:12 · WS-01 · 4 ev</span>');
    expect(html).toContain('<span class="now-stage-meta">09:40 · DC-01 · 12 ev</span>');
    // A stage with no host names no host rather than "null".
    expect(html).toContain('<span class="now-stage-meta">03:15 · 1 ev</span>');
    expect(html).not.toContain("null");
  });

  it("switches to MM-DD HH:MM once the chain spans more than one UTC day", async () => {
    const h = harness();
    const s = story();
    s.stages[2] = stage({ ...s.stages[2], firstSeenAt: "2026-06-11T00:05:00Z" });
    await h.render(snapshot({ story: s }));
    expect(h.body.innerHTML).toContain("06-10 03:12 · WS-01");
    expect(h.body.innerHTML).toContain("06-11 00:05 · DC-01");
  });

  it("carries the tactic on the chip so the click can find the stage", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    expect(h.body.innerHTML).toContain('data-act="cockpitStoryStage" data-tactic="Lateral Movement"');
  });

  it("replaces an empty chain with the import hint", async () => {
    const h = harness();
    await h.render(snapshot({ story: story({ stages: [] }) }));
    expect(h.body.innerHTML).toContain("No staged activity yet — import evidence to build the chain.");
    expect(h.body.innerHTML).not.toContain("now-stage-name");
  });
});

describe("cockpit story — freshness and text", () => {
  it("says when the synthesis ran and shows both prose lines with their links", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const html = h.body.innerHTML;
    expect(html).toContain('<span class="now-story-fresh">synthesis 14m ago</span>');
    expect(html).not.toContain("now-story-stale");
    expect(html).toContain(
      "<p>The host was compromised through a phishing macro. The actor moved to the DC.</p>",
    );
    expect(html).toContain("Macro launched PowerShell. PowerShell staged a beacon.");
    expect(html).toContain('data-act="cockpitStoryOpen" data-panel="attack-path"');
    expect(html).toContain('data-act="cockpitStoryOpen" data-panel="summary"');
  });

  it("flags a stale synthesis with the count of events that arrived after it", async () => {
    const h = harness();
    await h.render(snapshot({ story: story({ staleEventCount: 312 }) }));
    expect(h.body.innerHTML).toContain(
      '<span class="now-story-fresh now-story-stale">stale — 312 events since synthesis</span>',
    );
    await h.render(snapshot({ caseId: "CASE-2", story: story({ staleEventCount: 1 }) }));
    expect(h.body.innerHTML).toContain("stale — 1 event since synthesis");
  });

  it("replaces the text with the no-synthesis hint when nothing has run yet", async () => {
    const h = harness();
    await h.render(snapshot({ story: story({ synthesizedAt: null, conclusion: "", attackerPath: "" }) }));
    const html = h.body.innerHTML;
    expect(html).toContain('<span class="now-story-fresh">no synthesis yet</span>');
    expect(html).toContain("No synthesis yet — the conclusion appears after the first analysis run.");
    expect(html).not.toContain("cockpitStoryOpen");
    // The chain still renders: the stages come from the timeline, not from the synthesis.
    expect(html).toContain("now-stage-name");
  });

  it("renders no story block at all on a snapshot from an older server", async () => {
    const h = harness();
    await h.render(snapshot());
    expect(h.body.innerHTML).not.toContain("now-story");
    expect(h.body.innerHTML).toContain('class="now-workspaces"');
  });

  it("escapes hostile strings in the tactic, host and prose", async () => {
    const h = harness();
    const hostile = `<img src=x onerror=alert(1)>" onmouseover="alert(2)'`;
    await h.render(
      snapshot({
        story: story({
          stages: [stage({ tactic: hostile, host: hostile })],
          conclusion: hostile,
          attackerPath: hostile,
        }),
      }),
    );
    const html = h.body.innerHTML;
    expect(html).not.toContain("<img");
    expect(html).toContain(
      'data-tactic="&lt;img src=x onerror=alert(1)&gt;&quot; onmouseover=&quot;alert(2)&#39;"',
    );
    expect(html).not.toContain("style=");
  });
});

describe("cockpit story — clicks", () => {
  it("a chip filters the forensic timeline to exactly that stage's events", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    h.api.cockpitStoryStage({ dataset: { tactic: "Lateral Movement" } });
    expect(h.calls.filter).toEqual([[["e1", "e2"], "Lateral Movement stage"]]);
    expect(h.calls.reveal).toEqual([["sec-timeline"]]);
  });

  it("a chip for an unknown stage does nothing", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    h.api.cockpitStoryStage({ dataset: { tactic: "Impact" } });
    expect(h.calls.filter).toEqual([]);
  });

  it("the prose links open the attack path and the executive summary through the shared panel table", async () => {
    const h = harness();
    h.api.cockpitStoryOpen({ dataset: { panel: "attack-path" } });
    h.api.cockpitStoryOpen({ dataset: { panel: "summary" } });
    expect(h.calls.view.map((c) => (c[0] as { id: string }).id)).toEqual(["lead", "lead"]);
    expect(h.calls.reveal).toEqual([["sec-attack-path"], ["sec-exec"]]);
  });
});

describe("cockpit story — wiring", () => {
  const read = (file: string) => readFileSync(new URL(`../../../public/js/${file}`, import.meta.url), "utf8");

  it("dispatches both handlers through ACTIONS", async () => {
    const src = read("dashboard-data-act.js");
    expect(src).toContain("cockpitStoryStage: (el) => cockpitStoryStage(el),");
    expect(src).toContain("cockpitStoryOpen: (el) => cockpitStoryOpen(el),");
  });

  it("stubs both handlers in the facade so a failed module load cannot throw on click", async () => {
    const src = read("dashboard-facade.js");
    expect(src).toContain('"cockpitStoryOpen",');
    expect(src).toContain('"cockpitStoryStage",');
  });

  it("keeps one panel table for card targets and story links", async () => {
    // The refactor's point: no second copy of the view/section lookup to drift.
    const src = read("dashboard-cockpit.js");
    expect(src.match(/"sec-attack-path"/g)).toHaveLength(1);
    expect(src).toContain("function cockpitRevealPanel(");
  });

  it("styles the story with classes only, never inline style attributes", async () => {
    const src = read("dashboard-cockpit.js");
    const block = src.split("function cockpitStoryHtml(")[0];
    expect(block).not.toMatch(/\sstyle="/);
    const css = readFileSync(new URL("../../../public/css/dashboard-sections.css", import.meta.url), "utf8");
    for (const cls of [
      ".now-story{",
      ".now-story-head{",
      ".now-story-stale{",
      ".now-story-chain{",
      ".now-stage{",
      ".now-stage-meta{",
      ".now-stage-arrow{",
      ".now-story-text p{",
    ]) {
      expect(css).toContain(cls);
    }
  });
});
