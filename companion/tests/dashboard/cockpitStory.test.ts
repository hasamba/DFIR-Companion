// "Story so far" in the Now cockpit (#1487): one card per kill-chain stage, the freshness tag and the
// two-sentence conclusion the server derives from the forensic timeline, rendered above the
// workspaces row.
//
// Runs js/dashboard-cockpit.js in the vm harness with a fake `document`, a fake `fetch` and the
// page globals it reads by bare name, so these assertions are about the markup the browser gets —
// not a string grep of the source. renderCockpit is private to the module, so each render goes
// through loadCockpit, which is the path the browser takes too.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
interface Headline {
  eventId: string;
  description: string;
}
interface Finding {
  id: string;
  title: string;
  severity: Severity;
}
interface Stage {
  tactic: string;
  firstSeenAt: string;
  host: string | null;
  eventCount: number;
  eventIds: string[];
  worstSeverity: Severity;
  headline: Headline | null;
  finding: Finding | null;
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
  cockpitStoryFinding(el: { dataset: Record<string, string> }): void;
}

const NOW = new Date("2026-06-10T12:00:00Z");

function stage(over: Partial<Stage>): Stage {
  return {
    tactic: "Execution",
    firstSeenAt: "2026-06-10T03:12:00Z",
    host: "WS-01",
    eventCount: 4,
    eventIds: ["e1", "e2"],
    worstSeverity: "High",
    headline: { eventId: "e1", description: "Excel spawned powershell.exe -enc (T1059.001)" },
    finding: { id: "f-2", title: "Macro-launched PowerShell stager", severity: "High" },
    ...over,
  };
}

function story(over: Partial<Story> = {}): Story {
  return {
    stages: [
      stage({
        tactic: "Initial Access",
        firstSeenAt: "2026-06-10T03:12:00Z",
        host: "WS-01",
        worstSeverity: "Critical",
        headline: { eventId: "e0", description: "Spear-phishing email with macro-enabled Invoice_Q2.xlsm" },
        finding: { id: "f-1", title: "Phishing delivered Cobalt Strike stager", severity: "Critical" },
      }),
      stage({ tactic: "Execution", firstSeenAt: "2026-06-10T03:15:30Z", host: null, eventCount: 1 }),
      stage({
        tactic: "Lateral Movement",
        firstSeenAt: "2026-06-10T09:40:00Z",
        host: "DC-01",
        eventCount: 12,
        worstSeverity: "Medium",
        headline: null,
        finding: null,
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
  const calls: Record<string, unknown[][]> = { filter: [], view: [], reveal: [], finding: [] };
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
      jumpToFinding: (id: string) => calls.finding.push([id]),
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

describe("cockpit story — stage cards", () => {
  it("renders one card per stage in server order, above the workspaces row, with no arrows", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const html = h.body.innerHTML;
    const names = [...html.matchAll(/class="now-stage-name">([^<]+)</g)].map((m) => m[1]);
    expect(names).toEqual(["Initial Access", "Execution", "Lateral Movement"]);
    expect(html.indexOf('class="now-story-cards"')).toBeLessThan(html.indexOf('class="now-workspaces"'));
    expect(html.match(/class="now-stage-card sev-/g)).toHaveLength(3);
    expect(html).not.toContain("now-stage-arrow");
    expect(html).not.toContain("now-story-chain");
  });

  it("colours each card by the stage's worst severity", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const sevs = [...h.body.innerHTML.matchAll(/class="now-stage-card sev-(\w+)"/g)].map((m) => m[1]);
    expect(sevs).toEqual(["Critical", "High", "Medium"]);
  });

  it("shows HH:MM UTC when every stage sits on one day, the host and the count on each card", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const html = h.body.innerHTML;
    expect(html).toContain('<div class="now-stage-when">03:12 · WS-01</div>');
    expect(html).toContain('<div class="now-stage-when">09:40 · DC-01</div>');
    expect(html).toContain('class="now-stage-count">4 ev ›</button>');
    expect(html).toContain('class="now-stage-count">12 ev ›</button>');
    // A stage with no host names no host rather than "null".
    expect(html).toContain('<div class="now-stage-when">03:15</div>');
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

  it("carries the tactic on both the name and the count so either click can find the stage", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const html = h.body.innerHTML;
    expect(html).toContain(
      '<button data-act="cockpitStoryStage" data-tactic="Lateral Movement" class="now-stage-name">',
    );
    expect(html).toContain(
      '<button data-act="cockpitStoryStage" data-tactic="Lateral Movement" class="now-stage-count">',
    );
  });

  it("shows the headline event in a clamped block, and omits the block when the stage has none", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const html = h.body.innerHTML;
    expect(html).toContain(
      '<div class="now-stage-headline">Spear-phishing email with macro-enabled Invoice_Q2.xlsm</div>',
    );
    expect(html.match(/now-stage-headline/g)).toHaveLength(2);
    const css = readFileSync(new URL("../../../public/css/dashboard-sections.css", import.meta.url), "utf8");
    expect(css).toMatch(/\.now-stage-headline\{[^}]*-webkit-line-clamp:2/);
  });

  it("names the top finding with its severity badge, or says no finding yet", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const html = h.body.innerHTML;
    expect(html).toContain(
      '<div class="now-stage-finding"><span class="now-sev sev-Critical">Critical</span>' +
        '<button data-act="cockpitStoryFinding" data-id="f-1">Phishing delivered Cobalt Strike stager</button></div>',
    );
    expect(
      html.match(/<div class="now-stage-finding now-stage-nofinding">no finding yet<\/div>/g),
    ).toHaveLength(1);
  });

  it("replaces an empty chain with the import hint", async () => {
    const h = harness();
    await h.render(snapshot({ story: story({ stages: [] }) }));
    expect(h.body.innerHTML).toContain("No staged activity yet — import evidence to build the chain.");
    expect(h.body.innerHTML).not.toContain("now-stage-card");
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
    // The cards still render: the stages come from the timeline, not from the synthesis.
    expect(html).toContain("now-stage-card");
  });

  it("renders no story block at all on a snapshot from an older server", async () => {
    const h = harness();
    await h.render(snapshot());
    expect(h.body.innerHTML).not.toContain("now-story");
    expect(h.body.innerHTML).toContain('class="now-workspaces"');
  });

  it("escapes hostile strings in the tactic, host, headline, finding and prose", async () => {
    const h = harness();
    const hostile = `<img src=x onerror=alert(1)>" onmouseover="alert(2)'`;
    await h.render(
      snapshot({
        story: story({
          stages: [
            stage({
              tactic: hostile,
              host: hostile,
              headline: { eventId: "e9", description: hostile },
              finding: { id: hostile, title: hostile, severity: "High" },
            }),
          ],
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
    expect(html).toContain(
      'data-id="&lt;img src=x onerror=alert(1)&gt;&quot; onmouseover=&quot;alert(2)&#39;"',
    );
    expect(html).toContain(
      '<div class="now-stage-headline">&lt;img src=x onerror=alert(1)&gt;&quot; onmouseover=&quot;alert(2)&#39;</div>',
    );
    expect(html).not.toContain("style=");
  });
});

describe("cockpit story — clicks", () => {
  it("a card filters the forensic timeline to exactly that stage's events", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    h.api.cockpitStoryStage({ dataset: { tactic: "Lateral Movement" } });
    expect(h.calls.filter).toEqual([[["e1", "e2"], "Lateral Movement stage"]]);
    expect(h.calls.reveal).toEqual([["sec-timeline"]]);
  });

  it("a card for an unknown stage does nothing", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    h.api.cockpitStoryStage({ dataset: { tactic: "Impact" } });
    expect(h.calls.filter).toEqual([]);
  });

  it("a card's finding opens the Findings panel on that finding", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    h.api.cockpitStoryFinding({ dataset: { id: "f-1" } });
    expect(h.calls.view.map((c) => (c[0] as { id: string }).id)).toEqual(["lead"]);
    expect(h.calls.reveal).toEqual([["sec-findings"]]);
    expect(h.calls.finding).toEqual([["f-1"]]);
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

  it("dispatches all three handlers through ACTIONS", async () => {
    const src = read("dashboard-data-act.js");
    expect(src).toContain("cockpitStoryStage: (el) => cockpitStoryStage(el),");
    expect(src).toContain("cockpitStoryOpen: (el) => cockpitStoryOpen(el),");
    expect(src).toContain("cockpitStoryFinding: (el) => cockpitStoryFinding(el),");
  });

  it("stubs all three handlers in the facade so a failed module load cannot throw on click", async () => {
    const src = read("dashboard-facade.js");
    expect(src).toContain('"cockpitStoryFinding",');
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
      ".now-story-cards{",
      ".now-stage-card{",
      ".now-stage-card.sev-Critical{",
      ".now-stage-card-head{",
      ".now-stage-when{",
      ".now-stage-headline{",
      ".now-stage-finding{",
      ".now-stage-nofinding{",
      ".now-sev{",
      ".now-story-text p{",
    ]) {
      expect(css).toContain(cls);
    }
    // The chip chain is gone for good: no dead rules left behind.
    for (const cls of [".now-story-chain{", ".now-stage{", ".now-stage-meta{", ".now-stage-arrow{"]) {
      expect(css).not.toContain(cls);
    }
  });
});
