// "Story so far" in the Now cockpit (#1487): one card per kill-chain stage, the freshness tag and the
// two-sentence conclusion the server derives from the forensic timeline, rendered above the
// workspaces row. #1493 adds the shape strip (span, dwell, hosts, accounts), the missing-stage
// cards interleaved in kill-chain order, and "Copy as brief".
//
// Runs js/dashboard-cockpit.js with js/dashboard-cockpit-story.js (the rendering half, split out in
// #1493) in the vm harness with a fake `document`, a fake `fetch` and the page globals they read by
// bare name, so these assertions are about the markup the browser gets — not a string grep of the
// source. renderCockpit is private to the module, so each render goes through loadCockpit, which
// is the path the browser takes too.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { STORY_STAGE_ORDER } from "../../src/analysis/cockpitStory.js";
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
interface Shape {
  firstAt: string | null;
  lastAt: string | null;
  dwellMs: number | null;
  hosts: string[];
  hostsTotal: number;
  accounts: string[];
  accountsTotal: number;
}
interface Story {
  stages: Stage[];
  conclusion: string;
  attackerPath: string;
  synthesizedAt: string | null;
  staleEventCount: number;
  // Optional: a snapshot from a server older than #1493 has neither.
  shape?: Shape;
  missingStages?: string[];
  // Optional: a snapshot from a server older than #1599 has none.
  conclusionsOutOfDate?: boolean;
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
  cockpitStoryCopy(el: { nextElementSibling: FakeEl | null }): Promise<void>;
}

const NOW = new Date("2026-06-10T12:00:00Z");

function shape(over: Partial<Shape> = {}): Shape {
  return {
    firstAt: "2026-06-10T03:12:00Z",
    lastAt: "2026-06-10T09:40:00Z",
    dwellMs: 6 * 3_600_000 + 28 * 60_000,
    hosts: ["WS-01", "DC-01"],
    hostsTotal: 2,
    accounts: ["CORP\\jsmith"],
    accountsTotal: 1,
    ...over,
  };
}

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
    shape: shape(),
    missingStages: ["Persistence", "Impact"],
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

interface HarnessOpts {
  /** `null` = a page with no navigator.clipboard, so the textarea/execCommand path runs. */
  writeText?: ((text: string) => Promise<void>) | null;
}

function harness(opts: HarnessOpts = {}) {
  const body: FakeEl = { innerHTML: "", textContent: "" };
  const caseInput = { value: "" };
  const calls: Record<string, unknown[][]> = { filter: [], view: [], reveal: [], finding: [] };
  const copied: string[] = [];
  const timers: Array<() => void> = [];
  const textarea = { value: "", select: vi.fn(), remove: vi.fn() };
  const writeText =
    opts.writeText === undefined
      ? async (text: string) => {
          copied.push(text);
        }
      : opts.writeText;
  let next: Snapshot | null = null;
  const api = loadDashboardModule<Api>(
    "dashboard-cockpit.js",
    ["dashboard-escape.js", "dashboard-time.js", "dashboard-fragments.js", "dashboard-cockpit-story.js"],
    {
      lastCockpit: null,
      lastCockpitRenderSignature: "",
      document: {
        getElementById: (id: string) => (id === "cockpitBody" ? body : id === "caseId" ? caseInput : null),
        createElement: () => textarea,
        body: { appendChild: vi.fn() },
        execCommand: () => {
          copied.push(textarea.value);
          return true;
        },
      },
      navigator: writeText ? { clipboard: { writeText } } : {},
      investigatorName: () => "",
      fetch: async () => ({ ok: true, json: async () => next }),
      // The page's own globals the module resolves at call time. `setTimeout` is not an ECMAScript
      // built-in, so the sandbox has none; a synchronous one keeps the reveal assertion simple,
      // and a delayed one (the copy message's 2 s) is parked so the test can fire it.
      setTimeout: (fn: () => void, ms?: number) => (ms ? timers.push(fn) : fn()),
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
    copied,
    timers,
    textarea,
    /** Serve `snap` from the fake endpoint and paint it, the way the page does. */
    render: async (snap: Snapshot) => {
      next = snap;
      caseInput.value = snap.caseId;
      await api.loadCockpit(snap.caseId);
    },
    /** Click "Copy as brief" and hand back the message span the button's sibling holds. */
    copy: async () => {
      const msg: FakeEl = { innerHTML: "", textContent: "" };
      await api.cockpitStoryCopy({ nextElementSibling: msg });
      return msg;
    },
  };
}

/** The class-marked names in render order, so a test can tell a real card from a missing one. */
function stageNames(html: string): Array<[string, string]> {
  return [...html.matchAll(/<(button|span)[^>]*class="now-stage-name">([^<]+)</g)].map((m) => [m[1], m[2]]);
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

describe("cockpit story — stage cards", () => {
  it("renders one card per stage in server order, above the workspaces row, with no arrows", async () => {
    const h = harness();
    await h.render(snapshot({ story: story({ missingStages: [] }) }));
    const html = h.body.innerHTML;
    expect(stageNames(html)).toEqual([
      ["button", "Initial Access"],
      ["button", "Execution"],
      ["button", "Lateral Movement"],
    ]);
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

  // #1599: a dismissed finding or a new scope window starts no synthesis and adds no rows.
  it("flags a synthesis the case has moved past without new rows", async () => {
    const h = harness();
    await h.render(snapshot({ story: story({ staleEventCount: 0, conclusionsOutOfDate: true }) }));
    expect(h.body.innerHTML).toContain(
      '<span class="now-story-fresh now-story-stale">stale — conclusions out of date</span>',
    );
  });

  it("replaces the text with the no-synthesis hint when nothing has run yet", async () => {
    const h = harness();
    await h.render(snapshot({ story: story({ synthesizedAt: null, conclusion: "", attackerPath: "" }) }));
    const html = h.body.innerHTML;
    expect(html).toContain('<span class="now-story-fresh">no synthesis yet</span>');
    expect(html).toContain("No synthesis yet — the conclusion appears after the first analysis run.");
    // The prose links go with the prose; the missing cards' Evidence-gaps link is not synthesis.
    expect(html).not.toContain('data-panel="attack-path"');
    expect(html).not.toContain('data-panel="summary"');
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

describe("cockpit story — shape strip (#1493)", () => {
  it("sits between the head and the cards: span, dwell, hosts in touch order, accounts", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const html = h.body.innerHTML;
    const strip =
      '<div class="now-story-shape">' +
      '<span class="now-shape-item"><b>03:12</b> → <b>09:40</b> · dwell <b>6h 28m</b></span>' +
      '<span class="now-shape-item">hosts <b>WS-01</b> → <b>DC-01</b></span>' +
      '<span class="now-shape-item">accounts <b>CORP\\jsmith</b></span></div>';
    expect(html).toContain(strip);
    const head = html.indexOf('class="now-story-head"');
    const at = html.indexOf(strip);
    expect(head).toBeLessThan(at);
    expect(at).toBeLessThan(html.indexOf('class="now-story-cards"'));
  });

  it("shows (+N) only past the server's cap, on hosts and accounts independently", async () => {
    const h = harness();
    await h.render(
      snapshot({
        story: story({
          shape: shape({ hostsTotal: 5, accounts: ["a", "b"], accountsTotal: 2 }),
        }),
      }),
    );
    expect(h.body.innerHTML).toContain("hosts <b>WS-01</b> → <b>DC-01</b> (+3)</span>");
    expect(h.body.innerHTML).toContain("accounts <b>a</b>, <b>b</b></span>");
  });

  it("formats dwell as Nd Hh past a day, Hh Mm past an hour, else Mm", async () => {
    const cases: Array<[number, string]> = [
      [4 * 86_400_000 + 14 * 3_600_000 + 59 * 60_000, "4d 14h"],
      [86_400_000, "1d 0h"],
      [3 * 3_600_000 + 5 * 60_000, "3h 5m"],
      [12 * 60_000 + 59_000, "12m"],
      [0, "0m"],
    ];
    for (const [dwellMs, text] of cases) {
      const h = harness();
      await h.render(snapshot({ story: story({ shape: shape({ dwellMs }) }) }));
      expect(h.body.innerHTML, String(dwellMs)).toContain(`· dwell <b>${text}</b></span>`);
    }
  });

  it("names the day on the strip AND the cards once the span leaves the cards' day", async () => {
    const h = harness();
    await h.render(
      snapshot({
        story: story({
          shape: shape({ lastAt: "2026-06-11T05:40:00Z", dwellMs: 26 * 3_600_000 + 28 * 60_000 }),
        }),
      }),
    );
    const html = h.body.innerHTML;
    expect(html).toContain("<b>06-10 03:12</b> → <b>06-11 05:40</b> · dwell <b>1d 2h</b>");
    expect(html).toContain('<div class="now-stage-when">06-10 03:12 · WS-01</div>');
  });

  it("omits the hosts item, the accounts item and the dwell when each is empty", async () => {
    const h = harness();
    await h.render(
      snapshot({
        story: story({
          shape: shape({ hosts: [], hostsTotal: 0, accounts: [], accountsTotal: 0, dwellMs: null }),
        }),
      }),
    );
    const html = h.body.innerHTML;
    expect(html).toContain(
      '<div class="now-story-shape"><span class="now-shape-item"><b>03:12</b> → <b>09:40</b></span></div>',
    );
    expect(html).not.toContain("hosts ");
    expect(html).not.toContain("accounts ");
  });

  it("omits the whole strip when firstAt is null, and on a story without a shape", async () => {
    const h = harness();
    await h.render(
      snapshot({ story: story({ shape: shape({ firstAt: null, lastAt: null, dwellMs: null }) }) }),
    );
    expect(h.body.innerHTML).not.toContain("now-story-shape");
    const old = story();
    delete old.shape;
    delete old.missingStages;
    await h.render(snapshot({ caseId: "CASE-OLD", story: old }));
    expect(h.body.innerHTML).not.toContain("now-story-shape");
    expect(h.body.innerHTML).not.toContain("now-stage-missing");
    expect(h.body.innerHTML.match(/class="now-stage-card sev-/g)).toHaveLength(3);
  });

  it("escapes hostile hosts and accounts", async () => {
    const h = harness();
    const hostile = `<img src=x onerror=alert(1)>`;
    await h.render(snapshot({ story: story({ shape: shape({ hosts: [hostile], accounts: [hostile] }) }) }));
    expect(h.body.innerHTML).not.toContain("<img");
    expect(h.body.innerHTML).toContain("hosts <b>&lt;img src=x onerror=alert(1)&gt;</b>");
  });
});

describe("cockpit story — missing-stage cards (#1493)", () => {
  it("interleaves a missing card in kill-chain order among the real ones", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const html = h.body.innerHTML;
    expect(stageNames(html)).toEqual([
      ["button", "Initial Access"],
      ["button", "Execution"],
      ["span", "Persistence"],
      ["button", "Lateral Movement"],
      ["span", "Impact"],
    ]);
    expect(html).toContain(
      '<div class="now-stage-card now-stage-missing"><div class="now-stage-card-head">' +
        '<span class="now-stage-name">Persistence</span></div>' +
        '<div class="now-stage-nofinding">no evidence yet · ' +
        '<button data-act="cockpitStoryOpen" data-panel="evidence-gaps">Evidence gaps ↗</button></div></div>',
    );
    // The real cards are untouched: same count, same severity colours.
    expect(html.match(/class="now-stage-card sev-/g)).toHaveLength(3);
  });

  it("follows the server's STORY_STAGE_ORDER for the whole chain", async () => {
    const h = harness();
    const stages = [stage({ tactic: "Discovery" }), stage({ tactic: "Initial Access" })];
    const missingStages = STORY_STAGE_ORDER.filter((t) => t !== "Discovery" && t !== "Initial Access");
    await h.render(snapshot({ story: story({ stages, missingStages }) }));
    expect(stageNames(h.body.innerHTML).map((n) => n[1])).toEqual([...STORY_STAGE_ORDER]);
    expect(h.body.innerHTML.match(/now-stage-missing/g)).toHaveLength(10);
  });

  it("paints no missing card when there is no real stage at all", async () => {
    const h = harness();
    await h.render(snapshot({ story: story({ stages: [], missingStages: [...STORY_STAGE_ORDER] }) }));
    expect(h.body.innerHTML).toContain("No staged activity yet — import evidence to build the chain.");
    expect(h.body.innerHTML).not.toContain("now-stage-missing");
  });

  it("the Evidence gaps link opens that panel through the shared table", async () => {
    const h = harness();
    h.api.cockpitStoryOpen({ dataset: { panel: "evidence-gaps" } });
    expect(h.calls.view.map((c) => (c[0] as { id: string }).id)).toEqual(["lead"]);
    expect(h.calls.reveal).toEqual([["sec-evidence-gaps"]]);
  });

  it("escapes a hostile missing-stage name", async () => {
    const h = harness();
    await h.render(snapshot({ story: story({ missingStages: ["<b>x</b>"] }) }));
    expect(h.body.innerHTML).toContain('<span class="now-stage-name">&lt;b&gt;x&lt;/b&gt;</span>');
  });
});

describe("cockpit story — copy as brief (#1493)", () => {
  const BRIEF = [
    "Story so far — CASE-1 (synthesis 2026-06-10 11:46 UTC)",
    "Span: 2026-06-10 03:12 → 2026-06-10 09:40 UTC (dwell 6h 28m) · hosts: WS-01 → DC-01 · accounts: CORP\\jsmith",
    "",
    "1. Initial Access — 2026-06-10 03:12 UTC · WS-01 · 4 events",
    "   Event: Spear-phishing email with macro-enabled Invoice_Q2.xlsm",
    "   Finding: [Critical] Phishing delivered Cobalt Strike stager",
    "2. Execution — 2026-06-10 03:15 UTC · 1 event",
    "   Event: Excel spawned powershell.exe -enc (T1059.001)",
    "   Finding: [High] Macro-launched PowerShell stager",
    "3. Lateral Movement — 2026-06-10 09:40 UTC · DC-01 · 12 events",
    "No evidence yet: Persistence, Impact",
    "",
    "Conclusion: The host was compromised through a phishing macro. The actor moved to the DC.",
    "Attacker path: Macro launched PowerShell. PowerShell staged a beacon.",
  ].join("\n");

  it("puts the button in the head with its message span beside it", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const head = h.body.innerHTML.split('class="now-story-shape"')[0];
    expect(head).toContain(
      '<button data-act="cockpitStoryCopy" class="now-story-copy">⧉ Copy as brief</button>' +
        '<span class="now-story-copy-msg"></span></div>',
    );
  });

  it("copies the exact brief and says so for two seconds", async () => {
    const h = harness();
    await h.render(snapshot({ story: story() }));
    const msg = await h.copy();
    expect(h.copied).toEqual([BRIEF]);
    expect(msg.textContent).toBe("copied");
    expect(h.timers).toHaveLength(1);
    h.timers[0]();
    expect(msg.textContent).toBe("");
  });

  it("copies raw text — no HTML escaping in the brief", async () => {
    const h = harness();
    const raw = `<b>"quoted" & 'single'</b>`;
    await h.render(snapshot({ story: story({ conclusion: raw, stages: [stage({ tactic: raw })] }) }));
    await h.copy();
    expect(h.copied[0]).toContain(`1. ${raw} — `);
    expect(h.copied[0]).toContain(`Conclusion: ${raw}`);
    expect(h.copied[0]).not.toContain("&lt;");
  });

  it("says synthesis none, names the stale count, and drops empty prose lines", async () => {
    const h = harness();
    await h.render(
      snapshot({
        story: story({ synthesizedAt: null, conclusion: "", attackerPath: "", staleEventCount: 0 }),
      }),
    );
    await h.copy();
    expect(h.copied[0].startsWith("Story so far — CASE-1 (synthesis none)\n")).toBe(true);
    expect(h.copied[0]).not.toContain("Conclusion:");
    expect(h.copied[0]).not.toContain("Attacker path:");
    await h.render(snapshot({ caseId: "CASE-2", story: story({ staleEventCount: 312 }) }));
    await h.copy();
    expect(h.copied[1]).toContain(
      "Story so far — CASE-2 (synthesis 2026-06-10 11:46 UTC; stale — 312 events since synthesis)",
    );
  });

  it("writes the empty-chain hint and no span line when the story has no stages or shape", async () => {
    const h = harness();
    const bare = story({ stages: [], missingStages: [...STORY_STAGE_ORDER] });
    delete bare.shape;
    await h.render(snapshot({ story: bare }));
    await h.copy();
    expect(h.copied[0]).toBe(
      "Story so far — CASE-1 (synthesis 2026-06-10 11:46 UTC)\n\n" +
        "No staged activity yet — import evidence to build the chain.\n\n" +
        "Conclusion: The host was compromised through a phishing macro. The actor moved to the DC.\n" +
        "Attacker path: Macro launched PowerShell. PowerShell staged a beacon.",
    );
    expect(h.copied[0]).not.toContain("No evidence yet");
  });

  it("reports a clipboard failure instead of claiming a copy", async () => {
    const h = harness({ writeText: async () => Promise.reject(new Error("denied")) });
    await h.render(snapshot({ story: story() }));
    const msg = await h.copy();
    expect(msg.textContent).toBe("copy failed — select & copy manually");
    expect(h.copied).toEqual([]);
  });

  it("falls back to the textarea/execCommand path when navigator.clipboard is missing", async () => {
    const h = harness({ writeText: null });
    await h.render(snapshot({ story: story() }));
    const msg = await h.copy();
    expect(h.copied).toEqual([BRIEF]);
    expect(h.textarea.select).toHaveBeenCalledTimes(1);
    expect(h.textarea.remove).toHaveBeenCalledTimes(1);
    expect(msg.textContent).toBe("copied");
  });

  it("does nothing before a story has loaded", async () => {
    const h = harness();
    const msg = await h.copy();
    expect(h.copied).toEqual([]);
    expect(msg.textContent).toBe("");
  });
});

describe("cockpit story — wiring", () => {
  const read = (file: string) => readFileSync(new URL(`../../../public/js/${file}`, import.meta.url), "utf8");

  it("dispatches all four handlers through ACTIONS", async () => {
    const src = read("dashboard-data-act.js");
    expect(src).toContain("cockpitStoryStage: (el) => cockpitStoryStage(el),");
    expect(src).toContain("cockpitStoryOpen: (el) => cockpitStoryOpen(el),");
    expect(src).toContain("cockpitStoryFinding: (el) => cockpitStoryFinding(el),");
    expect(src).toContain("cockpitStoryCopy: (el) => cockpitStoryCopy(el),");
  });

  it("stubs all four handlers in the facade so a failed module load cannot throw on click", async () => {
    const src = read("dashboard-facade.js");
    expect(src).toContain('"cockpitStoryCopy",');
    expect(src).toContain('"cockpitStoryFinding",');
    expect(src).toContain('"cockpitStoryOpen",');
    expect(src).toContain('"cockpitStoryStage",');
  });

  it("publishes the renderer and the copy handler from the story module, tagged before the cockpit", async () => {
    const src = read("dashboard-cockpit-story.js");
    expect(src).toContain("window.cockpitStoryCopy = cockpitStoryCopy;");
    expect(src).toContain("window.cockpitStoryHtml = cockpitStoryHtml;");
    const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    const tags = [...html.matchAll(/<script src="\/js\/(dashboard-cockpit[^"]*)"><\/script>/g)].map(
      (m) => m[1],
    );
    expect(tags).toEqual(["dashboard-cockpit-story.js", "dashboard-cockpit.js"]);
  });

  it("paints the rest of the cockpit when the story module is missing and the facade stubbed it", async () => {
    // The facade's stub returns undefined; without the coercion the page would print "undefined".
    const h = harness();
    (h.api as unknown as Record<string, unknown>).cockpitStoryHtml = () => undefined;
    await h.render(snapshot({ story: story() }));
    expect(h.body.innerHTML.startsWith('<div class="now-workspaces">')).toBe(true);
    expect(h.body.innerHTML).not.toContain("undefined");
  });

  it("keeps one panel table for card targets and story links", async () => {
    // The refactor's point: no second copy of the view/section lookup to drift.
    const src = read("dashboard-cockpit.js");
    expect(src.match(/"sec-attack-path"/g)).toHaveLength(1);
    expect(src).toContain("function cockpitRevealPanel(");
  });

  it("styles the story with classes only, never inline style attributes", async () => {
    const src = read("dashboard-cockpit-story.js");
    expect(src).not.toMatch(/\sstyle="/);
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
      ".now-story-copy{",
      ".now-story-copy-msg{",
      ".now-story-shape{",
      ".now-shape-item b{",
      ".now-story-cards .now-stage-missing{",
      ".now-stage-missing .now-stage-name{",
    ]) {
      expect(css).toContain(cls);
    }
    // A missing card is a dashed outline with no severity colour, dimmed.
    expect(css).toMatch(
      /\.now-story-cards \.now-stage-missing\{[^}]*border:1px dashed var\(--border-subtle\)/,
    );
    expect(css).toMatch(/\.now-story-cards \.now-stage-missing\{[^}]*opacity:\.75/);
    // The chip chain is gone for good: no dead rules left behind.
    for (const cls of [".now-story-chain{", ".now-stage{", ".now-stage-meta{", ".now-stage-arrow{"]) {
      expect(css).not.toContain(cls);
    }
  });
});
