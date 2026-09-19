import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  renderHostDuplicates(pending: unknown[], dismissed?: unknown[]): string;
}

const panel = loadDashboardModule<Api>("dashboard-host-duplicates.js", [
  "dashboard-escape.js",
  "dashboard-time.js",
]);

const pair = { canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" };
const netIdPair = {
  canonical: "ws-042",
  other: "10.0.0.5",
  reason: "network-identity",
  sampleTime: "2026-06-10T12:00:00Z",
};

describe("host duplicates panel", () => {
  it("renders nothing when there is no pending pair", () => {
    expect(panel.renderHostDuplicates([])).toBe("");
  });

  it("names both spellings and offers both actions", () => {
    const html = panel.renderHostDuplicates([pair]);
    expect(html).toContain("win11.windomain.local");
    expect(html).toContain("data-hd-merge");
    expect(html).toContain("data-hd-dismiss");
  });

  it("says synthesis is blocked", () => {
    expect(panel.renderHostDuplicates([pair]).toLowerCase()).toContain("analysis is on hold");
  });

  it("escapes a hostile host name", () => {
    const html = panel.renderHostDuplicates([{ ...pair, other: "<img src=x onerror=alert(1)>" }]);
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img");
  });

  it("escapes attribute-breakout characters in a hostile host name", () => {
    // A quote-free payload cannot tell escAttr from esc: escAttr is esc PLUS quote-escaping
    // (public/js/dashboard-escape.js), so a payload with no `"` or `'` passes identically either
    // way. This one carries both quote flavours, so it only stays safe if the quote-escaping half
    // actually ran on the attribute.
    const hostile = `<img src=x onerror=alert(1)>" onmouseover="alert(2)'`;
    const html = panel.renderHostDuplicates([{ ...pair, other: hostile }]);
    // Anchored to the attribute itself (`data-hd-other="`), not searched for anywhere in the page:
    // the <code> text rendering uses esc() too and correctly leaves quotes unescaped there — text
    // content needs no quote-escaping, only attribute values do — so an unanchored check would
    // find the same raw quotes in a position where they are actually safe.
    expect(html).not.toContain('data-hd-other="&lt;img src=x onerror=alert(1)&gt;" onmouseover="alert(2)');
    expect(html).toContain(
      'data-hd-other="&lt;img src=x onerror=alert(1)&gt;&quot; onmouseover=&quot;alert(2)&#39;"',
    );
  });
});

describe("host duplicates panel — network-identity rows (#1163)", () => {
  it("does not say analysis is on hold when only a network-identity suggestion is pending", () => {
    const html = panel.renderHostDuplicates([netIdPair]);
    expect(html.toLowerCase()).not.toContain("analysis is on hold");
  });

  it("still names both sides and offers both actions for a network-identity row", () => {
    const html = panel.renderHostDuplicates([netIdPair]);
    expect(html).toContain("10.0.0.5");
    expect(html).toContain("ws-042");
    expect(html).toContain("data-hd-merge");
    expect(html).toContain("data-hd-dismiss");
  });

  it("shows the blocking banner sized to the blocking subset only, in a mixed list", () => {
    const html = panel.renderHostDuplicates([pair, netIdPair]);
    expect(html.toLowerCase()).toContain("analysis is on hold");
    expect(html).toContain("1 host appears");
  });

  it("shows a separate, non-blocking intro line for network-identity suggestions", () => {
    const html = panel.renderHostDuplicates([netIdPair]);
    expect(html.toLowerCase()).toContain("possible network identity match");
  });

  it("renders no network-identity intro line when there are no such candidates", () => {
    const html = panel.renderHostDuplicates([pair]);
    expect(html.toLowerCase()).not.toContain("network identity");
  });

  it("formats the sample time with the date, not just a bare time-of-day (#1168)", () => {
    // fmtTime alone (new Date(...).toLocaleTimeString()) drops the date entirely — a binding
    // sample days/weeks/months old would read as "today". fmtDateTime (toLocaleString()) keeps it.
    const html = panel.renderHostDuplicates([netIdPair]);
    expect(html).not.toContain("2026-06-10T12:00:00Z");
    const expectedDateTime = new Date(netIdPair.sampleTime).toLocaleString();
    expect(html).toContain(expectedDateTime);
  });
});

describe("host duplicates panel — previously dismissed, per-pair undo (#1170)", () => {
  const dismissal = {
    canonical: "win11.windomain.local",
    other: "win11",
    dismissedAt: "2026-06-10T12:00:00Z",
    dismissedBy: "alice",
  };

  it("renders nothing when there is neither a pending pair nor a dismissal", () => {
    expect(panel.renderHostDuplicates([], [])).toBe("");
    expect(panel.renderHostDuplicates([])).toBe(""); // pre-#1170 single-argument call still works
  });

  it("renders the dismissed list even when nothing is pending", () => {
    const html = panel.renderHostDuplicates([], [dismissal]);
    expect(html).toContain("win11.windomain.local");
    expect(html).toContain("win11");
    expect(html.toLowerCase()).toContain("previously dismissed");
    expect(html).toContain("data-hd-undo");
  });

  it("names who dismissed it and when, using date+time not bare time-of-day", () => {
    const html = panel.renderHostDuplicates([], [dismissal]);
    expect(html).toContain("alice");
    expect(html).toContain(new Date(dismissal.dismissedAt).toLocaleString());
  });

  it("shows both the pending rows and the dismissed list together", () => {
    const html = panel.renderHostDuplicates([pair], [dismissal]);
    expect(html.toLowerCase()).toContain("analysis is on hold");
    expect(html.toLowerCase()).toContain("previously dismissed");
  });

  it("escapes a hostile analyst name in the dismissed row", () => {
    const html = panel.renderHostDuplicates(
      [],
      [{ ...dismissal, dismissedBy: "<img src=x onerror=alert(1)>" }],
    );
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img");
  });

  it("shows no 'previously dismissed' section when the dismissed list is empty", () => {
    const html = panel.renderHostDuplicates([pair], []);
    expect(html.toLowerCase()).not.toContain("previously dismissed");
  });
});

// ── Reachability (#575 follow-up) ────────────────────────────────────────────────────────────────
//
// Everything above tests the panel's HTML. None of it could catch the reported bug, which was that
// the analyst never SAW that HTML: the Now view lists its visible sections and hides every other,
// sec-host-duplicates was not on the list, and the header chip's handler called scrollIntoView on a
// display:none element — a no-op. So a held synthesis had no reachable release anywhere in the
// default view. These read the markup and the module source, because that is where the bug lived.
describe("host duplicates panel reachability", () => {
  const markup = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  const module = readFileSync(
    new URL("../../../public/js/dashboard-host-duplicates.js", import.meta.url),
    "utf8",
  );

  it("declares the section's gate closed in markup so it cannot flash before paint runs", () => {
    expect(markup).toMatch(/<section id="sec-host-duplicates" data-gate-open=""/);
  });

  it("opens the gate when a pair is pending OR a dismissal exists to review (#1170), and defers display to applySectionsVis", () => {
    expect(module).toMatch(/const hasContent = pending\.length \|\| dismissed\.length/);
    expect(module).toMatch(/gateOpen = hasContent \? "1" : ""/);
    expect(module).toMatch(/applySectionsVis\(\)/);
  });

  // The gate alone is not enough: applyViewLayout has already written `false` into SECTIONS_VIS_KEY
  // for this section on any dashboard that has ever shown the Now view, and it carries a gated
  // section's stored choice through untouched. Without this, the gate opens onto a section the
  // stored preference still hides.
  it("forces the stored visibility on while a pair is pending", () => {
    expect(module).toMatch(/SECTIONS_VIS_KEY/);
    expect(module).toMatch(/vis\["sec-host-duplicates"\] = true/);
  });

  it("puts both gate chips in the status cluster, after the AI status pill", () => {
    const ai = markup.indexOf('id="aiStatus"');
    const duplicates = markup.indexOf('id="hostDuplicatesBadge"');
    const presidio = markup.indexOf('id="presidioPendingBadge"');
    expect(ai).toBeGreaterThan(-1);
    expect(duplicates).toBeGreaterThan(ai);
    expect(presidio).toBeGreaterThan(ai);
  });
});

// ── Live behaviour (#1281, #1282, #1284) ─────────────────────────────────────────────────────────
//
// The suites above call the pure renderer. These drive the module the way the page does — a
// stubbed document, a fetch whose answers the test chooses, a confirm the test answers — because
// each of the three findings lives in a code path the renderer never touches: the delegated click
// handler, the AI-state kick after a write, and the two guarded list assignments in the loader.
interface LiveApi {
  loadHostDuplicates(caseId: string): Promise<void>;
}

interface FetchCall {
  url: string;
  method: string;
}

interface Answers {
  pendingOk?: boolean;
  dismissedOk?: boolean;
  confirm?: boolean;
  refreshAiState?: (caseId: string) => void;
}

/** A page with the panel's three elements, a chosen fetch, and the delegated click handler captured. */
function liveHarness(answers: Answers = {}) {
  const body: {
    innerHTML: string;
    dataset: Record<string, string>;
    onClick: ((evt: unknown) => void) | null;
    addEventListener: (type: string, fn: (evt: unknown) => void) => void;
  } = {
    innerHTML: "",
    dataset: {},
    onClick: null,
    addEventListener(_type, fn) {
      body.onClick = fn;
    },
  };
  const section = { dataset: {} as Record<string, string> };
  const badge = { style: { display: "" }, textContent: "" };
  const elements: Record<string, unknown> = {
    hostDuplicatesBody: body,
    "sec-host-duplicates": section,
    hostDuplicatesBadge: badge,
    caseId: { value: "case-1" },
  };
  const calls: FetchCall[] = [];
  const pendingRow = { canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" };
  const dismissedRow = { canonical: "ws-042", other: "ws42", dismissedAt: "2026-06-10T12:00:00Z" };
  const answer = (ok: boolean, payload: unknown) =>
    Promise.resolve({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(payload) });
  const globals: Record<string, unknown> = {
    document: { getElementById: (id: string) => elements[id] ?? null },
    applySectionsVis: () => {},
    SECTIONS_VIS_KEY: "sections-vis",
    confirm: () => answers.confirm ?? true,
    fetch: (url: string, init?: { method?: string }) => {
      const method = init?.method ?? "GET";
      calls.push({ url, method });
      if (method === "DELETE") return answer(true, { dismissed: [], pending: [pendingRow] });
      if (url.endsWith("/host-duplicates/dismissed"))
        return answer(answers.dismissedOk ?? true, { dismissed: [dismissedRow] });
      return answer(answers.pendingOk ?? true, { pending: [pendingRow] });
    },
  };
  if (answers.refreshAiState) globals.refreshAiState = answers.refreshAiState;
  const api = loadDashboardModule<LiveApi>(
    "dashboard-host-duplicates.js",
    ["dashboard-escape.js", "dashboard-time.js"],
    globals,
  );
  const clickUndo = () => {
    const button = {
      hasAttribute: (name: string) => name === "data-hd-undo",
      getAttribute: (name: string) => (name === "data-hd-canonical" ? "ws-042" : "ws42"),
    };
    body.onClick?.({ target: { closest: () => button } });
  };
  return { api, body, section, calls, clickUndo };
}

const settle = () => new Promise((r) => setTimeout(r, 10));

describe("host duplicates panel — undo asks first (#1281)", () => {
  it("does nothing when the analyst declines", async () => {
    const { api, calls, clickUndo } = liveHarness({ confirm: false });
    await api.loadHostDuplicates("case-1");
    calls.length = 0;
    clickUndo();
    await settle();
    expect(calls).toEqual([]);
  });

  it("names the consequence in the question and sends the DELETE when accepted", async () => {
    const module = readFileSync(
      new URL("../../../public/js/dashboard-host-duplicates.js", import.meta.url),
      "utf8",
    );
    expect(module).toContain("Reconsider this pair? They will be suggested again.");
    const { api, calls, clickUndo } = liveHarness({ confirm: true });
    await api.loadHostDuplicates("case-1");
    calls.length = 0;
    clickUndo();
    await settle();
    expect(calls).toEqual([{ url: "/cases/case-1/host-duplicates/dismiss", method: "DELETE" }]);
  });
});

describe("host duplicates panel — the AI-state kick is a guarded global (#1282)", () => {
  it("kicks the published refreshAiState with the case id after an undo", async () => {
    const kicked: string[] = [];
    const { api, clickUndo } = liveHarness({ refreshAiState: (id) => kicked.push(id) });
    await api.loadHostDuplicates("case-1");
    clickUndo();
    await settle();
    expect(kicked).toEqual(["case-1"]);
  });

  it("is a no-op, not a swallowed ReferenceError, when nothing published it", async () => {
    const { api, body, clickUndo } = liveHarness();
    await api.loadHostDuplicates("case-1");
    clickUndo();
    await settle();
    // The undo's answer was painted — the handler ran to completion with no publisher present.
    expect(body.innerHTML.toLowerCase()).not.toContain("previously dismissed");
    // And by construction: no bare-name call is left for a load-order change to break.
    const module = readFileSync(
      new URL("../../../public/js/dashboard-host-duplicates.js", import.meta.url),
      "utf8",
    );
    expect(module).not.toMatch(/^\s*refreshAiState\(/m);
    expect(module).toMatch(/window\.refreshAiState\?\.\(/);
  });
});

describe("host duplicates panel — a failed refresh is visible, not stale (#1284)", () => {
  it("shows both lists and no notice when both fetches succeed", async () => {
    const { api, body } = liveHarness();
    await api.loadHostDuplicates("case-1");
    expect(body.innerHTML).toContain("win11.windomain.local");
    expect(body.innerHTML.toLowerCase()).toContain("previously dismissed");
    expect(body.innerHTML.toLowerCase()).not.toContain("couldn't refresh");
  });

  it("empties the pending list and says so when the pending fetch fails", async () => {
    const { api, body } = liveHarness({ pendingOk: false });
    await api.loadHostDuplicates("case-1");
    expect(body.innerHTML).not.toContain("win11.windomain.local");
    expect(body.innerHTML.toLowerCase()).toContain("previously dismissed"); // the healthy list still shows
    expect(body.innerHTML.toLowerCase()).toContain("couldn't refresh");
  });

  it("clears a previously loaded list rather than keeping it after a later failure", async () => {
    const answers: Answers = {};
    const { api, body } = liveHarness(answers);
    await api.loadHostDuplicates("case-1");
    expect(body.innerHTML.toLowerCase()).toContain("previously dismissed");
    answers.dismissedOk = false;
    await api.loadHostDuplicates("case-1");
    expect(body.innerHTML.toLowerCase()).not.toContain("previously dismissed");
    expect(body.innerHTML.toLowerCase()).toContain("couldn't refresh");
  });

  it("keeps the section reachable while the notice is showing", async () => {
    const { api, section } = liveHarness({ pendingOk: false, dismissedOk: false });
    await api.loadHostDuplicates("case-1");
    expect(section.dataset.gateOpen).toBe("1");
  });

  it("drops the notice once a later refresh succeeds", async () => {
    const answers: Answers = { pendingOk: false };
    const { api, body } = liveHarness(answers);
    await api.loadHostDuplicates("case-1");
    expect(body.innerHTML.toLowerCase()).toContain("couldn't refresh");
    answers.pendingOk = true;
    await api.loadHostDuplicates("case-1");
    expect(body.innerHTML.toLowerCase()).not.toContain("couldn't refresh");
    expect(body.innerHTML).toContain("win11.windomain.local");
  });
});
