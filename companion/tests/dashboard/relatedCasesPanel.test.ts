import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  renderRelatedCases(list: unknown[]): string;
}

const panel = loadDashboardModule<Api>("dashboard-related-cases.js", ["dashboard-escape.js"]);

function related(over: Record<string, unknown> = {}) {
  return {
    caseId: "CASE-2",
    name: "Phishing wave",
    status: "open",
    score: 3,
    sharedCount: 1,
    maliciousCount: 1,
    shared: [{ value: "evil.com", types: ["domain"], malicious: true, isInternal: false, weight: 3 }],
    ...over,
  };
}

describe("related cases panel", () => {
  it("renders nothing when no case overlaps — the gate closes on the empty string", () => {
    expect(panel.renderRelatedCases([])).toBe("");
  });

  it("names the case and links to it", () => {
    const html = panel.renderRelatedCases([related()]);
    expect(html).toContain("CASE-2 — Phishing wave");
    expect(html).toContain('href="/dashboard?caseId=CASE-2"');
  });

  it("lists the shared indicator and marks a flagged one in text, not colour alone", () => {
    const html = panel.renderRelatedCases([related()]);
    expect(html).toContain("evil.com");
    expect(html).toContain("rc-ioc-mal");
    expect(html).toContain("⚠");
  });

  it("says the overlap is a lead, not a proven link", () => {
    // A panel titled "Related Cases" invites the opposite reading, and the analyst is the one who
    // has to defend the claim in a report.
    expect(panel.renderRelatedCases([related()]).toLowerCase()).toContain("not a proven link");
  });

  it("marks a private address as the weak link it is", () => {
    const html = panel.renderRelatedCases([
      related({
        maliciousCount: 0,
        shared: [{ value: "10.0.0.5", types: ["ip"], malicious: false, isInternal: true, weight: 0.25 }],
      }),
    ]);
    expect(html).toContain("rc-ioc-int");
    expect(html).toContain("weak link");
  });

  it("reports the indicators the server did not list", () => {
    const html = panel.renderRelatedCases([related({ sharedCount: 6 })]);
    expect(html).toContain("+5 more");
  });

  it("shows a closed case's status and stays silent about an open one", () => {
    expect(panel.renderRelatedCases([related({ status: "closed" })])).toContain("rc-status");
    expect(panel.renderRelatedCases([related()])).not.toContain("rc-status");
  });

  it("escapes a hostile case name", () => {
    const html = panel.renderRelatedCases([related({ name: "<img src=x onerror=alert(1)>" })]);
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img");
  });

  it("escapes attribute-breakout characters in a hostile indicator value", () => {
    // A quote-free payload cannot tell escAttr from esc, so this one carries both quote flavours:
    // it only stays safe if the quote-escaping half actually ran on the title attribute.
    const hostile = `<img src=x onerror=alert(1)>" onmouseover="alert(2)'`;
    const html = panel.renderRelatedCases([
      related({
        shared: [{ value: hostile, types: [hostile], malicious: false, isInternal: false, weight: 1 }],
      }),
    ]);
    expect(html).not.toContain('title="&lt;img src=x onerror=alert(1)&gt;" onmouseover="alert(2)');
    expect(html).toContain("&quot; onmouseover=&quot;alert(2)&#39;");
  });

  it("percent-encodes a case id before putting it in the link", () => {
    const html = panel.renderRelatedCases([related({ caseId: 'a"b c' })]);
    expect(html).toContain('href="/dashboard?caseId=a%22b%20c"');
  });
});

// Reachability, the same class of check dashboard-host-duplicates.js carries: the panel can render
// perfect HTML into a section the analyst never sees.
describe("related cases panel reachability", () => {
  const markup = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

  it("declares the section's gate closed in markup so it cannot flash before paint runs", () => {
    expect(markup).toMatch(/<section id="sec-related-cases" data-gate-open=""/);
  });

  it("loads the module and gives the panel a body to paint into", () => {
    expect(markup).toContain('<script src="/js/dashboard-related-cases.js"></script>');
    expect(markup).toContain('<div id="relatedCasesBody">');
  });

  it("registers the section so Settings can show and order it", () => {
    expect(markup).toContain('{ id: "sec-related-cases", label: "Related Cases", defaultHidden: true }');
  });

  // Off by default, not removed. A shared indicator across one estate is usually ordinary, so the
  // panel does not earn a slot on every analyst's page unasked — but the routes, the data gate and
  // the Settings checkbox all stay, and an explicit tick still wins (see SECTION_DEFS lookup in
  // applySectionsVis).
  it("is hidden by default until the analyst turns it on", () => {
    const def = markup.match(/\{ id: "sec-related-cases",[^}]*\}/);
    expect(def?.[0]).toContain("defaultHidden: true");
  });

  it("is loaded on case connect", () => {
    const connect = readFileSync(
      new URL("../../../public/js/dashboard-case-connect.js", import.meta.url),
      "utf8",
    );
    expect(connect).toContain("loadRelatedCases(caseId)");
  });

  it("refreshes when an import settles, not only on case connect", () => {
    // An import that lands a domain another case already holds is exactly when the link should
    // appear. ai_status "idle" is the only reliable "import settled" signal available client-side,
    // and it is where the duplicate-host check already hangs.
    const aiStatus = readFileSync(
      new URL("../../../public/js/dashboard-ai-status.js", import.meta.url),
      "utf8",
    );
    expect(aiStatus).toContain("loadRelatedCases(activeCaseId)");
  });

  it("is stubbed by the facade, because that call site has no try/catch", () => {
    // dashboard-ai-status.js calls it bare. Without a stub, a 404 on the panel module turns that
    // branch into a ReferenceError and takes the rest of the branch with it (#475).
    const facade = readFileSync(new URL("../../../public/js/dashboard-facade.js", import.meta.url), "utf8");
    expect(facade).toContain('"loadRelatedCases",');
  });
});

// ── Staleness (Codex review, P2) ─────────────────────────────────────────────────────────────────
//
// Everything above tests the HTML. None of it could catch showing case A's related cases on case
// B's dashboard, which is a wrong claim about the case on screen rather than a rendering fault. So
// these drive loadRelatedCases for real, with an injected document and fetch.
describe("related cases panel staleness", () => {
  interface FakeSection {
    dataset: Record<string, string>;
  }
  interface FakeBody {
    innerHTML: string;
  }
  interface LoaderApi {
    loadRelatedCases(caseId: string): Promise<void>;
  }

  function deferred<T>() {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>((r) => {
      resolve = r;
    });
    return { promise, resolve };
  }

  function response(related: unknown[], ok = true) {
    return { ok, json: async () => ({ related }) };
  }

  function harness() {
    const section: FakeSection = { dataset: {} };
    const body: FakeBody = { innerHTML: "untouched" };
    const queue: Array<() => Promise<unknown>> = [];
    const sandbox = loadDashboardModule<LoaderApi>("dashboard-related-cases.js", ["dashboard-escape.js"], {
      applySectionsVis: () => {},
      document: {
        getElementById: (id: string) =>
          id === "sec-related-cases" ? section : id === "relatedCasesBody" ? body : null,
      },
      fetch: () => {
        const next = queue.shift();
        if (!next) throw new Error("unexpected fetch — the test queued no response for it");
        return next();
      },
    });
    return {
      section,
      body,
      /** Queue the answer the NEXT fetch will give, in call order. */
      answer: (fn: () => Promise<unknown>) => queue.push(fn),
      load: sandbox.loadRelatedCases,
    };
  }

  it("clears the previous case's rows before the new case's request answers", async () => {
    const h = harness();
    h.answer(async () => response([related()]));
    await h.load("CASE-1");
    expect(h.body.innerHTML).toContain("CASE-2 — Phishing wave");
    expect(h.section.dataset.gateOpen).toBe("1");

    // A connect to another case whose request has not answered yet.
    const pending = deferred<unknown>();
    h.answer(() => pending.promise);
    const inFlight = h.load("CASE-9");
    expect(h.body.innerHTML).toBe("");
    expect(h.section.dataset.gateOpen).toBe("");
    pending.resolve(response([]));
    await inFlight;
  });

  it("leaves the panel empty when the new case's request fails", async () => {
    // The bug: the non-OK branch returns without repainting, so without the clear-on-switch above
    // the previous case's links would sit on this case's dashboard until the next page load.
    const h = harness();
    h.answer(async () => response([related()]));
    await h.load("CASE-1");
    h.answer(async () => response([], false));
    await h.load("CASE-9");
    expect(h.body.innerHTML).toBe("");
    expect(h.section.dataset.gateOpen).toBe("");
  });

  it("leaves the panel empty when the new case's request throws", async () => {
    const h = harness();
    h.answer(async () => response([related()]));
    await h.load("CASE-1");
    h.answer(() => Promise.reject(new Error("offline")));
    await h.load("CASE-9");
    expect(h.body.innerHTML).toBe("");
  });

  it("does not blank the panel on a same-case refresh", async () => {
    // The ai_status "idle" hook re-loads the SAME case after every settled import. Clearing there
    // would flicker the panel for no gain — those rows are still this case's.
    const h = harness();
    h.answer(async () => response([related()]));
    await h.load("CASE-1");
    const pending = deferred<unknown>();
    h.answer(() => pending.promise);
    const inFlight = h.load("CASE-1");
    expect(h.body.innerHTML).toContain("CASE-2 — Phishing wave");
    pending.resolve(response([related()]));
    await inFlight;
    expect(h.body.innerHTML).toContain("CASE-2 — Phishing wave");
  });

  it("drops a late answer for a case the analyst has already left", async () => {
    // Panel loaders are fired per connect and are not awaited, so two can overlap.
    const h = harness();
    const slow = deferred<unknown>();
    h.answer(() => slow.promise);
    const abandoned = h.load("CASE-1");
    h.answer(async () => response([]));
    await h.load("CASE-9");
    slow.resolve(response([related()]));
    await abandoned;
    expect(h.body.innerHTML).toBe("");
  });

  it("clears the panel on disconnect", async () => {
    const h = harness();
    h.answer(async () => response([related()]));
    await h.load("CASE-1");
    await h.load("");
    expect(h.body.innerHTML).toBe("");
    expect(h.section.dataset.gateOpen).toBe("");
  });
});
