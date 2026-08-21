import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface HostScopeApi {
  renderHostScope(ledger: unknown): string;
  setHostScopeFilter(status: string): void;
}

const panel = loadDashboardModule<HostScopeApi>("dashboard-host-scope.js", ["dashboard-escape.js"]);

function host(over: Record<string, unknown> = {}) {
  return {
    name: "ws-099",
    presence: "referenced",
    derivedStatus: "unknown",
    effectiveStatus: "unknown",
    eligibility: { eligible: false, criteria: [] },
    sources: [],
    firstSeen: "",
    lastSeen: "",
    eventCount: 0,
    referencedBy: ["srv-file01"],
    gap: "named by 1 collected host but never collected",
    fingerprint: "",
    ...over,
  };
}

function ledger(over: Record<string, unknown> = {}) {
  return {
    hosts: [host()],
    counts: { unknown: 1, suspected: 0, confirmed: 0, cleared: 0, "out-of-scope": 0 },
    referencedNeverCollected: 1,
    fleet: null,
    nearDuplicates: [],
    ...over,
  };
}

describe("host scope panel", () => {
  it("puts the gap list above the host table", () => {
    const html = panel.renderHostScope(ledger());
    expect(html.indexOf("Scope gaps")).toBeLessThan(html.indexOf("<h4>Hosts</h4>"));
    expect(html).toContain("never collected");
  });

  it("omits the fleet figure when there is no snapshot", () => {
    expect(panel.renderHostScope(ledger())).not.toContain("enrolled endpoints");
  });

  it("shows the fleet figure with both denominators when a snapshot exists", () => {
    const html = panel.renderHostScope(
      ledger({ fleet: { enrolled: 5000, collected: 4200, snapshotAt: "2026-08-12T00:00:00Z" } }),
    );
    expect(html).toContain("4,200");
    expect(html).toContain("5,000");
    expect(html).toContain("2026-08-12");
  });

  it("ranks a stale clearance above an uncollected host", () => {
    const html = panel.renderHostScope(
      ledger({
        hosts: [
          host(),
          host({ name: "ws-042", presence: "collected", stale: "evidence changed", gap: undefined }),
        ],
      }),
    );
    expect(html.indexOf("ws-042")).toBeLessThan(html.indexOf("ws-099"));
  });

  it("warns about possible duplicate hosts instead of merging them", () => {
    const html = panel.renderHostScope(
      ledger({
        nearDuplicates: [{ canonical: "ws-099.corp.local", other: "ws-099", reason: "shortname-fqdn" }],
      }),
    );
    expect(html).toContain("may be the same host");
  });

  it("escapes a hostile host name", () => {
    const html = panel.renderHostScope(ledger({ hosts: [host({ name: "<img src=x onerror=alert(1)>" })] }));
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img");
  });

  it("offers clearance actions, so a decision can actually be recorded from the UI", () => {
    const html = panel.renderHostScope(ledger());
    expect(html).toContain('data-hs-action="cleared"');
    expect(html).toContain('data-hs-action="out-of-scope"');
    expect(html).toContain('data-hs-host="ws-099"');
  });

  it("uses data attributes rather than inline handlers, which the CSP forbids", () => {
    const html = panel.renderHostScope(ledger());
    expect(html).not.toMatch(/\son(click|change|load)=/i);
  });

  it("offers reopen only once a decision exists, and hides the action already taken", () => {
    const decided = ledger({
      hosts: [
        host({
          effectiveStatus: "cleared",
          decision: { to: "cleared", analyst: "a.analyst@example.invalid", reason: "covered" },
        }),
      ],
    });
    const html = panel.renderHostScope(decided);
    expect(html).toContain('data-hs-action="unknown"');
    expect(html).not.toContain('data-hs-action="cleared"');
  });

  it("does not offer reopen on a host that was already reopened", () => {
    // The decision exists but asserts nothing — clicking reopen again would append a duplicate
    // no-op to an append-only audit log.
    const reopened = ledger({
      hosts: [
        host({
          effectiveStatus: "suspected",
          decision: { to: "unknown", analyst: "a.analyst@example.invalid", reason: "" },
        }),
      ],
    });
    const html = panel.renderHostScope(reopened);
    expect(html).not.toContain('data-hs-action="unknown"');
    expect(html).toContain('data-hs-action="cleared"');
  });

  it("offers reopen on a manual escalation too, so no decision is stranded", () => {
    for (const to of ["suspected", "confirmed"]) {
      const escalated = ledger({
        hosts: [
          host({
            effectiveStatus: to,
            decision: { to, analyst: "a.analyst@example.invalid", reason: "" },
          }),
        ],
      });
      const html = panel.renderHostScope(escalated);
      expect(html, `${to} must be retractable`).toContain('data-hs-action="unknown"');
    }
  });

  it("escapes a hostile host name inside the action attributes too", () => {
    const html = panel.renderHostScope(ledger({ hosts: [host({ name: '" onclick="alert(1)' })] }));
    expect(html).not.toContain('" onclick="alert(1)"');
    expect(html).toContain("&quot;");
  });

  it("never calls a cleared host clean", () => {
    const html = panel.renderHostScope(
      ledger({ counts: { unknown: 0, suspected: 0, confirmed: 0, cleared: 4, "out-of-scope": 0 } }),
    );
    expect(html.toLowerCase()).not.toContain("clean");
  });
});

// The decision write is append-only and quoted in the report, so a decision that never landed must
// surface as an error the click handler can show — not a silent `false` nobody consumed.
interface HostScopeDecisionApi {
  decideHostScope(caseId: string, host: string, to: string, reason: string): Promise<boolean>;
}

function panelWithFetch(fetchStub: unknown) {
  return loadDashboardModule<HostScopeDecisionApi>("dashboard-host-scope.js", ["dashboard-escape.js"], {
    fetch: fetchStub,
    document: { getElementById: () => null }, // paintHostScope no-ops without the panel element
  });
}

describe("recording a host-scope decision", () => {
  it("throws the server's own error when the decision is rejected", async () => {
    const p = panelWithFetch(async () => ({
      ok: false,
      status: 400,
      json: async () => ({ error: "a reason is required" }),
    }));
    await expect(p.decideHostScope("c1", "ws-099", "cleared", "")).rejects.toThrow("a reason is required");
  });

  it("falls back to the HTTP status when the error body is unreadable", async () => {
    const p = panelWithFetch(async () => ({
      ok: false,
      status: 502,
      json: async () => {
        throw new Error("not json");
      },
    }));
    await expect(p.decideHostScope("c1", "ws-099", "out-of-scope", "why")).rejects.toThrow("HTTP 502");
  });

  it("resolves true when the decision lands", async () => {
    const p = panelWithFetch(async () => ({
      ok: true,
      status: 200,
      json: async () => ledger(),
    }));
    await expect(p.decideHostScope("c1", "ws-099", "cleared", "covered")).resolves.toBe(true);
  });
});

// The ledger read is raced by case switches, and the per-case resets in dashboard-case-connect.js
// never touch this module's state — so a stale response must not overwrite the newer case's
// ledger, and the LATEST load's failure must clear and repaint rather than leave the PREVIOUS
// case's clearance board ("Cleared"/"Confirmed" for the wrong case) on a surface analysts use for
// scoping calls. Same generation-token contract as loadAssetGraph, pinned the same way.
interface HostScopeLoadApi {
  loadHostScope(caseId: string): Promise<void>;
  decideHostScope(caseId: string, host: string, to: string, reason: string): Promise<boolean>;
}

interface PendingFetch {
  url: string;
  resolve(response: unknown): void;
  reject(reason: unknown): void;
}

// A fetch stub whose responses are settled BY THE TEST, in the order the test chooses — the whole
// point is answering request A after request B.
function deferredFetch() {
  const pending: PendingFetch[] = [];
  const fetch = (url: string) =>
    new Promise((resolve, reject) => {
      pending.push({ url, resolve, reject });
    });
  return { pending, fetch };
}

// One macrotask turn, so every already-settled promise chain runs to completion.
const drain = () => new Promise((r) => setImmediate(r));

// The panel body the module paints into: enough element for paintHostScope (innerHTML, the
// bind-once dataset flag, the delegated listener) and for the failure writes.
function panelWithBody(fetchStub: unknown) {
  const body = { innerHTML: "", dataset: {} as Record<string, string>, addEventListener: () => {} };
  const p = loadDashboardModule<HostScopeLoadApi>("dashboard-host-scope.js", ["dashboard-escape.js"], {
    fetch: fetchStub,
    document: { getElementById: (id: string) => (id === "hostScopeBody" ? body : null) },
  });
  return { p, body };
}

function okLedger(name: string) {
  return { ok: true, status: 200, json: async () => ledger({ hosts: [host({ name })] }) };
}

describe("loading the host-scope ledger under case switches", () => {
  it("ignores a stale load's late success — the newer case's board survives", async () => {
    const { pending, fetch } = deferredFetch();
    const { p, body } = panelWithBody(fetch);
    void p.loadHostScope("case-a");
    void p.loadHostScope("case-b");
    pending[1].resolve(okLedger("host-b"));
    await drain();
    expect(body.innerHTML).toContain("host-b");
    pending[0].resolve(okLedger("host-a"));
    await drain();
    expect(body.innerHTML).toContain("host-b");
    expect(body.innerHTML).not.toContain("host-a");
  });

  it("ignores a stale load's late failure — the newer case's board survives", async () => {
    const { pending, fetch } = deferredFetch();
    const { p, body } = panelWithBody(fetch);
    void p.loadHostScope("case-a");
    void p.loadHostScope("case-b");
    pending[1].resolve(okLedger("host-b"));
    await drain();
    pending[0].resolve({ ok: false, status: 500, json: async () => ({ error: "boom" }) });
    await drain();
    expect(body.innerHTML).toContain("host-b");
    expect(body.innerHTML).not.toContain("unavailable");
  });

  it("clears the previous case's board when the new case's read fails, and says why", async () => {
    const { pending, fetch } = deferredFetch();
    const { p, body } = panelWithBody(fetch);
    void p.loadHostScope("case-a");
    pending[0].resolve(okLedger("host-a"));
    await drain();
    expect(body.innerHTML).toContain("host-a");
    void p.loadHostScope("case-b");
    // The 500 routes/hostScope.ts produces on a corrupt ledger file carries the error message —
    // fail-loud by design, and the panel must not silence it at the last hop.
    pending[1].resolve({ ok: false, status: 500, json: async () => ({ error: "scope ledger corrupt" }) });
    await drain();
    expect(body.innerHTML).toContain("Host scope unavailable: scope ledger corrupt");
    expect(body.innerHTML).not.toContain("host-a");
  });

  it("falls back to the HTTP status when the failure body is unreadable", async () => {
    const { pending, fetch } = deferredFetch();
    const { p, body } = panelWithBody(fetch);
    void p.loadHostScope("case-a");
    pending[0].resolve({
      ok: false,
      status: 502,
      json: async () => {
        throw new Error("not json");
      },
    });
    await drain();
    expect(body.innerHTML).toContain("Host scope unavailable: HTTP 502");
  });

  it("clears the previous case's board on a network-level rejection too", async () => {
    const { pending, fetch } = deferredFetch();
    const { p, body } = panelWithBody(fetch);
    void p.loadHostScope("case-a");
    pending[0].resolve(okLedger("host-a"));
    await drain();
    void p.loadHostScope("case-b");
    pending[1].reject(new Error("ECONNREFUSED"));
    await drain();
    expect(body.innerHTML).toContain("Host scope could not be loaded.");
    expect(body.innerHTML).not.toContain("host-a");
  });

  it("renders the default empty state when the store is not configured (501)", async () => {
    const { pending, fetch } = deferredFetch();
    const { p, body } = panelWithBody(fetch);
    void p.loadHostScope("case-a");
    pending[0].resolve({ ok: false, status: 501, json: async () => ({ error: "not configured" }) });
    await drain();
    expect(body.innerHTML).toContain("No scope data.");
    expect(body.innerHTML).not.toContain("unavailable");
  });

  it("a decision's late response does not resurrect the previous case's board after a switch", async () => {
    const { pending, fetch } = deferredFetch();
    const { p, body } = panelWithBody(fetch);
    void p.loadHostScope("case-a");
    pending[0].resolve(okLedger("host-a"));
    await drain();
    expect(body.innerHTML).toContain("host-a");
    // A clearance decision for case A is still in flight when the analyst switches to case B.
    const decided = p.decideHostScope("case-a", "host-a", "cleared", "covered");
    void p.loadHostScope("case-b");
    pending[2].resolve(okLedger("host-b"));
    await drain();
    expect(body.innerHTML).toContain("host-b");
    // The decision's response carries case A's ledger — it landed server-side (resolves true),
    // but must not repaint case B's board with the superseded case's clearance state.
    pending[1].resolve(okLedger("host-a"));
    await drain();
    await expect(decided).resolves.toBe(true);
    expect(body.innerHTML).toContain("host-b");
    expect(body.innerHTML).not.toContain("host-a");
    // A DIFFERENT-case supersession must not reconcile — reloading case A would clobber case B.
    expect(pending.length).toBe(3);
  });

  it("reconciles with a fresh load when a same-case reload supersedes a decision", async () => {
    const { pending, fetch } = deferredFetch();
    const { p, body } = panelWithBody(fetch);
    void p.loadHostScope("case-a");
    pending[0].resolve(okLedger("host-a"));
    await drain();
    // A decision and a SAME-case reload race; the reload's read predates the append, so its
    // ledger is the pre-decision state.
    const decided = p.decideHostScope("case-a", "host-a", "cleared", "covered");
    void p.loadHostScope("case-a");
    pending[2].resolve(okLedger("host-a"));
    await drain();
    expect(body.innerHTML).toContain("host-a");
    // The decision's post-append ledger arrives superseded: it must not paint directly, but a
    // recorded decision must not stay invisible either — a reconciling load is issued and its
    // (post-append) response is what paints.
    pending[1].resolve(okLedger("host-a-cleared"));
    await drain();
    await expect(decided).resolves.toBe(true);
    expect(pending.length).toBe(4);
    pending[3].resolve(okLedger("host-a-cleared"));
    await drain();
    expect(body.innerHTML).toContain("host-a-cleared");
  });
});
