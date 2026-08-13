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
