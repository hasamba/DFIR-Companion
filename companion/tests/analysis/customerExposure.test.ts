import { describe, it, expect } from "vitest";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import {
  buildCustomerExposureTargets,
  summarizeExposure,
  type CustomerExposureProvider,
} from "../../src/analysis/customerExposure.js";
import type { CustomerTargets } from "../../src/analysis/customerStore.js";

function stateWith(descs: string[], iocs: string[] = []): InvestigationState {
  return {
    ...emptyState("c1"),
    forensicTimeline: descs.map((description, n) => ({
      id: `e${n + 1}`,
      timestamp: `2026-06-0${n + 1}T00:00:00Z`,
      description,
      severity: "Medium",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    })),
    iocs: iocs.map((value, n) => ({ id: `i${n + 1}`, type: "domain", value, firstSeen: "2026-06-01T00:00:00Z" })),
  };
}

describe("buildCustomerExposureTargets", () => {
  it("checks only manually entered customer domains, never IOC domains found in the case", () => {
    const state = stateWith([
      "User alice@example.com clicked a phishing link at evil-c2.test",
      "Remote domain payload.bad was contacted by host DC01",
    ], ["evil-c2.test", "payload.bad"]);
    const targets: CustomerTargets = { domains: ["example.com"], emails: [] };

    const built = buildCustomerExposureTargets(state, targets);

    expect(built.domains).toEqual(["example.com"]);
    expect(built.emails).toEqual(["alice@example.com"]);
    expect(built.emails).not.toContain("payload.bad");
  });

  it("checks manually entered emails even when their domain is not in the domain list", () => {
    const built = buildCustomerExposureTargets(
      stateWith(["No emails in evidence"]),
      { domains: [], emails: [" VIP@Example.org "] },
    );

    expect(built.domains).toEqual([]);
    expect(built.emails).toEqual(["vip@example.org"]);
  });

  it("does not auto-check case emails outside customer domains or emails recorded as IOCs", () => {
    const state = stateWith([
      "alice@example.com received mail from attacker@phish.test and bob@other.test",
    ], ["attacker@phish.test"]);
    state.iocs = [{ id: "i1", type: "other", value: "attacker@phish.test", firstSeen: "2026-06-01T00:00:00Z" }];

    const built = buildCustomerExposureTargets(state, { domains: ["example.com"], emails: [] });

    expect(built.emails).toEqual(["alice@example.com"]);
  });
});

describe("summarizeExposure", () => {
  it("runs all providers and strips raw secrets from stored findings", async () => {
    const providers: CustomerExposureProvider[] = [{
      name: "MockLeaks",
      lookupEmail: async (email) => [{
        provider: "MockLeaks",
        targetType: "email",
        target: email,
        email,
        breach: "ExampleBreach",
        exposedData: ["email", "password"],
        secretPresent: true,
        raw: { password: "cleartext-secret" },
      }],
      lookupDomain: async (domain) => [{
        provider: "MockLeaks",
        targetType: "domain",
        target: domain,
        email: `alice@${domain}`,
        breach: "DomainBreach",
        raw: { password: "another-secret" },
      }],
    }];

    const summary = await summarizeExposure(
      stateWith(["alice@example.com logged in"]),
      { domains: ["example.com"], emails: [] },
      providers,
      { now: () => "2026-06-08T12:00:00Z", sleep: async () => {} },
    );

    expect(summary.targets).toEqual({ domains: ["example.com"], emails: ["alice@example.com"] });
    expect(summary.results).toHaveLength(2);
    expect(summary.results.map((r) => r.provider)).toEqual(["MockLeaks", "MockLeaks"]);
    expect(JSON.stringify(summary.results)).not.toContain("cleartext-secret");
    expect(summary.results.find((r) => r.targetType === "email")).toMatchObject({ secretPresent: true });
  });

  it("records provider errors without aborting other lookups", async () => {
    const providers: CustomerExposureProvider[] = [
      {
        name: "Bad",
        lookupEmail: async () => { throw new Error("rate limited"); },
        lookupDomain: async () => [],
      },
      {
        name: "Good",
        lookupEmail: async (email) => [{ provider: "Good", targetType: "email", target: email, breach: "B1" }],
        lookupDomain: async () => [],
      },
    ];

    const summary = await summarizeExposure(
      stateWith(["alice@example.com"]),
      { domains: ["example.com"], emails: [] },
      providers,
      { now: () => "2026-06-08T12:00:00Z", sleep: async () => {} },
    );

    expect(summary.results).toHaveLength(1);
    expect(summary.errors).toEqual([{ provider: "Bad", targetType: "email", target: "alice@example.com", error: "rate limited" }]);
  });
});
