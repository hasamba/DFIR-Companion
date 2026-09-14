// #1024: the three views — latest, actionable at a moment, last-known with a label — and the
// consumers that act on them: grounding, the block-list, the STIX bundle.
import { describe, expect, it } from "vitest";
import {
  actionableAssertions,
  assertionLabel,
  lastKnownAssertions,
  latestAssertions,
  statusAt,
} from "../../src/analysis/intelViews.js";
import { intelFlaggedIocIds } from "../../src/analysis/findingGrounding.js";
import { filterBlocklistIocs } from "../../src/reports/iocBlocklist.js";
import { buildStixBundle } from "../../src/reports/stix.js";
import { emptyState, type IOC, type IocEnrichment } from "../../src/analysis/stateTypes.js";

const T = "2026-06-01T00:00:00.000Z";
const at = (h: number) => new Date(Date.parse(T) + h * 3_600_000).toISOString();
const ioc = (enrichments: IocEnrichment[], over: Partial<IOC> = {}): IOC => ({
  id: "i1",
  type: "ip",
  value: "203.0.113.5",
  firstSeen: T,
  enrichments,
  ...over,
});
const live = (over: Partial<IocEnrichment> = {}): IocEnrichment => ({
  source: "OpenCTI",
  verdict: "malicious",
  fetchedAt: at(0),
  assertionId: "a",
  status: "live",
  originKind: "relay",
  origins: ["ACME"],
  ...over,
});

describe("statusAt and the views", () => {
  it("a validity that ended since the last check is expired at the moment of use, whatever the stored status", () => {
    const e = live({ validity: { until: at(24) } });
    expect(statusAt(e, at(1))).toBe("live");
    expect(statusAt(e, at(25))).toBe("expired");
    expect(actionableAssertions(ioc([e]), at(1))).toHaveLength(1);
    expect(actionableAssertions(ioc([e]), at(25))).toHaveLength(0);
    expect(assertionLabel(e, at(25))).toContain("validity ended 2026-06-02 (before now); kept as history");
  });
  it("last-known keeps every state labelled; latest drops errored and legacy; actionable keeps live only", () => {
    const list = [
      live({ assertionId: "a" }),
      live({ assertionId: "b", status: "revoked", revoked: true }),
      live({ assertionId: "c", status: "not-returned", lastMissAt: at(2) }),
      live({ assertionId: "d", status: "errored-last-known" }),
      { source: "VirusTotal", verdict: "malicious", fetchedAt: at(-24) } as IocEnrichment,
    ];
    const i = ioc(list);
    expect(lastKnownAssertions(i)).toHaveLength(5);
    expect(
      latestAssertions(i)
        .map((e) => e.assertionId)
        .sort(),
    ).toEqual(["a", "b", "c"]);
    expect(actionableAssertions(i, at(3)).map((e) => e.assertionId)).toEqual(["a"]);
    expect(assertionLabel(list[1])).toBe("revoked by the provider; kept as history");
    expect(assertionLabel(list[2])).toContain(
      "not returned on the check at 2026-06-01T02:00:00; kept as history — a miss is not a withdrawal",
    );
    expect(assertionLabel(list[3])).toBe("last known; the provider errored on the last check");
    expect(assertionLabel(list[4])).toBe(
      "recorded before assertion tracking; re-check to make it actionable",
    );
  });
  it("two stored states of one assertion: the newest check wins in every view", () => {
    const i = ioc([live({ fetchedAt: at(0) }), live({ fetchedAt: at(2), status: "revoked", revoked: true })]);
    expect(lastKnownAssertions(i)).toHaveLength(1);
    expect(lastKnownAssertions(i)[0].status).toBe("revoked");
  });
});

describe("consumers act on the actionable view only", () => {
  it("grounding counts an IOC as intel-flagged only with an actionable, creator-named assertion", () => {
    expect(intelFlaggedIocIds([ioc([live()])], at(1)).has("i1")).toBe(true);
    expect(intelFlaggedIocIds([ioc([live({ status: "revoked", revoked: true })])], at(1)).has("i1")).toBe(
      false,
    );
    expect(intelFlaggedIocIds([ioc([live({ validity: { until: at(1) } })])], at(2)).has("i1")).toBe(false);
    expect(
      intelFlaggedIocIds(
        [
          ioc([
            { source: "MISP", verdict: "malicious", fetchedAt: at(0), originKind: "relay", origins: ["X"] },
          ]),
        ],
        at(1),
      ).has("i1"),
    ).toBe(false);
  });
  it("the block-list never carries a verdict from an expired, revoked or legacy assertion; the STIX bundle labels last-known and drops the intel-only relationship", () => {
    const revoked = ioc([live({ status: "revoked", revoked: true })]);
    expect(filterBlocklistIocs([revoked], { verdictOnly: true })).toHaveLength(0);
    expect(filterBlocklistIocs([ioc([live()])], { verdictOnly: true })).toHaveLength(1);
    const legacy = ioc([{ source: "VirusTotal", verdict: "malicious", fetchedAt: at(0) }]);
    expect(filterBlocklistIocs([legacy], { verdictOnly: true })).toHaveLength(0);
    const state = emptyState("c1");
    state.iocs.push(
      ioc([live({ status: "revoked", revoked: true })], { type: "domain", value: "c2.evil.invalid" }),
    );
    state.mitreTechniques.push({ id: "T1071", name: "Application Layer Protocol", findingIds: ["f1"] });
    state.findings.push({
      id: "f1",
      title: "C2",
      description: "",
      severity: "High",
      status: "open",
      relatedIocs: ["i1"],
      mitreTechniques: ["T1071"],
      supportingEvents: [],
      createdAt: T,
      updatedAt: T,
    } as never);
    const bundle = buildStixBundle(state);
    const indicator = bundle.objects.find((o) => o.type === "indicator") as
      { description?: string; indicator_types?: string[] } | undefined;
    expect(indicator?.description).toContain("[revoked by the provider; kept as history]");
    expect(
      bundle.objects.some(
        (o) =>
          o.type === "relationship" &&
          (o as { relationship_type?: string }).relationship_type === "indicates",
      ),
    ).toBe(false);
    // The same finding with a live assertion keeps its relationship.
    state.iocs[0] = ioc([live()], { type: "domain", value: "c2.evil.invalid" });
    expect(
      buildStixBundle(state).objects.some(
        (o) =>
          o.type === "relationship" &&
          (o as { relationship_type?: string }).relationship_type === "indicates",
      ),
    ).toBe(true);
    // A recorded retire decision applies only while the finding is in the review: with the live
    // assertion it is stale and suppresses nothing; with the intel non-actionable again it applies.
    state.intelRetirementDecisions = [
      { findingId: "f1", decision: "retire", decidedAt: T, assertionIds: ["a"] },
    ];
    expect(
      buildStixBundle(state).objects.some(
        (o) =>
          o.type === "relationship" &&
          (o as { relationship_type?: string }).relationship_type === "indicates",
      ),
    ).toBe(true);
    state.iocs[0] = ioc([live({ status: "revoked", revoked: true })], {
      type: "domain",
      value: "c2.evil.invalid",
    });
    expect(
      buildStixBundle(state).objects.some(
        (o) =>
          o.type === "relationship" &&
          (o as { relationship_type?: string }).relationship_type === "indicates",
      ),
    ).toBe(false);
  });
});

describe("code round 1 — malware tags and the intel-only grade read actionable assertions only", () => {
  it("a revoked assertion's family tag creates no malware object or relationship in the STIX bundle", () => {
    const state = emptyState("c1");
    state.iocs.push(ioc([live({ status: "revoked", revoked: true, tags: ["Emotet"] })]));
    const bundle = buildStixBundle(state);
    expect(bundle.objects.some((o) => o.type === "malware")).toBe(false);
    state.iocs[0] = ioc([live({ tags: ["Emotet"] })]);
    expect(buildStixBundle(state).objects.some((o) => o.type === "malware")).toBe(true);
  });
});
