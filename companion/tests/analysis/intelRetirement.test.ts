// #1024 part 4: the retirement review lists findings whose intel corroboration is no longer
// actionable; the analyst's decision is recorded and changes nothing else; the decision survives
// a merge and a concurrent synthesis; the route exposes both.
import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";
import { intelRetirementReview, recordRetirementDecision } from "../../src/analysis/intelRetirement.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { mergeConcurrentAdditions } from "../../src/analysis/ai/synthesisPersist.js";
import {
  emptyState,
  type Finding,
  type InvestigationState,
  type IOC,
  type IocEnrichment,
} from "../../src/analysis/stateTypes.js";

const T = "2026-06-01T00:00:00.000Z";
const at = (h: number) => new Date(Date.parse(T) + h * 3_600_000).toISOString();
const hit = (over: Partial<IocEnrichment> = {}): IocEnrichment => ({
  source: "OpenCTI",
  verdict: "malicious",
  fetchedAt: at(0),
  assertionId: "a1",
  status: "live",
  originKind: "relay",
  origins: ["ACME"],
  tags: ["c2"],
  ...over,
});
const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "f1",
  severity: "High",
  title: "C2 beacon",
  description: "d",
  relatedIocs: ["i1"],
  sourceScreenshots: [],
  mitreTechniques: [],
  firstSeen: T,
  lastUpdated: T,
  status: "open",
  corroboration: { distinctTools: 1, distinctHosts: 1, intelSources: 1, graphLinked: false },
  ...over,
});
const stateWith = (enrichments: IocEnrichment[], f: Partial<Finding> = {}): InvestigationState => {
  const s = emptyState("c1");
  const ioc: IOC = { id: "i1", type: "ip", value: "203.0.113.5", firstSeen: T, enrichments };
  s.iocs.push(ioc);
  s.findings.push(finding(f));
  return s;
};

describe("intelRetirementReview", () => {
  it("lists a finding whose every assertion is expired / revoked / not returned, names them, and says what else stands", () => {
    const s = stateWith([
      hit({ status: "revoked", revoked: true }),
      hit({ assertionId: "a2", source: "ThreatFox", status: "not-returned", lastMissAt: at(1) }),
    ]);
    const r = intelRetirementReview(s, at(2));
    expect(r.items).toHaveLength(1);
    expect(r.stillActionable).toBe(0);
    const it1 = r.items[0];
    expect(it1.assertions.map((a) => a.status).sort()).toEqual(["not-returned", "revoked"]);
    expect(it1.assertions[0].tags).toEqual(["c2"]);
    expect(it1.recommendation).toContain(
      "the intel this finding rested on is no longer actionable (2 assertions: 1 revoked, 1 not-returned)",
    );
    expect(it1.recommendation).toContain(
      "the finding's other corroboration (1 tool, 1 host) does not stand on its own; nothing changes until you decide",
    );
    expect(it1.decision).toBeUndefined();
  });
  it("a finding with one live assertion is not up for review; a validity that ended since the check puts it up", () => {
    expect(intelRetirementReview(stateWith([hit()]), at(1)).items).toHaveLength(0);
    expect(intelRetirementReview(stateWith([hit()]), at(1)).stillActionable).toBe(1);
    const expiring = stateWith([hit({ validity: { until: at(24) } })]);
    expect(intelRetirementReview(expiring, at(1)).items).toHaveLength(0);
    expect(intelRetirementReview(expiring, at(25)).items).toHaveLength(1);
    expect(intelRetirementReview(expiring, at(25)).items[0].assertions[0].label).toContain("validity ended");
    // Legacy (pre-tracking) hits put the finding up for review too — re-check to make them actionable.
    const legacy = stateWith([{ source: "VirusTotal", verdict: "malicious", fetchedAt: at(0) }]);
    expect(intelRetirementReview(legacy, at(1)).items[0].assertions[0].status).toBe("legacy-unverified");
    // No intel at all: nothing to review.
    expect(intelRetirementReview(stateWith([]), at(1)).items).toHaveLength(0);
  });
  it("a decision is recorded by finding id with the assertions it covered, a timeline entry, and nothing else changed", () => {
    const s = stateWith([hit({ status: "revoked", revoked: true })]);
    const next = recordRetirementDecision(
      s,
      { findingId: "f1", decision: "retire", note: "confirmed by the packet capture" },
      at(3),
    )!;
    expect(next.intelRetirementDecisions).toEqual([
      {
        findingId: "f1",
        decision: "retire",
        note: "confirmed by the packet capture",
        decidedAt: at(3),
        assertionIds: ["a1"],
      },
    ]);
    expect(next.findings[0]).toEqual(s.findings[0]);
    expect(next.iocs).toEqual(s.iocs);
    expect(next.timeline[next.timeline.length - 1].description).toContain(
      "Intel retirement review: retire finding f1 — confirmed by the packet capture (a recorded recommendation; the finding's severity and status are unchanged)",
    );
    expect(intelRetirementReview(next, at(4)).items[0].decision?.decision).toBe("retire");
    const kept = recordRetirementDecision(next, { findingId: "f1", decision: "keep" }, at(5))!;
    expect(kept.intelRetirementDecisions).toHaveLength(1);
    expect(kept.intelRetirementDecisions![0].decision).toBe("keep");
    // A finding whose intel is still live is not in the review: a decision on it is refused.
    expect(
      recordRetirementDecision(stateWith([hit()]), { findingId: "f1", decision: "retire" }, at(5)),
    ).toBeNull();
  });
  it("the decision survives mergeDelta and a concurrent synthesis; the newest per finding wins", () => {
    const s = recordRetirementDecision(
      stateWith([hit({ status: "revoked", revoked: true })]),
      { findingId: "f1", decision: "keep" },
      at(3),
    )!;
    const merged = mergeDelta(
      s,
      {
        findings: [],
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "",
        summary: "",
      },
      { timestamp: at(4), windowSequence: 1, sourceScreenshots: [] },
    );
    expect(merged.intelRetirementDecisions).toHaveLength(1);
    const latest = recordRetirementDecision(s, { findingId: "f1", decision: "retire" }, at(6))!;
    const concurrent = mergeConcurrentAdditions(s, s, latest);
    expect(concurrent.intelRetirementDecisions![0].decision).toBe("retire");
    expect(emptyState("x").intelRetirementDecisions).toEqual([]);
  });
});

describe("the route", () => {
  it("GET lists the review; POST records a decision under the lock and returns the review; a bad decision or an unknown finding is refused", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-retire-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save(stateWith([hit({ status: "revoked", revoked: true })]));
    const app = createApp(cases, { stateStore });
    const list = await request(app).get("/cases/c1/intel-retirement");
    expect(list.status).toBe(200);
    expect(list.body.items).toHaveLength(1);
    expect(
      await request(app)
        .post("/cases/c1/intel-retirement/f1")
        .send({ decision: "delete" })
        .then((r) => r.status),
    ).toBe(400);
    expect(
      await request(app)
        .post("/cases/c1/intel-retirement/nope")
        .send({ decision: "keep" })
        .then((r) => r.status),
    ).toBe(404);
    // A finding with live intel is not in the review: 409, nothing recorded.
    await stateStore.save(stateWith([hit()]));
    expect(
      await request(app)
        .post("/cases/c1/intel-retirement/f1")
        .send({ decision: "retire" })
        .then((r) => r.status),
    ).toBe(409);
    await stateStore.save(stateWith([hit({ status: "revoked", revoked: true })]));
    const posted = await request(app)
      .post("/cases/c1/intel-retirement/f1")
      .send({ decision: "retire", note: "n" });
    expect(posted.status).toBe(200);
    expect(posted.body.items[0].decision).toMatchObject({ decision: "retire", note: "n" });
    const saved = await stateStore.load("c1");
    expect(saved.intelRetirementDecisions).toHaveLength(1);
    expect(saved.findings[0].severity).toBe("High");
    expect(saved.findings[0].status).toBe("open");
  });
});

// Code round 1: a retire decision applies only while the finding is in the review; a later live
// assertion makes it stale — nothing is suppressed; the block-list leaves out the retired
// finding's own IOCs and keeps one another finding relates.
describe("stale decisions and the block-list (code round 1)", () => {
  it("a retire decision stops applying when the IOC regains a live assertion; the block-list honours a current one", async () => {
    const { retiredFindingIds, retiredIocIds } = await import("../../src/analysis/intelRetirement.js");
    const { filterBlocklistIocs, buildIocBlocklistTxt } = await import("../../src/reports/iocBlocklist.js");
    const s = recordRetirementDecision(
      stateWith([hit({ status: "revoked", revoked: true })]),
      { findingId: "f1", decision: "retire" },
      at(3),
    )!;
    expect([...retiredFindingIds(s, at(4))]).toEqual(["f1"]);
    expect([...retiredIocIds(s, at(4))]).toEqual(["i1"]);
    expect(buildIocBlocklistTxt(s, { minSeverity: "Info" })).not.toContain("203.0.113.5");
    // Another, non-retired finding relates the same IOC: it stays in the block-list.
    const shared = { ...s, findings: [...s.findings, finding({ id: "f2", relatedIocs: ["i1"] })] };
    expect([...retiredIocIds(shared, at(4))]).toEqual([]);
    expect(buildIocBlocklistTxt(shared, { minSeverity: "Info" })).toContain("203.0.113.5");
    // The IOC regains a live assertion: the finding leaves the review and the decision is stale.
    const revived = { ...s, iocs: [{ ...s.iocs[0], enrichments: [hit({ fetchedAt: at(5) })] }] };
    expect(retiredFindingIds(revived, at(6)).size).toBe(0);
    expect(
      filterBlocklistIocs(revived.iocs, { verdictOnly: true, excludeIocIds: retiredIocIds(revived, at(6)) }),
    ).toHaveLength(1);
  });
});
