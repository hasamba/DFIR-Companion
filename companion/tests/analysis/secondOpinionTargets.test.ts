import { describe, it, expect } from "vitest";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";
import {
  applyAcceptedSecondOpinion,
  type SecondOpinion,
  type SecondOpinionDelta,
} from "../../src/analysis/secondOpinion.js";
import {
  carryAcceptedDecisions,
  markUnappliedDecisions,
  unappliedSecondOpinionDeltas,
} from "../../src/analysis/secondOpinionTargets.js";

// #1590 — an accepted second-opinion decision must follow its finding by identity, not by wording.
// A re-synthesis that retitles a finding or changes its ATT&CK tags used to break the derived key,
// and the dismissal or severity change quietly stopped applying.

function finding(over: Partial<Finding> & Pick<Finding, "id" | "title">): Finding {
  return {
    severity: "High",
    confidence: 80,
    description: `${over.title} description`,
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "2026-06-01T00:00:00.000Z",
    lastUpdated: "2026-06-01T00:00:00.000Z",
    status: "open",
    ...over,
  };
}

const stateWith = (findings: Finding[]): InvestigationState => ({ ...emptyState("c1"), findings });

function accepted(kind: SecondOpinionDelta["kind"], f: Finding, extra: Partial<SecondOpinionDelta> = {}) {
  return {
    id: `${kind}:${f.id}`,
    kind,
    title: f.title,
    finding: f,
    rationale: "",
    recommendation: "review",
    status: "accepted",
    ...extra,
  } satisfies SecondOpinionDelta;
}

function record(deltas: SecondOpinionDelta[], generatedAt = "2026-06-01T13:26:00.000Z"): SecondOpinion {
  return { generatedAt, modelA: "A", modelB: "B", referee: "", summary: "", agreementCount: 0, deltas };
}

// f17 in the lab case: same title, techniques changed from T1482/T1087.002 to T1069.002/T1018.
const f17Before = finding({
  id: "f17",
  title: "Possible BloodHound-style AD enumeration",
  mitreTechniques: ["T1482", "T1087.002"],
  relatedEventIds: ["e1", "e2"],
});
// f13: retitled, techniques changed, still cites one of the same events.
const f13Before = finding({
  id: "f13",
  title: "Remote-access/RMM tooling staged",
  mitreTechniques: ["T1219"],
  relatedEventIds: ["e7"],
});

describe("an accepted dismissal follows its finding across a re-synthesis (#1590)", () => {
  it("stays applied when the same finding comes back with changed techniques", () => {
    const so = record([accepted("a_only", f17Before)]);
    const after = stateWith([{ ...f17Before, mitreTechniques: ["T1069.002", "T1018"] }]);
    const out = applyAcceptedSecondOpinion(after, so);
    expect(out.findings[0].status).toBe("dismissed");
    expect(unappliedSecondOpinionDeltas(after.findings, so)).toEqual([]);
  });

  it("stays applied when the finding is retitled AND retagged but keeps its id and evidence", () => {
    const so = record([accepted("a_only", f13Before)]);
    const after = stateWith([
      { ...f13Before, title: "AnyDesk dropped into a user profile", mitreTechniques: ["T1105"] },
    ]);
    expect(applyAcceptedSecondOpinion(after, so).findings[0].status).toBe("dismissed");
  });

  it("does not follow an id that now holds a different claim — it reports it instead", () => {
    const so = record([accepted("a_only", f13Before)]);
    const reused = finding({
      id: "f13",
      title: "Kerberoasting of a service account",
      mitreTechniques: ["T1558.003"],
      relatedEventIds: ["e99"],
    });
    const after = stateWith([reused]);
    expect(applyAcceptedSecondOpinion(after, so).findings[0].status).toBe("open");
    expect(unappliedSecondOpinionDeltas(after.findings, so)).toEqual([
      { deltaId: "a_only:f13", reason: "changed" },
    ]);
  });

  it("falls back to the derived key when the id is gone", () => {
    const so = record([accepted("a_only", f17Before)]);
    const after = stateWith([{ ...f17Before, id: "f40" }]);
    expect(applyAcceptedSecondOpinion(after, so).findings[0].status).toBe("dismissed");
  });

  it("lists a decision whose finding is really gone", () => {
    const so = record([
      accepted("a_only", f17Before),
      accepted("severity", f13Before, { bSeverity: "Medium" }),
    ]);
    const after = stateWith([finding({ id: "f2", title: "Something unrelated" })]);
    expect(unappliedSecondOpinionDeltas(after.findings, so)).toEqual([
      { deltaId: "a_only:f17", reason: "missing" },
      { deltaId: "severity:f13", reason: "missing" },
    ]);
  });

  it("never lists pending, rejected, B-only or ATT&CK decisions", () => {
    const so = record([
      { ...accepted("a_only", f17Before), status: "pending" },
      { ...accepted("severity", f13Before, { bSeverity: "Low" }), status: "rejected" },
      accepted("b_only", finding({ id: "g1", title: "B found this" })),
      {
        id: "mitre_added:T1018",
        kind: "mitre_added",
        title: "T1018",
        rationale: "",
        recommendation: "review",
        status: "accepted",
      },
    ]);
    expect(unappliedSecondOpinionDeltas([], so)).toEqual([]);
  });

  it("marks the unapplied decisions on a copy of the record, leaving the rest untouched", () => {
    const so = record([accepted("a_only", f17Before), accepted("a_only", f13Before)]);
    const marked = markUnappliedDecisions(so, [f13Before]);
    expect(marked.deltas.map((d) => d.unapplied)).toEqual(["missing", undefined]);
    expect(so.deltas[0].unapplied).toBeUndefined();
  });
});

describe("an accepted severity change follows its finding (#1590)", () => {
  it("still applies after a retag", () => {
    const f6 = finding({
      id: "f6",
      title: "Advanced IP Scanner executed",
      mitreTechniques: ["T1018", "T1016"],
    });
    const so = record([accepted("severity", f6, { aSeverity: "High", bSeverity: "Medium" })]);
    const after = stateWith([{ ...f6, mitreTechniques: ["T1046", "T1018"] }]);
    expect(applyAcceptedSecondOpinion(after, so).findings[0].severity).toBe("Medium");
  });
});

describe("an adopted B-only finding is not added twice", () => {
  it("recognises the adopted finding by its id after the model retitles it", () => {
    const g = finding({ id: "g3", title: "B only finding", mitreTechniques: ["T1071"] });
    const so = record([accepted("b_only", g, { title: "B only finding" })]);
    const once = applyAcceptedSecondOpinion(stateWith([]), so);
    expect(once.findings.map((f) => f.id)).toEqual(["so:b-only-finding"]);
    const retitled = stateWith([
      { ...once.findings[0], title: "C2 beacon to a rare host", mitreTechniques: [] },
    ]);
    expect(applyAcceptedSecondOpinion(retitled, so).findings).toHaveLength(1);
  });
});

describe("a new second-opinion run keeps the decisions already accepted (#1590)", () => {
  const f6 = finding({ id: "f6", title: "Advanced IP Scanner executed" });
  const prev = record([
    accepted("severity", f6, { id: "severity:scanner", bSeverity: "Medium" }),
    { ...accepted("a_only", f17Before), status: "rejected" },
    { ...accepted("a_only", f13Before), status: "pending" },
  ]);

  it("carries accepted decisions, stamped with the run they came from, and drops the rest", () => {
    const next = record([], "2026-06-01T14:00:00.000Z");
    const out = carryAcceptedDecisions(prev, next);
    expect(out.generatedAt).toBe("2026-06-01T14:00:00.000Z");
    expect(out.deltas.map((d) => [d.id, d.status, d.carriedFrom])).toEqual([
      ["severity:scanner", "accepted", "2026-06-01T13:26:00.000Z"],
    ]);
  });

  it("keeps the original run stamp through a third run", () => {
    const second = carryAcceptedDecisions(prev, record([], "2026-06-01T14:00:00.000Z"));
    const third = carryAcceptedDecisions(second, record([], "2026-06-01T15:00:00.000Z"));
    expect(third.deltas[0].carriedFrom).toBe("2026-06-01T13:26:00.000Z");
  });

  it("drops a fresh delta that repeats a carried decision, keeps a new proposal for the same finding", () => {
    const sameId = {
      ...accepted("severity", f6, { id: "severity:scanner", bSeverity: "Low" }),
      status: "pending" as const,
    };
    const sameCall = {
      ...accepted("severity", f6, { id: "severity:other-key", bSeverity: "Medium" }),
      status: "pending" as const,
    };
    const newCall = {
      ...accepted("severity", f6, { id: "severity:third-key", bSeverity: "Low" }),
      status: "pending" as const,
    };
    const fresh = accepted("a_only", f13Before, { status: "pending" });
    const out = carryAcceptedDecisions(
      prev,
      record([sameId, sameCall, newCall, fresh], "2026-06-01T14:00:00.000Z"),
    );
    // Carried first, so a later accepted proposal for the same finding wins on apply.
    expect(out.deltas.map((d) => d.id)).toEqual(["severity:scanner", "severity:third-key", "a_only:f13"]);
  });

  it("returns the fresh record unchanged when there was no earlier record", () => {
    const next = record([accepted("a_only", f13Before, { status: "pending" })]);
    expect(carryAcceptedDecisions(null, next)).toBe(next);
  });
});
