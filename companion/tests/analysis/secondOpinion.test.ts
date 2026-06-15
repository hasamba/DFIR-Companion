import { describe, it, expect } from "vitest";
import { emptyState, type Finding, type InvestigationState, type Technique } from "../../src/analysis/stateTypes.js";
import {
  buildSecondOpinionDeltas,
  buildSecondOpinion,
  mergeReconcileVerdicts,
  applyAcceptedSecondOpinion,
  setDeltaStatus,
  buildReconcilePrompt,
  reconcileResponseSchema,
  type SecondOpinion,
} from "../../src/analysis/secondOpinion.js";

function finding(over: Partial<Finding> & Pick<Finding, "id" | "title" | "severity">): Finding {
  return {
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

function tech(id: string, name = `${id} name`): Technique {
  return { id, name, findingIds: [] };
}

function stateWith(over: Partial<InvestigationState>): InvestigationState {
  return { ...emptyState("c1"), ...over };
}

// Model A (primary, saved) vs Model B (second opinion, dry-run).
const A = stateWith({
  findings: [
    finding({ id: "f1", title: "Mimikatz credential dumping", severity: "Critical" }),
    finding({ id: "f2", title: "Benign admin task", severity: "Low" }),
    finding({ id: "f3", title: "Suspicious logon", severity: "Medium" }),
  ],
  mitreTechniques: [tech("T1003.001"), tech("T1078")],
});
const B = stateWith({
  findings: [
    finding({ id: "g1", title: "Mimikatz credential dumping", severity: "Critical" }),
    finding({ id: "g2", title: "Suspicious logon", severity: "High" }), // severity disagreement Medium→High
    finding({ id: "g3", title: "Cobalt Strike C2 beacon", severity: "High", relatedIocs: ["i9"] }), // B-only
  ],
  mitreTechniques: [tech("T1003.001"), tech("T1071")], // T1078 removed, T1071 added
});

describe("buildSecondOpinionDeltas", () => {
  const deltas = buildSecondOpinionDeltas(A, B);
  const byKind = (k: string) => deltas.filter((d) => d.kind === k);

  it("flags a finding model B raised that model A missed (b_only) and carries B's finding", () => {
    const bOnly = byKind("b_only");
    expect(bOnly).toHaveLength(1);
    expect(bOnly[0].title).toBe("Cobalt Strike C2 beacon");
    expect(bOnly[0].finding?.id).toBe("g3");
    expect(bOnly[0].bSeverity).toBe("High");
    expect(bOnly[0].status).toBe("pending");
  });

  it("flags a finding model A has that model B dropped (a_only) and carries A's finding", () => {
    const aOnly = byKind("a_only");
    expect(aOnly.map((d) => d.title)).toEqual(["Benign admin task"]);
    expect(aOnly[0].finding?.id).toBe("f2");
  });

  it("flags a severity disagreement on a shared finding with both severities", () => {
    const sev = byKind("severity");
    expect(sev).toHaveLength(1);
    expect(sev[0].title).toBe("Suspicious logon");
    expect(sev[0].aSeverity).toBe("Medium");
    expect(sev[0].bSeverity).toBe("High");
    expect(sev[0].finding?.id).toBe("f3"); // A's finding, so we can update its severity in place
  });

  it("flags MITRE technique add/remove deltas by id", () => {
    expect(byKind("mitre_added").map((d) => d.title)).toContain("T1071");
    expect(byKind("mitre_removed").map((d) => d.title)).toContain("T1078");
  });

  it("does not flag the agreed finding (same title + severity)", () => {
    expect(deltas.find((d) => d.title === "Mimikatz credential dumping")).toBeUndefined();
  });

  it("assigns stable, unique ids", () => {
    const ids = deltas.map((d) => d.id);
    expect(new Set(ids).size).toBe(ids.length);
    // stable across rebuilds
    expect(buildSecondOpinionDeltas(A, B).map((d) => d.id)).toEqual(ids);
  });
});

describe("buildSecondOpinion + mergeReconcileVerdicts", () => {
  it("counts agreements (shared finding titles)", () => {
    const so = buildSecondOpinion({ a: A, b: B, modelA: "claude", modelB: "gpt", now: () => "2026-06-15T00:00:00.000Z" });
    expect(so.agreementCount).toBe(2); // Mimikatz + Suspicious logon (shared by title)
    expect(so.modelA).toBe("claude");
    expect(so.modelB).toBe("gpt");
    expect(so.generatedAt).toBe("2026-06-15T00:00:00.000Z");
  });

  it("merges reconcile verdicts (rationale + recommendation) onto the matching deltas by id", () => {
    const so = buildSecondOpinion({ a: A, b: B, modelA: "a", modelB: "b", now: () => "t" });
    const target = so.deltas.find((d) => d.kind === "b_only")!;
    const merged = mergeReconcileVerdicts(so, {
      summary: "B is more thorough on C2.",
      verdicts: [
        { id: target.id, rationale: "Beacon backed by event e9 + IOC i9.", recommendation: "accept_b" },
        { id: "bogus-id", rationale: "ignored", recommendation: "keep_a" },
      ],
    });
    const after = merged.deltas.find((d) => d.id === target.id)!;
    expect(after.rationale).toBe("Beacon backed by event e9 + IOC i9.");
    expect(after.recommendation).toBe("accept_b");
    expect(merged.summary).toBe("B is more thorough on C2.");
    // untouched deltas keep their defaults
    expect(merged.deltas.find((d) => d.kind === "a_only")!.recommendation).toBe("review");
  });

  it("reconcileResponseSchema is lenient — a bad recommendation falls back to review", () => {
    const parsed = reconcileResponseSchema.parse({ summary: "s", verdicts: [{ id: "x", rationale: "r", recommendation: "nonsense" }] });
    expect(parsed.verdicts[0].recommendation).toBe("review");
  });

  it("buildReconcilePrompt lists each delta id, both findings, and asks for raw JSON", () => {
    const so = buildSecondOpinion({ a: A, b: B, modelA: "a", modelB: "b", now: () => "t" });
    const prompt = buildReconcilePrompt(A, B, so.deltas);
    expect(prompt).toContain("Cobalt Strike C2 beacon");
    expect(prompt).toContain(so.deltas[0].id);
    expect(prompt.toLowerCase()).toContain("json");
  });
});

describe("applyAcceptedSecondOpinion", () => {
  function recordWith(mutate: (so: SecondOpinion) => SecondOpinion): SecondOpinion {
    return mutate(buildSecondOpinion({ a: A, b: B, modelA: "a", modelB: "b", now: () => "t" }));
  }

  it("does nothing for pending/rejected deltas", () => {
    const so = buildSecondOpinion({ a: A, b: B, modelA: "a", modelB: "b", now: () => "t" });
    const out = applyAcceptedSecondOpinion(A, so);
    expect(out.findings).toEqual(A.findings);
    expect(out.mitreTechniques).toEqual(A.mitreTechniques);
  });

  it("adds an accepted b_only finding to the case (deterministic id, dedup by title, idempotent)", () => {
    let so = buildSecondOpinion({ a: A, b: B, modelA: "a", modelB: "b", now: () => "t" });
    const bOnly = so.deltas.find((d) => d.kind === "b_only")!;
    so = setDeltaStatus(so, bOnly.id, "accepted");
    const out1 = applyAcceptedSecondOpinion(A, so);
    const added = out1.findings.find((f) => f.title === "Cobalt Strike C2 beacon");
    expect(added).toBeDefined();
    expect(out1.findings).toHaveLength(A.findings.length + 1);
    // idempotent — re-applying does not duplicate
    const out2 = applyAcceptedSecondOpinion(out1, so);
    expect(out2.findings.filter((f) => f.title === "Cobalt Strike C2 beacon")).toHaveLength(1);
  });

  it("dismisses an accepted a_only finding in place (keeps the finding, marks it dismissed)", () => {
    let so = buildSecondOpinion({ a: A, b: B, modelA: "a", modelB: "b", now: () => "t" });
    const aOnly = so.deltas.find((d) => d.kind === "a_only")!;
    so = setDeltaStatus(so, aOnly.id, "accepted");
    const out = applyAcceptedSecondOpinion(A, so);
    const f = out.findings.find((x) => x.title === "Benign admin task")!;
    expect(f.status).toBe("dismissed");
    expect(out.findings).toHaveLength(A.findings.length);
  });

  it("applies an accepted severity change in place", () => {
    let so = buildSecondOpinion({ a: A, b: B, modelA: "a", modelB: "b", now: () => "t" });
    const sev = so.deltas.find((d) => d.kind === "severity")!;
    so = setDeltaStatus(so, sev.id, "accepted");
    const out = applyAcceptedSecondOpinion(A, so);
    expect(out.findings.find((x) => x.title === "Suspicious logon")!.severity).toBe("High");
  });

  it("adds/removes accepted MITRE technique deltas", () => {
    let so = buildSecondOpinion({ a: A, b: B, modelA: "a", modelB: "b", now: () => "t" });
    const add = so.deltas.find((d) => d.kind === "mitre_added")!;
    const rm = so.deltas.find((d) => d.kind === "mitre_removed")!;
    so = setDeltaStatus(so, add.id, "accepted");
    so = setDeltaStatus(so, rm.id, "accepted");
    const out = applyAcceptedSecondOpinion(A, so);
    const ids = out.mitreTechniques.map((t) => t.id);
    expect(ids).toContain("T1071");
    expect(ids).not.toContain("T1078");
  });

  it("setDeltaStatus is immutable and only touches the target", () => {
    const so = buildSecondOpinion({ a: A, b: B, modelA: "a", modelB: "b", now: () => "t" });
    const id = so.deltas[0].id;
    const next = setDeltaStatus(so, id, "rejected");
    expect(so.deltas[0].status).toBe("pending"); // original untouched
    expect(next.deltas[0].status).toBe("rejected");
    expect(next.deltas.slice(1)).toEqual(so.deltas.slice(1));
  });
});
