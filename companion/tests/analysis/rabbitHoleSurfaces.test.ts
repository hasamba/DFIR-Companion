import { describe, it, expect } from "vitest";
import { buildAuthorizedContextBlock, buildFalsePositiveContext, type FalsePositiveMarker } from "../../src/analysis/falsePositive.js";
import { derivePlaybookTasks } from "../../src/analysis/playbook.js";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";

function marker(partial: Partial<FalsePositiveMarker> & { kind: FalsePositiveMarker["kind"]; ref: string; reason: FalsePositiveMarker["reason"] }): FalsePositiveMarker {
  return { id: `${partial.kind}:${partial.ref}`, note: "", markedAt: "2026-01-01T00:00:00Z", markedBy: "a", ...partial };
}

describe("buildAuthorizedContextBlock (#13 FP-context retention)", () => {
  it("retains authorized-test / known-good-tool markers as shaping context, not erasure", () => {
    const markers = [
      marker({ kind: "finding", ref: "Nessus scan burst", reason: "authorized-test", note: "quarterly pentest" }),
      marker({ kind: "ioc", ref: "10.0.0.9", reason: "known-good-tool", note: "vuln scanner" }),
      marker({ kind: "finding", ref: "random noise", reason: "detection-misfire" }),   // not retained
    ];
    const block = buildAuthorizedContextBlock(markers);
    expect(block).toContain("SANCTIONED ACTIVITY CONTEXT");
    expect(block).toContain("Nessus scan burst");
    expect(block).toContain("10.0.0.9");
    expect(block).not.toContain("random noise");        // detection-misfire is pure exclusion, not context
    // Attacker-hides-in-sanctioned-tooling caveat is present so overlap isn't dismissed.
    expect(block.toLowerCase()).toContain("attackers hide");
  });

  it("returns '' when there are no authorized/known-good markers", () => {
    expect(buildAuthorizedContextBlock([marker({ kind: "finding", ref: "x", reason: "duplicate" })])).toBe("");
  });

  it("does not change the pure-exclusion block's behavior", () => {
    const m = [marker({ kind: "finding", ref: "malware X", reason: "authorized-test", note: "n" })];
    // The exclusion block still lists it (belt and suspenders); the context block adds the nuance.
    expect(buildFalsePositiveContext(m)).toContain("malware X");
  });
});

describe("derivePlaybookTasks rabbit-hole down-weight (#13)", () => {
  function highFinding(id: string, relevance?: Finding["relevance"]): Finding {
    return {
      id, severity: "High", title: `finding ${id}`, description: "d", relatedIocs: [], sourceScreenshots: [],
      mitreTechniques: [], firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z", status: "open",
      ...(relevance ? { relevance } : {}),
    };
  }

  it("demotes a disconnected High finding one notch and reframes it as verify-before-chasing", () => {
    const state: InvestigationState = { ...emptyState("c1"), findings: [highFinding("f1"), highFinding("f2", "disconnected")] };
    const seeds = derivePlaybookTasks(state);
    const lead = seeds.find((s) => s.relatedFindingId === "f1")!;
    const rabbit = seeds.find((s) => s.relatedFindingId === "f2")!;
    expect(lead.priority).toBe("high");
    expect(rabbit.priority).toBe("medium");            // High demoted one notch
    expect(rabbit.title).toContain("possible rabbit hole");
    expect(rabbit.description).toContain("no causal link");
  });
});
