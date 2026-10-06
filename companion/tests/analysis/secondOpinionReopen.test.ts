import { describe, it, expect } from "vitest";
import {
  dropToPrimaryCall,
  keepReopenedDecision,
  markReopenedDecisions,
  primaryCallOf,
  primaryCallSnapshot,
  reopenedCall,
  stampPrimaryCalls,
  type PrimaryCall,
} from "../../src/analysis/secondOpinionReopen.js";
import {
  severityCapOf,
  severityRestoredOf,
  type SeverityCap,
} from "../../src/analysis/findingSeverityRestore.js";
import { carryAcceptedDecisions } from "../../src/analysis/secondOpinionTargets.js";
import type { SecondOpinion, SecondOpinionDelta } from "../../src/analysis/secondOpinion.js";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #1972: an accepted second-opinion decision is reopened when the PRIMARY model's own graded call on
// new evidence differs from both its original call and the analyst's accepted call.

function f(p: Partial<Finding> & Record<string, unknown> = {}): Finding {
  return {
    id: "f1",
    severity: "Medium",
    title: "Advanced IP Scanner executed",
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1046"],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
    semanticKey: "k1",
    relatedEventIds: ["e1"],
    ...p,
  };
}

const call = (severity: Finding["severity"], p: Partial<PrimaryCall> = {}): PrimaryCall => ({
  severity,
  status: "open",
  ...p,
});

// A said High, B said Medium, the analyst accepted Medium.
const SEV: SecondOpinionDelta = {
  id: "severity:k1",
  kind: "severity",
  title: "Advanced IP Scanner executed",
  aSeverity: "High",
  bSeverity: "Medium",
  finding: f({ severity: "High" }),
  rationale: "",
  recommendation: "review",
  status: "accepted",
};
// A said Medium, B left it out, the analyst dismissed it.
const DISMISS: SecondOpinionDelta = {
  ...SEV,
  id: "a_only:k1",
  kind: "a_only",
  aSeverity: "Medium",
  bSeverity: undefined,
  finding: f({ severity: "Medium" }),
};

const record = (deltas: SecondOpinionDelta[]): SecondOpinion => ({
  generatedAt: "2026-10-06T10:00:00.000Z",
  modelA: "a",
  modelB: "b",
  referee: "",
  summary: "",
  agreementCount: 0,
  deltas,
});
const state = (findings: Finding[]): InvestigationState => ({ ...emptyState("c1"), findings });
const withCall = (c: PrimaryCall, p: Partial<Finding> & Record<string, unknown> = {}): Finding =>
  f({ ...p, primaryCall: c });

describe("reopenedCall (#1972)", () => {
  it("reopens a severity decision when the primary makes a genuinely new call", () => {
    expect(reopenedCall([withCall(call("Critical"))], SEV)).toBe("Critical");
    expect(reopenedCall([withCall(call("Low"))], SEV)).toBe("Low");
  });

  it("does not reopen when the primary repeats its overruled call", () => {
    expect(reopenedCall([withCall(call("High"))], SEV)).toBeUndefined();
  });

  it("does not reopen when the primary now agrees with the accepted call", () => {
    expect(reopenedCall([withCall(call("Medium"))], SEV)).toBeUndefined();
  });

  it("reopens a dismissal only when the primary raises severity above its original call", () => {
    expect(reopenedCall([withCall(call("High"))], DISMISS)).toBe("High");
    expect(reopenedCall([withCall(call("Medium"))], DISMISS)).toBeUndefined();
    expect(reopenedCall([withCall(call("Low"))], DISMISS)).toBeUndefined();
  });

  it("ignores a finding with no primary snapshot, and a decision not accepted", () => {
    expect(reopenedCall([f()], SEV)).toBeUndefined();
    expect(reopenedCall([withCall(call("Critical"))], { ...SEV, status: "rejected" })).toBeUndefined();
  });
});

describe("primaryCallSnapshot + stampPrimaryCalls (#1972)", () => {
  it("snapshots only the targets of accepted severity / dismissal decisions", () => {
    let graded = 0;
    const calls = primaryCallSnapshot(record([SEV]), () => {
      graded += 1;
      return state([f({ severity: "Critical" }), f({ id: "f9", semanticKey: "k9", title: "other" })]);
    });
    expect(graded).toBe(1);
    expect([...calls.keys()]).toEqual(["f1"]);
    expect(calls.get("f1")).toMatchObject({ severity: "Critical", status: "open" });
  });

  it("grades nothing when there is no accepted targeted decision", () => {
    let graded = 0;
    const calls = primaryCallSnapshot(record([{ ...SEV, status: "pending" }]), () => {
      graded += 1;
      return state([]);
    });
    expect(graded).toBe(0);
    expect(calls.size).toBe(0);
  });

  it("keeps the grading cap of the primary's own call", () => {
    const cap = { from: "High", to: "Medium", gates: ["self-disclaimed"] };
    const calls = primaryCallSnapshot(record([SEV]), () => state([f({ severityCap: cap })]));
    expect(calls.get("f1")?.cap).toEqual(cap);
  });

  it("replaces stale snapshots and leaves the input untouched", () => {
    const input = state([withCall(call("Low")), withCall(call("Low"), { id: "f2" })]);
    const out = stampPrimaryCalls(input, new Map([["f1", call("Critical")]]));
    expect(primaryCallOf(out.findings[0])?.severity).toBe("Critical");
    expect(primaryCallOf(out.findings[1])).toBeUndefined();
    expect(primaryCallOf(input.findings[0])?.severity).toBe("Low");
  });
});

describe("markReopenedDecisions (#1972)", () => {
  it("marks the reopened decision for the panel, and only that one", () => {
    const marked = markReopenedDecisions(record([SEV, { ...SEV, id: "other", status: "pending" }]), [
      withCall(call("Critical")),
    ]);
    expect(marked.deltas[0].reopened).toBe("Critical");
    expect(marked.deltas[1].reopened).toBeUndefined();
  });

  it("clears a stale mark, and a carried decision never stores one", () => {
    const stale = record([{ ...SEV, reopened: "Low" }]);
    expect(markReopenedDecisions(stale, [withCall(call("High"))]).deltas[0].reopened).toBeUndefined();
    const carried = carryAcceptedDecisions(stale, record([]));
    expect(carried.deltas[0].reopened).toBeUndefined();
  });
});

describe("Keep and Drop (#1972)", () => {
  it("Keep records the new call as the overruled one, so the decision closes", () => {
    const findings = [withCall(call("Critical"))];
    const kept = keepReopenedDecision(record([SEV]), SEV.id, findings);
    expect(kept.deltas[0]).toMatchObject({ status: "accepted", aSeverity: "Critical", bSeverity: "Medium" });
    expect(reopenedCall(findings, kept.deltas[0])).toBeUndefined();
  });

  it("Keep refuses a decision that is not reopened", () => {
    expect(() => keepReopenedDecision(record([SEV]), SEV.id, [withCall(call("High"))])).toThrow(
      /not reopened/,
    );
  });

  it("Drop puts the finding back on the primary's call", () => {
    const live = state([withCall(call("Critical"), { severity: "Medium" })]);
    const out = dropToPrimaryCall(live, SEV, []).findings[0];
    expect(out.severity).toBe("Critical");
    expect(out.status).toBe("open");
  });

  it("Drop of a dismissal reopens the finding at the primary's call", () => {
    const live = state([withCall(call("High"), { status: "dismissed", severity: "Medium" })]);
    const out = dropToPrimaryCall(live, DISMISS, []).findings[0];
    expect(out).toMatchObject({ status: "open", severity: "High" });
  });

  it("Drop leaves other findings alone, restored or not", () => {
    const cap = { from: "High", to: "Medium", gates: ["tamper-timing"] };
    const other = f({
      id: "f2",
      semanticKey: "k2",
      title: "other",
      severity: "High",
      severityCap: cap,
      severityRestored: { by: "Bob", at: "t" },
    });
    const live = state([withCall(call("Critical"), { severity: "Medium" }), other]);
    expect(dropToPrimaryCall(live, SEV, []).findings[1]).toBe(other);
  });
});

describe("a #1973 severity restore and a reopened decision on one finding (#1972)", () => {
  const cap: SeverityCap = { from: "Critical", to: "High", gates: ["lateral-unconfirmed"] };
  const restore = {
    findingId: "f1",
    semanticKey: "k1",
    restoredBy: "Alice",
    restoredAt: "2026-10-06T10:00:00.000Z",
  };

  it("the restore never decides a reopen: the check reads the graded call before it", () => {
    // Graded primary call High (capped from Critical); the analyst restored Critical on the live finding.
    const live = withCall(call("High", { cap }), {
      severity: "Medium",
      severityCap: cap,
      severityRestored: { by: "Alice", at: "t" },
    });
    expect(reopenedCall([live], SEV)).toBeUndefined(); // High is A's overruled call: no reopen
  });

  it("on Drop the restore wins over the graded call: it lifts the primary's own cap", () => {
    const live = state([withCall(call("High", { cap }), { severity: "Medium" })]);
    const out = dropToPrimaryCall(live, { ...SEV, aSeverity: "Low" }, [restore]).findings[0];
    expect(out.severity).toBe("Critical");
    expect(severityCapOf(out)).toEqual(cap);
    expect(severityRestoredOf(out)?.by).toBe("Alice");
  });

  it("on Drop without a restore the finding takes the primary's graded call and its cap", () => {
    const live = state([withCall(call("High", { cap }), { severity: "Medium" })]);
    const out = dropToPrimaryCall(live, { ...SEV, aSeverity: "Low" }, []).findings[0];
    expect(out.severity).toBe("High");
    expect(severityCapOf(out)).toEqual(cap);
    expect(severityRestoredOf(out)).toBeUndefined();
  });
});
