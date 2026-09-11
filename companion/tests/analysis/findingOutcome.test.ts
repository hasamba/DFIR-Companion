import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  FindingOutcomeStore,
  MAX_OUTCOME_NOTE_LENGTH,
  withAnalystOutcomes,
  outcomeLabel,
} from "../../src/analysis/findingOutcome.js";
import { findingHeadingSuffix } from "../../src/analysis/findingGrounding.js";
import type { Finding, InvestigationState } from "../../src/analysis/stateTypes.js";

function finding(over: Partial<Finding> & { id: string }): Finding {
  return {
    severity: "High",
    title: "t",
    description: "d",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "2026-01-01T00:00:00Z",
    lastUpdated: "2026-01-01T00:00:00Z",
    status: "open",
    ...over,
  };
}

describe("FindingOutcomeStore", () => {
  let cases: CaseStore;
  let store: FindingOutcomeStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-fout-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new FindingOutcomeStore(cases);
  });

  it("returns [] when nothing is set", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("records an execution outcome with provenance, leaving control unset", async () => {
    const rec = await store.patch("c1", "f-1", { execution: "not-observed", updatedBy: "Alice" });
    expect(rec).not.toBeNull();
    expect(rec!.findingId).toBe("f-1");
    expect(rec!.execution).toBe("not-observed");
    expect(rec!.control).toBeNull();
    expect(rec!.updatedBy).toBe("Alice");
    expect(rec!.updatedAt).toBeTruthy();
  });

  // The whole reason there are two axes: a payload that RAN and was then quarantined must keep both.
  it("holds execution and control independently — observed AND remediated both survive", async () => {
    const rec = await store.patch("c1", "f-1", { execution: "observed", control: "remediated" });
    expect(rec!.execution).toBe("observed");
    expect(rec!.control).toBe("remediated");
  });

  it("merges partial patches: a control-only patch leaves execution intact", async () => {
    await store.patch("c1", "f-1", { execution: "observed" });
    const rec = await store.patch("c1", "f-1", { control: "blocked" });
    expect(rec!.execution).toBe("observed");
    expect(rec!.control).toBe("blocked");
  });

  it("clears the record when both axes and the note become empty", async () => {
    await store.patch("c1", "f-1", { execution: "observed", note: "seen" });
    const rec = await store.patch("c1", "f-1", { execution: null, note: "" });
    expect(rec).toBeNull();
    expect(await store.load("c1")).toEqual([]);
  });

  it('"unknown" is an explicit analyst statement, distinct from unset', async () => {
    const rec = await store.patch("c1", "f-1", { execution: "unknown" });
    expect(rec).not.toBeNull();
    expect(rec!.execution).toBe("unknown");
  });

  it("coerces a value outside the vocabulary to null (defensive)", async () => {
    const rec = await store.patch("c1", "f-1", {
      execution: "prevented" as never,
      control: "blocked",
    });
    expect(rec!.execution).toBeNull();
    expect(rec!.control).toBe("blocked");
  });

  it("caps a very long note and rejects a blank findingId", async () => {
    const rec = await store.patch("c1", "f-1", { note: "x".repeat(MAX_OUTCOME_NOTE_LENGTH + 50) });
    expect(rec!.note).toHaveLength(MAX_OUTCOME_NOTE_LENGTH);
    await expect(store.patch("c1", "   ", { execution: "observed" })).rejects.toThrow(/findingId/);
  });

  it("persists across store instances — a re-synthesis cannot reach this file", async () => {
    await store.patch("c1", "f-1", { control: "blocked" });
    const again = new FindingOutcomeStore(cases);
    expect((await again.load("c1"))[0]?.control).toBe("blocked");
  });
});

describe("withAnalystOutcomes", () => {
  const state = (findings: Finding[]): InvestigationState =>
    ({ findings, forensicTimeline: [], iocs: [], mitreTechniques: [] }) as unknown as InvestigationState;

  it("applies the analyst's axes over the machine's and marks the source", () => {
    const s = state([finding({ id: "f-1", execution: "unknown", control: "allowed" })]);
    const out = withAnalystOutcomes(s, [
      { findingId: "f-1", execution: "observed", control: null, note: "", updatedAt: "", updatedBy: "" },
    ]);
    const f = out.findings[0]!;
    expect(f.execution).toBe("observed"); // analyst wins on the axis they set
    expect(f.control).toBe("allowed"); // machine value survives on the axis they did not
    expect(f.outcomeSource).toBe("analyst");
  });

  it("leaves a finding with no analyst record untouched, and marks a machine-only one", () => {
    const s = state([finding({ id: "f-1", execution: "observed" }), finding({ id: "f-2" })]);
    const out = withAnalystOutcomes(s, []);
    expect(out.findings[0]!.outcomeSource).toBe("machine");
    expect(out.findings[1]!.outcomeSource).toBeUndefined();
    expect(out.findings[1]!.execution).toBeUndefined();
  });

  it("does not mutate its input", () => {
    const f = finding({ id: "f-1" });
    const s = state([f]);
    withAnalystOutcomes(s, [
      { findingId: "f-1", execution: "observed", control: null, note: "", updatedAt: "", updatedBy: "" },
    ]);
    expect(f.execution).toBeUndefined();
  });
});

describe("outcomeLabel", () => {
  it("is empty when nothing is known", () => {
    expect(outcomeLabel(finding({ id: "f" }))).toBe("");
  });

  it("renders both axes and never collapses them into one word", () => {
    const l = outcomeLabel(
      finding({ id: "f", execution: "observed", control: "remediated", outcomeSource: "analyst" }),
    );
    expect(l).toContain("execution observed");
    expect(l).toContain("control remediated");
    expect(l).toContain("analyst");
    expect(l).not.toMatch(/prevented/);
  });

  it("renders one axis alone", () => {
    expect(outcomeLabel(finding({ id: "f", control: "blocked", outcomeSource: "machine" }))).toBe(
      "[control blocked]",
    );
  });

  it("heading suffix keeps the confidence tag exactly as before when no outcome is known", () => {
    expect(findingHeadingSuffix(finding({ id: "f", confidence: 72 }))).toBe(" [72% confidence]");
    expect(findingHeadingSuffix(finding({ id: "f" }))).toBe("");
  });

  it("heading suffix appends the outcome after the confidence tag", () => {
    expect(
      findingHeadingSuffix(
        finding({ id: "f", confidence: 72, control: "blocked", outcomeSource: "analyst" }),
      ),
    ).toBe(" [72% confidence] [control blocked (analyst)]");
  });
});
