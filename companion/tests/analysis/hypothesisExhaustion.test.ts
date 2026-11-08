import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it, expect } from "vitest";
import {
  applyHypothesisPatch,
  buildAnalystHypothesis,
  hypothesisAutoKey,
  markExhaustedHypotheses,
  mergeHypotheses,
  reconsiderHypotheses,
  type Hypothesis,
  type HypothesisHuntSignal,
  type HypothesisSeed,
} from "../../src/analysis/hypothesis.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import { huntSignalsFromOutcomes, type HuntOutcome } from "../../src/analysis/huntOutcomes.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// Issue #2415: an exhausted hypothesis must not stay exhausted after its status changes or after
// what it tests changes, and once reset it is re-judged only on hunts deployed after the reset.

const T0 = "2026-06-01T00:00:00.000Z";
const T1 = "2026-06-02T00:00:00.000Z";
const T2 = "2026-06-03T00:00:00.000Z";
const T3 = "2026-06-04T00:00:00.000Z";

const miss = (at: string | undefined, id = "h1"): HypothesisHuntSignal => ({
  relatedHypothesisId: id,
  techniques: [],
  missed: true,
  ...(at ? { at } : {}),
});

function exhaustedOpen(): Hypothesis {
  const h = buildAnalystHypothesis(
    {
      title: "Lateral movement via PsExec",
      expectedOutcome: "PSEXESVC service install",
      relatedTechniques: ["T1021.002"],
    },
    "h1",
    T0,
  );
  const { hypotheses } = markExhaustedHypotheses([h], [miss(T0), miss(T0)], T1);
  expect(hypotheses[0].exhausted).toBe(true);
  return hypotheses[0];
}

describe("analyst edits reset exhaustion (#2415)", () => {
  it("clears exhausted when the analyst changes the status", () => {
    const next = applyHypothesisPatch(exhaustedOpen(), { status: "supported" }, T2);
    expect(next.exhausted).toBe(false);
    expect(next.exhaustedReason).toBe("");
    expect(next.exhaustionResetAt).toBe(T2);
  });

  it("set back to open, it is re-judged only on hunts deployed after the change", () => {
    const refuted = applyHypothesisPatch(exhaustedOpen(), { status: "refuted" }, T2);
    const reopened = applyHypothesisPatch(refuted, { status: "open" }, T2);
    expect(reopened.exhausted).toBe(false);
    // The two old misses (deployed at T0) no longer count …
    const old = markExhaustedHypotheses([reopened], [miss(T0), miss(T0)], T3);
    expect(old.changed).toBe(false);
    expect(old.hypotheses[0].exhausted).toBe(false);
    // … a miss with no deployment time cannot be shown to be new …
    expect(markExhaustedHypotheses([reopened], [miss(undefined), miss(undefined)], T3).changed).toBe(false);
    // … a hunt deployed exactly at the reset point is not after it …
    expect(markExhaustedHypotheses([reopened], [miss(T2), miss(T2)], T3).changed).toBe(false);
    // … and two new empty hunts exhaust it again.
    const fresh = markExhaustedHypotheses([reopened], [miss(T0), miss(T3), miss(T3)], T3);
    expect(fresh.hypotheses[0].exhausted).toBe(true);
  });

  it("resets when the expected outcome changes, even before it was exhausted", () => {
    const h = buildAnalystHypothesis({ title: "x", expectedOutcome: "service install" }, "h1", T0);
    const reaimed = applyHypothesisPatch(h, { expectedOutcome: "scheduled task creation" }, T2);
    expect(reaimed.exhaustionResetAt).toBe(T2);
    const exhaustedReaimed = applyHypothesisPatch(exhaustedOpen(), { relatedTechniques: ["T1053.005"] }, T2);
    expect(exhaustedReaimed.exhausted).toBe(false);
  });

  it("does not reset on a wording, case or ordering change, or a notes edit", () => {
    const h = exhaustedOpen();
    const reworded = applyHypothesisPatch(h, { expectedOutcome: "  psexesvc   SERVICE install " }, T2);
    expect(reworded.exhausted).toBe(true);
    const notes = applyHypothesisPatch(h, { notes: "checked DC01" }, T2);
    expect(notes.exhausted).toBe(true);
    expect(notes.exhaustionResetAt).toBe("");
  });
});

describe("other status-change paths reset exhaustion (#2415)", () => {
  const seed = (over: Partial<HypothesisSeed>): HypothesisSeed => ({
    sourceKey: hypothesisAutoKey("Phishing initial access"),
    title: "Phishing initial access",
    description: "",
    expectedOutcome: "malicious attachment opened",
    status: "open",
    relatedTechniques: ["T1566.001"],
    relatedEventIds: [],
    relatedIocIds: [],
    contradictingEventIds: [],
    discriminator: "",
    ...over,
  });
  const exhaustedPristine = (): Hypothesis => {
    const { hypotheses } = mergeHypotheses([], [seed({})], T0);
    const marked = markExhaustedHypotheses(
      hypotheses,
      [miss(T0, hypotheses[0].id), miss(T0, hypotheses[0].id)],
      T1,
    );
    expect(marked.hypotheses[0].exhausted).toBe(true);
    return marked.hypotheses[0];
  };

  it("a synthesis refresh that changes the status clears exhausted", () => {
    const { hypotheses } = mergeHypotheses([exhaustedPristine()], [seed({ status: "supported" })], T2);
    expect(hypotheses[0].exhausted).toBe(false);
    expect(hypotheses[0].exhaustionResetAt).toBe(T2);
  });

  it("a synthesis refresh that changes the techniques clears exhausted", () => {
    const { hypotheses } = mergeHypotheses(
      [exhaustedPristine()],
      [seed({ relatedTechniques: ["T1204.002"] })],
      T2,
    );
    expect(hypotheses[0].exhausted).toBe(false);
  });

  it("a synthesis refresh that only re-words the outcome keeps it exhausted", () => {
    const { hypotheses } = mergeHypotheses(
      [exhaustedPristine()],
      [seed({ expectedOutcome: "the user opened a weaponised attachment" })],
      T2,
    );
    expect(hypotheses[0].exhausted).toBe(true);
  });

  it("the false-positive cascade flipping it to unknown clears exhausted", () => {
    const h = { ...exhaustedPristine(), relatedEventIds: ["e1"] };
    const { hypotheses } = reconsiderHypotheses(
      [h],
      { fpEventIds: new Set(["e1"]), fpIocIds: new Set() },
      T2,
    );
    expect(hypotheses[0].status).toBe("unknown");
    expect(hypotheses[0].exhausted).toBe(false);
  });
});

describe("hunt signals and stored records (#2415)", () => {
  it("dates a hunt signal by deployment, which re-collection does not change", () => {
    const outcome = {
      id: "o1",
      source: "hunt",
      title: "PsExec sweep",
      vqlFingerprint: "",
      vqlPreview: "",
      mitreTechniques: [],
      deployedAt: T0,
      collectedAt: T3,
      status: "collected",
      foundEvidence: false,
    } as unknown as HuntOutcome;
    expect(huntSignalsFromOutcomes([outcome])[0].at).toBe(T0);
  });

  it("loads a stored supported+exhausted record as not exhausted, and keeps the reset point", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hyp-exhaustion-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new HypothesisStore(cases);
    const legacy = { ...exhaustedOpen(), status: "supported" };
    const reset = applyHypothesisPatch(exhaustedOpen(), { status: "refuted" }, T2);
    const other = { ...reset, id: "h2" };
    // Seed the file through the store's own path by adding, then overwriting with the legacy shape.
    await store.add("c1", { title: "placeholder" });
    const path = (store as unknown as { path(id: string): string }).path("c1");
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, JSON.stringify([legacy, other]));
    const loaded = await store.load("c1");
    expect(loaded[0].exhausted).toBe(false);
    expect(loaded[0].exhaustedReason).toBe("");
    expect(loaded[1].exhaustionResetAt).toBe(T2);
  });

  it("counts every miss for a hypothesis that was never reset (unchanged behaviour)", () => {
    const h = buildAnalystHypothesis({ title: "x" }, "h1", T0);
    expect(markExhaustedHypotheses([h], [miss(undefined), miss(undefined)], T1).hypotheses[0].exhausted).toBe(
      true,
    );
  });
});
