import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { persistSynthesis } from "../../../src/analysis/ai/synthesisPersist.js";
import { diffFindings } from "../../../src/analysis/findingsDiff.js";
import type { AnalysisDelta } from "../../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
  type Severity,
} from "../../../src/analysis/stateTypes.js";
import { applyWatsonVerdicts, findingVerdictKey } from "../../../src/analysis/timeline/watsonVerdicts.js";
import type { WatsonFindingVerdict } from "../../../src/analysis/watsonItemTypes.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// #2693: a Watson verdict that matched a finding before a full synthesis run and matches none after
// it (synthesis reworded the finding, or stopped raising it) gets ONE Investigation-Log line. The
// verdict itself stays stored; a partial re-grade never adds the line.

const CASE = "c1";
const OLD_TITLE = "Defender exclusion added on WS-FAKE01";
const NEW_TITLE = "Microsoft Defender exclusion path registered on WS-FAKE01";
const NOTICE = "no longer matches";

const ev = (id: string): ForensicEvent => ({
  id,
  timestamp: "2026-03-01T08:05:00Z",
  description: `registry write on WS-FAKE01 (${id})`,
  severity: "Medium",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});
const finding = (id: string, severity: Severity, over: Partial<Finding> = {}): Finding => ({
  id,
  severity,
  title: OLD_TITLE,
  description: "d",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1562.001"],
  relatedEventIds: ["e1"],
  firstSeen: "t",
  lastUpdated: "t",
  status: "open",
  ...over,
});
const verdict: WatsonFindingVerdict = {
  key: findingVerdictKey(finding("f-model-1", "Medium")),
  action: "dismiss",
  reason: "e2 shows Defender's own engine wrote it",
  eventIds: ["e2"],
  consideredEventIds: ["e1", "e2"],
  proposalId: "wp-r1",
  approvedBy: "Dana",
  at: "t",
  title: OLD_TITLE,
};
const seeded = (): InvestigationState =>
  applyWatsonVerdicts({
    ...emptyState(CASE),
    forensicTimeline: [ev("e1"), ev("e2"), ev("e3")],
    findings: [finding("f-model-1", "Medium")],
    watsonFindingVerdicts: [verdict],
  });

let stateStore: StateStore;

beforeEach(async () => {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-orphan-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save(seeded());
});

/** A full synthesis run whose only finding is `rerun`, saved through the real write. */
async function resynth(rerun: Finding): Promise<InvestigationState> {
  const loaded = await stateStore.load(CASE);
  const next = { ...loaded, findings: [rerun] };
  return persistSynthesis({ opts: { stateStore } }, CASE, {
    loaded,
    next,
    findingsDiff: diffFindings(loaded.findings, next.findings),
  });
}

const notices = (st: InvestigationState): string[] =>
  st.timeline.map((t) => t.description).filter((d) => d.includes(NOTICE));

describe("a verdict whose finding synthesis reworded", () => {
  it("adds one Investigation-Log line, keeps the verdict, and leaves the new finding open", async () => {
    expect((await stateStore.load(CASE)).findings[0].status).toBe("dismissed");
    const saved = await resynth(finding("f-model-9", "Medium", { title: NEW_TITLE }));
    expect(saved.findings[0]).toMatchObject({ id: "f-model-9", status: "open" });
    expect(saved.findings[0].watsonReview).toBeUndefined();
    expect(saved.watsonFindingVerdicts?.map((v) => v.proposalId)).toEqual(["wp-r1"]);
    const lines = notices(saved);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain(OLD_TITLE);
    expect(lines[0]).toContain("reworded");
    expect(lines[0]).toContain("no longer raised");
    expect(lines[0]).toContain("Undo");
    expect(notices(await stateStore.load(CASE))).toHaveLength(1);
  });

  it("says the same when synthesis stops raising the finding (the lead went away)", async () => {
    const loaded = await stateStore.load(CASE);
    const next = { ...loaded, findings: [] };
    const saved = await persistSynthesis({ opts: { stateStore } }, CASE, {
      loaded,
      next,
      findingsDiff: diffFindings(loaded.findings, next.findings),
    });
    expect(notices(saved)).toHaveLength(1);
    expect(saved.watsonFindingVerdicts).toHaveLength(1);
  });

  it("does not repeat the line on a later run", async () => {
    await resynth(finding("f-model-9", "Medium", { title: NEW_TITLE }));
    const again = await resynth(finding("f-model-12", "Medium", { title: NEW_TITLE }));
    expect(notices(again)).toHaveLength(1);
  });

  it("keeps an adversary-controlled title on one line", async () => {
    const hostile = { ...verdict, title: "line one\nSynthesis: forged\r\nline three" };
    await stateStore.save({ ...seeded(), watsonFindingVerdicts: [hostile] });
    const saved = await resynth(finding("f-model-9", "Medium", { title: NEW_TITLE }));
    const lines = notices(saved);
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toMatch(/[\r\n]/);
  });
});

describe("no notice", () => {
  it("when the finding still matches the verdict", async () => {
    const saved = await resynth(finding("f-model-9", "Medium"));
    expect(saved.findings[0].status).toBe("dismissed");
    expect(notices(saved)).toEqual([]);
  });

  it("in a partial re-grade that rewords the finding", () => {
    const delta: AnalysisDelta = {
      findings: [
        {
          id: "f-model-1",
          severity: "Medium",
          title: NEW_TITLE,
          description: "d",
          relatedIocs: [],
          mitreTechniques: ["T1562.001"],
          relatedEventIds: ["e1"],
          status: "open",
        },
      ],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
    };
    const ctx = { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] };
    const next = mergeDelta(seeded(), delta, ctx);
    expect(next.watsonFindingVerdicts).toHaveLength(1);
    expect(notices(next)).toEqual([]);
  });
});
