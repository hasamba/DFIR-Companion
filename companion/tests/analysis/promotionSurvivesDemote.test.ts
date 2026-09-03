import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { demoteBelowSeverity } from "../../src/analysis/forensicGate.js";
import { MockProvider } from "../../src/providers/provider.js";

// An analyst promotes a raw super-timeline row (Info) into the forensic timeline — via the
// Super-Timeline panel, explain-event, a starred report or the second-look loop; all four go
// through pipeline.promoteSuperTimeline. The row is still Info, and the NEXT import's demote pass
// (importIngest.demoteForensicForCase → demoteBelowSeverity) removed it again, silently undoing
// the promotion. The stamp set here is what the gate honours.

const ev = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: "e1",
  timestamp: "2026-05-12T08:00:00Z",
  description: "d",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources: [],
  ...over,
});

async function harness(rawEvents: ForensicEvent[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-promote-demote-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save(emptyState("c1"));
  const superTimelineStore = new SuperTimelineStore(cases);
  await superTimelineStore.append("c1", rawEvents);
  const provider = new MockProvider("mock", "{}");
  const pipeline = new AnalysisPipeline({
    provider,
    stateStore,
    superTimelineStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  return { pipeline, stateStore };
}

describe("a promoted super-timeline row survives the next import's demote pass", () => {
  it("stamps promotedAt on the promoted rows and the forensic gate keeps them", async () => {
    const raw = [
      ev({ id: "raw1", description: "netstat: 10.0.0.5 → 185.220.101.33:443", asset: "WS-01" }),
      ev({ id: "raw2", description: "email: payroll lure", asset: "WS-01" }),
    ];
    const { pipeline, stateStore } = await harness(raw);

    await pipeline.promoteSuperTimeline("c1", raw, { importedAt: "2026-09-03T12:00:00.000Z" });

    const state = await stateStore.load("c1");
    const promoted = state.forensicTimeline.filter((e) => e.id === "raw1" || e.id === "raw2");
    expect(promoted).toHaveLength(2);
    for (const e of promoted) {
      expect(e.severity).toBe("Info"); // promotion does not forge a verdict
      expect(e.promotedAt).toBe("2026-09-03T12:00:00.000Z");
    }

    // What the next import runs over the forensic timeline: the promoted rows must not fall out.
    const { kept, demoted } = demoteBelowSeverity(state.forensicTimeline, "Low");
    expect(kept.map((e) => e.id).sort()).toEqual(["raw1", "raw2"]);
    expect(demoted).toHaveLength(0);
  });

  it("keeps an earlier stamp when the same row is promoted again", async () => {
    const raw = [ev({ id: "raw1" })];
    const { pipeline, stateStore } = await harness(raw);
    await pipeline.promoteSuperTimeline("c1", raw, { importedAt: "2026-09-01T00:00:00.000Z" });
    await pipeline.promoteSuperTimeline("c1", raw, { importedAt: "2026-09-02T00:00:00.000Z" });
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.find((e) => e.id === "raw1")?.promotedAt).toBe("2026-09-01T00:00:00.000Z");
  });
});

describe("demoteBelowSeverity", () => {
  it("never demotes a row carrying promotedAt, whatever its severity", () => {
    const events = [
      ev({ id: "info-promoted", severity: "Info", promotedAt: "2026-09-03T12:00:00.000Z" }),
      ev({ id: "info-raw", severity: "Info" }),
      ev({ id: "low", severity: "Low" }),
    ];
    const { kept, demoted } = demoteBelowSeverity(events, "Medium");
    expect(kept.map((e) => e.id)).toEqual(["info-promoted"]);
    expect(demoted.map((e) => e.id)).toEqual(["info-raw", "low"]);
  });
});
