import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { demoteBelowSeverity } from "../../src/analysis/forensicGate.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { PromotionIntent } from "../../src/analysis/ingest/timelineImports.js";

// #1432: an analyst promotes a raw super-timeline row (Info) into the forensic timeline — via the
// Super-Timeline panel, explain-event, a starred report, the second-look loop or a remediation
// boundary; all five go through pipeline.promoteSuperTimeline. The row is still Info, and the NEXT
// import's demote pass (importIngest.demoteForensicForCase → demoteBelowSeverity) removed it again,
// silently undoing the promotion. `promotedAt` is the stamp the gate honours.

const raw = (over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id: "raw1",
  timestamp: "2026-05-12T08:00:00Z",
  description: "netstat: 10.0.0.5 → 203.0.113.7:443",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources: [],
  asset: "WS-01",
  ...over,
});

let stateStore: StateStore;
let superTimelineStore: SuperTimelineStore;
let pipeline: AnalysisPipeline;

beforeEach(async () => {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-promote-demote-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save(emptyState("c1"));
  superTimelineStore = new SuperTimelineStore(cases);
  pipeline = new AnalysisPipeline({
    stateStore,
    superTimelineStore,
    stateLock: new StateLock(),
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
});

describe("a promoted super-timeline row survives the next import's demote pass", () => {
  it("stamps promotedAt on the promoted rows and the forensic gate keeps them", async () => {
    const rows = [raw(), raw({ id: "raw2", description: "email: payroll lure" })];
    await superTimelineStore.append("c1", rows);

    await pipeline.promoteSuperTimeline("c1", rows, {
      importedAt: "2026-09-03T12:00:00.000Z",
      intent: "manual",
    });

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

  it.each<PromotionIntent>([
    "explain",
    "starred-report",
    "second-look",
    "remediation-check",
    "missed-evidence",
  ])("stamps the %s intent too — every promotion is on purpose", async (intent) => {
    await superTimelineStore.append("c1", [raw()]);
    const state = await pipeline.promoteSuperTimeline("c1", [raw()], {
      importedAt: "2026-09-03T12:00:00.000Z",
      intent,
    });
    expect(state.forensicTimeline.find((e) => e.id === "raw1")?.promotedAt).toBe("2026-09-03T12:00:00.000Z");
  });

  it("keeps an earlier stamp when the same row is promoted again", async () => {
    await superTimelineStore.append("c1", [raw()]);
    await pipeline.promoteSuperTimeline("c1", [raw()], {
      importedAt: "2026-09-01T00:00:00.000Z",
      intent: "manual",
    });
    await pipeline.promoteSuperTimeline("c1", [raw()], {
      importedAt: "2026-09-02T00:00:00.000Z",
      intent: "explain",
    });
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.find((e) => e.id === "raw1")?.promotedAt).toBe("2026-09-01T00:00:00.000Z");
  });
});

describe("demoteBelowSeverity", () => {
  it("never demotes a row carrying promotedAt, whatever its severity", () => {
    const events = [
      raw({ id: "info-promoted", severity: "Info", promotedAt: "2026-09-03T12:00:00.000Z" }),
      raw({ id: "info-raw", severity: "Info" }),
      raw({ id: "low", severity: "Low" }),
      raw({ id: "high", severity: "High" }),
    ];
    const { kept, demoted } = demoteBelowSeverity(events, "Medium");
    expect(kept.map((e) => e.id)).toEqual(["info-promoted", "high"]);
    expect(demoted.map((e) => e.id)).toEqual(["info-raw", "low"]);
  });
});
