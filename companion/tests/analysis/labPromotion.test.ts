import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { PROMOTED_MARKER, isPendingLabRow } from "../../src/analysis/labIntel.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #932 item 5 part B: what happens when a lab row is promoted into the forensic timeline, and how
// the second-look loop treats lab rows. Promotion carries an INTENT because four callers share it
// and only an analyst's deliberate choice earns the exemption marker.

const SHA = "a".repeat(64);
const labRow = (over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id: "sb1e1",
  timestamp: "2023-09-01T10:00:00Z",
  description: "CAPE sandbox: [run 42] Emotet — invoice.exe score 9/10",
  severity: "High", // a legacy copy: written before part A forced Info
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources: ["CAPEv2"],
  sha256: SHA,
  ...over,
});

let cases: CaseStore;
let stateStore: StateStore;
let superTimelineStore: SuperTimelineStore;
let pipeline: AnalysisPipeline;

beforeEach(async () => {
  cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-labpromo-")));
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

describe("promoting a lab row", () => {
  it("manual promotion normalises the row (origin lab, Info) and stamps the exemption marker", async () => {
    await superTimelineStore.append("c1", [labRow()]);
    const state = await pipeline.promoteSuperTimeline("c1", [labRow()], {
      importedAt: "2026-09-11T12:00:00Z",
      intent: "manual",
    });
    const e = state.forensicTimeline.find((x) => x.id === "sb1e1");
    expect(e?.origin).toBe("lab");
    expect(e?.severity).toBe("Info"); // the sandbox's High is capability, not incident severity
    expect(e?.provenance).toContain(PROMOTED_MARKER);
    expect(isPendingLabRow(e!)).toBe(false);
  });

  it("explain-on-demand promotion normalises but does NOT stamp the exemption — it was incidental", async () => {
    const state = await pipeline.promoteSuperTimeline("c1", [labRow()], {
      importedAt: "2026-09-11T12:00:00Z",
      intent: "explain",
    });
    const e = state.forensicTimeline.find((x) => x.id === "sb1e1");
    expect(e?.origin).toBe("lab");
    expect(e?.severity).toBe("Info");
    expect(e?.provenance ?? []).not.toContain(PROMOTED_MARKER);
    expect(isPendingLabRow(e!)).toBe(true);
  });

  it("second-look promotion of a lab row is refused at the promotion boundary, marker or not", async () => {
    const state = await pipeline.promoteSuperTimeline("c1", [labRow()], {
      importedAt: "2026-09-11T12:00:00Z",
      intent: "second-look",
      tagById: { sb1e1: ["[second-look: h1]"] },
    });
    expect(state.forensicTimeline.find((x) => x.id === "sb1e1")).toBeUndefined();
  });

  it("a host row promoted manually is untouched apart from the marker", async () => {
    const host = labRow({
      id: "h1",
      sources: ["KAPE"],
      description: "prefetch: EVIL.EXE executed",
      severity: "Low",
    });
    const state = await pipeline.promoteSuperTimeline("c1", [host], {
      importedAt: "2026-09-11T12:00:00Z",
      intent: "manual",
    });
    const e = state.forensicTimeline.find((x) => x.id === "h1");
    expect(e?.origin).toBeUndefined();
    expect(e?.severity).toBe("Low");
    expect(e?.provenance).toContain(PROMOTED_MARKER);
  });
});

describe("isPendingLabRow", () => {
  it("is a lab-produced row without the exemption marker; a second-look marker does not exempt", () => {
    expect(isPendingLabRow(labRow())).toBe(true);
    expect(isPendingLabRow(labRow({ provenance: ["[second-look: h1]"] }))).toBe(true);
    expect(isPendingLabRow(labRow({ provenance: [PROMOTED_MARKER] }))).toBe(false);
    expect(isPendingLabRow(labRow({ sources: ["CAPEv2", "KAPE"] }))).toBe(false); // merged: not lab-produced
  });
});

describe("origin is not the model's to assert", () => {
  it("stripAiExtractedFrom removes origin from every model-produced forensic event", async () => {
    const { deltaSchema, stripAiExtractedFrom } = await import("../../src/analysis/responseSchema.js");
    const delta = deltaSchema.parse({
      findings: [],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
      forensicEvents: [
        {
          id: "e1",
          timestamp: "2023-03-15T08:00:00Z",
          description: "process create invoice.exe on WS-01",
          severity: "High",
          mitreTechniques: [],
          relatedFindingIds: [],
          origin: "lab", // a prompt-injected or weak model claiming a host event is lab evidence
        },
      ],
    });
    expect(delta.forensicEvents?.[0]?.origin).toBe("lab"); // the schema transports it …
    expect(stripAiExtractedFrom(delta).forensicEvents?.[0]?.origin).toBeUndefined(); // … the AI guard drops it
  });
});

describe("the promotion marker survives correlation", () => {
  it("a lab/lab merge keeps [promoted] even when the other member's longer description wins primary", async () => {
    const { correlateEvents } = await import("../../src/analysis/correlate.js");
    const manual = labRow({ id: "man", severity: "Info", origin: "lab", provenance: [PROMOTED_MARKER] });
    const incidental = labRow({
      id: "exp",
      severity: "Info",
      origin: "lab",
      description:
        "CAPE sandbox: [run 42] Emotet — invoice.exe score 9/10 — promoted so it could be explained",
    });
    const out = correlateEvents([manual, incidental]);
    expect(out).toHaveLength(1);
    expect(out[0].provenance).toContain(PROMOTED_MARKER);
    expect(isPendingLabRow(out[0])).toBe(false);
  });
});
