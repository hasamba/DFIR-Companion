import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  coverageSentence,
  huntCoverageFromJobs,
  renderHuntFramingBlock,
} from "../../src/analysis/huntFraming.js";
import { getBuiltInIncidentType } from "../../src/analysis/incidentTypesData.js";
import { parseIncidentType } from "../../src/analysis/incidentTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

const job = (p: Partial<VeloHuntJob>): VeloHuntJob => ({
  bundleId: "b",
  bundleName: "Starter",
  artifacts: ["Windows.Forensics.Prefetch"],
  huntId: "H.1",
  launchedAt: "2026-01-01T00:00:00Z",
  waitMinutes: 10,
  collectAt: "2026-01-01T00:10:00Z",
  status: "imported",
  ...p,
});

const reached = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ clientId: `C.${i}`, hostname: `ws-${i}`, fqdn: "", os: "windows" }));

describe("hunt coverage (#2670)", () => {
  it("says coverage unknown for an uploaded export (no Companion-launched hunt)", () => {
    const c = huntCoverageFromJobs([]);
    expect(c.known).toBe(false);
    expect(coverageSentence(c)).toMatch(/coverage unknown/);
    expect(coverageSentence(c)).toMatch(/no percentage/);
  });

  it("says coverage unknown when a collected hunt has no client-coverage record", () => {
    const c = huntCoverageFromJobs([job({})]);
    expect(c.known).toBe(false);
    expect(coverageSentence(c)).toMatch(/1 collected hunt\(s\) carry no client-coverage record/);
  });

  it("counts only the hosts that answered cleanly and names the gap", () => {
    const c = huntCoverageFromJobs([
      job({ clientCounts: { scheduled: 300, completed: 287, errors: 0 }, reachedClients: reached(287) }),
    ]);
    expect(c).toMatchObject({ known: true, answered: 287, targeted: 300, notAnswered: 13 });
    expect(coverageSentence(c)).toBe(
      "Coverage: 287 host(s) of 300 targeted answered cleanly; 13 did not answer (coverage gap).",
    );
  });

  it("never proves absence for a partial collection", () => {
    const c = huntCoverageFromJobs([
      job({
        clientCounts: { scheduled: 2, completed: 2, errors: 0 },
        reachedClients: reached(2),
        truncatedArtifacts: [{ name: "Windows.Forensics.Prefetch", kept: 10 } as never],
      }),
    ]);
    expect(coverageSentence(c)).toMatch(/1 artifact collection\(s\) were partial, so absence is not proven/);
  });

  describe("partial-collection count: one artifact in two of a job's lists is one collection (#2844)", () => {
    const answered = { clientCounts: { scheduled: 1, completed: 1, errors: 0 }, reachedClients: reached(1) };
    const held = { name: "A.two", error: "held", notImported: "held" as const };
    const cut = (name: string) => ({ name, kept: 10, total: 11 });

    it("counts a held artifact that was also cut short once", () => {
      const c = huntCoverageFromJobs([
        job({ ...answered, truncatedArtifacts: [cut("A.two")], skippedArtifacts: [held] }),
      ]);
      expect(c).toMatchObject({ known: true, partialArtifacts: 1, partialArtifactNames: ["A.two"] });
      expect(coverageSentence(c)).toMatch(/; 1 artifact collection\(s\) were partial/);
    });

    it("counts a held artifact that was also not read in full once", () => {
      const c = huntCoverageFromJobs([
        job({ ...answered, unreadArtifacts: [{ name: "A.two", rows: 5 }], skippedArtifacts: [held] }),
      ]);
      expect(c).toMatchObject({ known: true, partialArtifacts: 1, partialArtifactNames: ["A.two"] });
    });

    it("still counts two different artifacts in one hunt as two", () => {
      const c = huntCoverageFromJobs([
        job({ ...answered, truncatedArtifacts: [cut("A.one")], skippedArtifacts: [held] }),
      ]);
      expect(c).toMatchObject({ known: true, partialArtifacts: 2, partialArtifactNames: ["A.one", "A.two"] });
      expect(coverageSentence(c)).toMatch(/; 2 artifact collection\(s\) were partial/);
    });

    it("still counts the same artifact cut short in two hunts as two collections", () => {
      const c = huntCoverageFromJobs([
        job({ ...answered, huntId: "H.1", truncatedArtifacts: [cut("A.two")] }),
        job({ ...answered, huntId: "H.2", truncatedArtifacts: [cut("A.two")] }),
      ]);
      expect(c).toMatchObject({ known: true, partialArtifacts: 2, partialArtifactNames: ["A.two"] });
    });
  });

  it("de-duplicates a host that answered two hunts", () => {
    const both = { clientCounts: { scheduled: 3, completed: 3, errors: 0 }, reachedClients: reached(3) };
    const c = huntCoverageFromJobs([job({ ...both, huntId: "H.1" }), job({ ...both, huntId: "H.2" })]);
    expect(c.known && c.answered).toBe(3);
  });

  it("ignores a hunt that is still running", () => {
    const c = huntCoverageFromJobs([
      job({
        status: "running",
        clientCounts: { scheduled: 1, completed: 1, errors: 0 },
        reachedClients: reached(1),
      }),
    ]);
    expect(c.known).toBe(false);
  });

  it("frames the hunt: ranks anomalies, verdict within coverage, no forced kill chain", () => {
    const block = renderHuntFramingBlock(huntCoverageFromJobs([]));
    expect(block).toMatch(/^HUNT MODE:/);
    expect(block).toMatch(/Rank anomalies/);
    expect(block).toMatch(/WITHIN COVERAGE/);
    expect(block).toMatch(/Do NOT force a kill chain/);
    expect(block.endsWith("\n\n")).toBe(true);
  });
});

describe("the Threat hunt template (#2670)", () => {
  it("is a built-in type in hunt mode", () => {
    expect(getBuiltInIncidentType("threat-hunt")?.mode).toBe("hunt");
    expect(getBuiltInIncidentType("ransomware")?.mode).toBe("incident");
  });

  it("a custom type written before hunt mode existed loads as an incident type", () => {
    expect(parseIncidentType({ id: "x", name: "X" })?.mode).toBe("incident");
    expect(parseIncidentType({ id: "x", name: "X", mode: "bogus" })?.mode).toBe("incident");
  });
});

// ── synthesis wiring ─────────────────────────────────────────────────────────────────────────────

const SYNTH_DELTA = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  attackerPath: "p",
  summary: "s",
  forensicEvents: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
});

class CapturingProvider implements AIProvider {
  readonly name = "capture";
  readonly model = "capture-model";
  lastReq?: AnalyzeRequest;
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return { rawText: SYNTH_DELTA };
  }
}

const ev = (id: string, minute: number): ForensicEvent => ({
  id,
  timestamp: `2026-01-01T00:${String(minute).padStart(2, "0")}:00Z`,
  description: `powershell -enc AAAA ${id}`,
  severity: "High",
  mitreTechniques: ["T1059.001"],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS-01",
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-hunt-frame-"));
  const cases = new CaseStore(join(root, "cases"));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState("c1"), forensicTimeline: [ev("e1", 0), ev("e2", 1), ev("e3", 2)] });
  const incidentTypeStore = new IncidentTypeStore(cases, join(root, "incident-types"));
  const veloHuntStore = new VeloHuntStore(cases);
  const provider = new CapturingProvider();
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    incidentTypeStore,
    veloHuntStore,
  });
  return { pipeline, provider, incidentTypeStore, cases };
}

describe("hunt framing in synthesis (#2670)", () => {
  it("carries the hunt block and drops the attack-phase digest in a hunt case", async () => {
    const { pipeline, provider, incidentTypeStore } = await harness();
    await incidentTypeStore.saveRecord("c1", "threat-hunt");
    await pipeline.synthesize("c1", { force: true });
    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("HUNT MODE:");
    expect(prompt).toContain("coverage unknown");
    expect(prompt).not.toContain("ATTACK PHASES");
  });

  it("an incident case carries no hunt block and keeps the attack-phase digest", async () => {
    const { pipeline, provider, incidentTypeStore } = await harness();
    await incidentTypeStore.saveRecord("c1", "intrusion");
    await pipeline.synthesize("c1", { force: true });
    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).not.toContain("HUNT MODE:");
    expect(prompt).toContain("ATTACK PHASES");
  });

  it("states the coverage the collected hunts recorded", async () => {
    const { pipeline, provider, incidentTypeStore, cases } = await harness();
    await incidentTypeStore.saveRecord("c1", "threat-hunt");
    const jobs = [
      job({ clientCounts: { scheduled: 5, completed: 4, errors: 0 }, reachedClients: reached(4) }),
    ];
    await writeFile(join(cases.stateDir("c1"), "velo-hunt.json"), JSON.stringify(jobs));
    await pipeline.synthesize("c1", { force: true });
    expect(provider.lastReq!.userPrompt).toContain("Coverage: 4 host(s) of 5 targeted answered cleanly");
  });
});

describe("the hunt framing Watson and synthesis share (#2670)", () => {
  it("is empty outside hunt mode and names approved programs inside it", async () => {
    const { loadHuntFramingFor } = await import("../../src/analysis/huntFramingLoad.js");
    const stores = (typeId: string) => ({
      incidentTypeStore: { loadType: async () => getBuiltInIncidentType(typeId) ?? null },
      veloHuntStore: { list: async () => [] },
      huntInventoryStore: { load: async () => ({ approvedLabels: ["7z.exe in \\program files\\7-zip"] }) },
    });
    expect((await loadHuntFramingFor(stores("ransomware"), "c1")).block).toBe("");
    const hunt = await loadHuntFramingFor(stores("threat-hunt"), "c1");
    expect(hunt.block).toMatch(/^HUNT MODE:/);
    expect(hunt.block).toContain(
      "APPROVED BY CLIENT (the client's reviewed baseline; a detection on these still stands): 7z.exe",
    );
  });

  it("leads Watson's case context", async () => {
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(
      new URL("../../src/analysis/ai/watson/roundContext.ts", import.meta.url),
      "utf8",
    );
    expect(src).toMatch(
      /\(await loadHuntFramingFor\(ctx\.opts, caseId\)\)\.block \+\s*buildSynthesisContext/,
    );
  });
});
