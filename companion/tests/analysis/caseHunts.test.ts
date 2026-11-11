import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CaseMainSourceStore } from "../../src/analysis/caseMainSourceStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { HUNT_SUGGEST_PROMPT, PLAYBOOK_HUNT_PROMPT } from "../../src/analysis/ai/prompts/index.js";
import {
  LANGUAGE_HUNT_PROMPT,
  PLAYBOOK_LANGUAGE_HUNT_PROMPT,
} from "../../src/analysis/ai/prompts/languageHunt.js";
import type { PlaybookTask } from "../../src/analysis/playbook.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2559: the hunt routing by the case's main evidence source.

let cases: CaseStore;
let stateStore: StateStore;
let mainSourceStore: CaseMainSourceStore;
let requests: Array<{ systemPrompt: string; userPrompt: string }>;
let reply: (systemPrompt: string) => unknown;

function ev(id: string, sources: string[], batch: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: `row ${id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources,
    importBatchId: batch,
    ...over,
  };
}

const finding = (id: string, relatedEventIds: string[]): Finding =>
  ({
    id,
    title: `Finding ${id}`,
    description: "d",
    severity: "High",
    mitreTechniques: [],
    relatedEventIds,
    relatedIocs: [],
    status: "open",
  }) as unknown as Finding;

const task = (id: string, relatedFindingId?: string): PlaybookTask => ({
  id,
  title: `Task ${id}`,
  description: "",
  status: "todo",
  priority: "high",
  source: "custom",
  order: 0,
  createdAt: "2026-04-22T11:41:00Z",
  updatedAt: "2026-04-22T11:41:00Z",
  ...(relatedFindingId ? { relatedFindingId } : {}),
});

async function seed(events: ForensicEvent[], findings: Finding[]): Promise<void> {
  const s = emptyState("c1");
  s.forensicTimeline.push(...events);
  s.findings.push(...findings);
  await stateStore.save(s);
}

function pipeline(): AnalysisPipeline {
  const analyze = vi.fn(async (req: { systemPrompt: string; userPrompt: string }) => {
    requests.push({ systemPrompt: req.systemPrompt, userPrompt: req.userPrompt });
    return { rawText: JSON.stringify(reply(req.systemPrompt)) };
  });
  return new AnalysisPipeline({
    stateStore,
    mainSourceStore,
    superTimelineStore: new SuperTimelineStore(cases),
    synthesisProvider: { name: "fake", analyze } as never,
    imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
  });
}

const csFiles = (n: number): ForensicEvent[] =>
  Array.from({ length: n }, (_, i) => ev(`c${i}`, ["CrowdStrike Falcon"], `cs${i}`));

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-casehunts-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  mainSourceStore = new CaseMainSourceStore(cases);
  requests = [];
  reply = () => ({ suggestions: [] });
});

afterEach(() => {
  delete process.env.DFIR_HUNT_PLATFORMS;
});

describe("fleet hunts by main source (#2559)", () => {
  it("a Velociraptor case sends exactly the VQL request suggestHunts sends", async () => {
    await seed(
      [ev("v1", ["Velociraptor"], "h", { artifactName: "Windows.NTFS.MFT" })],
      [finding("f1", ["v1"])],
    );
    const res = await pipeline().caseHunts.suggest("c1");
    expect(res).toEqual({ suggestions: [] });
    await pipeline().suggestHunts("c1");
    expect(requests).toHaveLength(2);
    expect(requests[0].systemPrompt).toBe(HUNT_SUGGEST_PROMPT);
    expect(requests[0]).toEqual(requests[1]);
  });

  it("a CrowdStrike case asks for CQL behaviour hunts and returns them copy-only", async () => {
    await seed(csFiles(3), [finding("f1", ["c0"])]);
    reply = () => ({
      suggestions: [
        {
          title: "Rundll32 from Office",
          query: "#event_simpleName=ProcessRollup2 | ImageFileName=/rundll32/i",
          relatedFindingIds: ["f1"],
        },
        { title: "Wrong language", query: "SELECT * FROM pslist()" },
      ],
    });
    const res = await pipeline().caseHunts.suggest("c1");
    expect(requests).toHaveLength(1);
    expect(requests[0].systemPrompt).toBe(LANGUAGE_HUNT_PROMPT);
    expect(requests[0].userPrompt).toContain("TARGET LANGUAGE: cql");
    expect(res.suggestions).toEqual([]);
    expect(res.languageHunts).toHaveLength(1);
    expect(res.languageHunts?.[0]).toMatchObject({ language: "cql", platform: "crowdstrike" });
    expect(res.languageHunts?.[0]).not.toHaveProperty("vql");
  });

  it("an M365 case asks for KQL over the sign-in and audit tables", async () => {
    await seed([ev("m1", ["Microsoft 365"], "u1"), ev("m2", ["Entra ID"], "u2")], [finding("f1", ["m1"])]);
    await pipeline().caseHunts.suggest("c1");
    expect(requests[0].userPrompt).toContain("TARGET LANGUAGE: kql-cloud");
    expect(requests[0].userPrompt).toContain("SigninLogs");
  });

  it("an other-cloud case makes no AI call and returns the Query Translator note — never VQL", async () => {
    await seed([ev("a1", ["AWS CloudTrail"], "t1")], [finding("f1", ["a1"])]);
    const res = await pipeline().caseHunts.suggest("c1");
    expect(requests).toHaveLength(0);
    expect(res.suggestions).toEqual([]);
    expect(res.notes?.join(" ")).toMatch(/Query Translator/);
  });

  it("a tenant-only mixed case never falls back to VQL for a finding with no cited evidence", async () => {
    await seed(
      [
        ev("m1", ["Microsoft 365"], "u1", { asset: undefined }),
        ev("o1", ["Okta"], "k1", { asset: undefined }),
      ],
      [finding("f1", [])],
    );
    const res = await pipeline().caseHunts.suggest("c1");
    expect(requests).toHaveLength(0);
    expect(res.suggestions).toEqual([]);
    expect(res.notes?.join(" ")).toMatch(/Query Translator/);
  });

  it("a disabled language falls back to the unchanged VQL path, with a note", async () => {
    process.env.DFIR_HUNT_PLATFORMS = "velociraptor";
    await seed(csFiles(2), [finding("f1", ["c0"])]);
    const res = await pipeline().caseHunts.suggest("c1");
    expect(requests).toHaveLength(1);
    expect(requests[0].systemPrompt).toBe(HUNT_SUGGEST_PROMPT);
    expect(res.notes?.join(" ")).toMatch(/disabled/);
  });

  it("a mixed case runs VQL for Velociraptor findings and CQL for CrowdStrike findings", async () => {
    await seed(
      [ev("c0", ["CrowdStrike Falcon"], "cs0"), ev("v1", ["Velociraptor"], "h", { artifactName: "A" })],
      [finding("f1", ["c0"]), finding("f2", ["v1"])],
    );
    reply = (sys) =>
      sys === HUNT_SUGGEST_PROMPT
        ? {
            suggestions: [
              { title: "keep", vql: "SELECT * FROM pslist()", relatedFindingIds: ["f2"] },
              { title: "drop", vql: "SELECT * FROM netstat()", relatedFindingIds: ["f1"] },
            ],
          }
        : {
            suggestions: [
              { title: "cs", query: "#event_simpleName=DnsRequest", relatedFindingIds: ["f1", "f2"] },
            ],
          };
    const res = await pipeline().caseHunts.suggest("c1");
    expect(requests.map((r) => r.systemPrompt)).toEqual([HUNT_SUGGEST_PROMPT, LANGUAGE_HUNT_PROMPT]);
    expect(requests[1].userPrompt).toContain("[f1]");
    expect(requests[1].userPrompt).not.toContain("[f2]");
    expect(res.suggestions.map((s) => s.title)).toEqual(["keep"]);
    expect(res.languageHunts?.[0].relatedFindingIds).toEqual(["f1"]);
  });

  it("the analyst's override decides the language", async () => {
    await seed(csFiles(3), [finding("f1", ["c0"])]);
    await mainSourceStore.save("c1", "splunk");
    await pipeline().caseHunts.suggest("c1");
    expect(requests[0].userPrompt).toContain("TARGET LANGUAGE: spl");
  });

  it("a regenerate of a language card goes straight to that language", async () => {
    await seed(csFiles(3), [finding("f1", ["c0"])]);
    await pipeline().caseHunts.suggest("c1", { language: "esql", excludeQuery: "FROM logs-* | LIMIT 1" });
    expect(requests[0].userPrompt).toContain("TARGET LANGUAGE: esql");
    expect(requests[0].userPrompt).toContain("ALREADY SUGGESTED");
  });

  it("never shows the model a super-timeline row", async () => {
    await seed(csFiles(2), [finding("f1", ["c0"])]);
    await new SuperTimelineStore(cases).append("c1", [
      ev("raw1", ["CrowdStrike Falcon"], "cs9", { severity: "Info", description: "SUPER_ONLY_MARKER row" }),
    ]);
    await pipeline().caseHunts.suggest("c1");
    expect(requests).toHaveLength(1);
    expect(requests[0].userPrompt).not.toContain("SUPER_ONLY_MARKER");
  });
});

describe("playbook hunt languages (#2559)", () => {
  it("each task uses its finding's evidence on a mixed case; no finding → VQL", async () => {
    await seed(
      [ev("c0", ["CrowdStrike Falcon"], "cs0"), ev("v1", ["Velociraptor"], "h", { artifactName: "A" })],
      [finding("f1", ["c0"]), finding("f2", ["v1"])],
    );
    const plan = await pipeline().caseHunts.planPlaybook("c1", [
      task("t1", "f1"),
      task("t2", "f2"),
      task("t3"),
    ]);
    expect(plan.languages).toEqual({ t1: "cql", t2: "vql", t3: "vql" });
  });

  it("writes per-task queries in the language asked, through its own prompt", async () => {
    await seed(csFiles(2), [finding("f1", ["c0"])]);
    reply = () => ({
      suggestions: [{ taskId: "t1", relevant: true, title: "x", query: "#event_simpleName=ProcessRollup2" }],
    });
    const out = await pipeline().caseHunts.suggestPlaybook("c1", [task("t1", "f1")], "cql");
    expect(requests[0].systemPrompt).toBe(PLAYBOOK_LANGUAGE_HUNT_PROMPT);
    expect(requests[0].systemPrompt).not.toBe(PLAYBOOK_HUNT_PROMPT);
    expect(out).toEqual([expect.objectContaining({ taskId: "t1", language: "cql" })]);
  });
});
