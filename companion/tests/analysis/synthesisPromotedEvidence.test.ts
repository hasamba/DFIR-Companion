import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";
import { promotionSource } from "../../src/analysis/ai/promotedEvidence.js";

// #1586 — the missed-evidence review promoted the AES encryptor loop, lubrute.ps1 and adbrute.ps1
// into the forensic timeline of a ransomware lab case, and the next synthesis still said "no
// encryption or data-destruction impact was observed". The model could not tell the rows were new,
// could not see what its own findings had said, and some of the rows never reached the prompt.
// This suite is built on that case's shape.

const JEV = "[missed-evidence: Medium conf 90 by typesafe/jev-1.13]";
const NEW_TAG = "⟨promoted: missed-evidence review · NEW since last synthesis⟩";
const OLD_TAG = "⟨promoted: missed-evidence review⟩";

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-08-28T09:00:00Z",
    description: `event ${id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    ...over,
  };
}

function promoted(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return ev(id, { promotedAt: "2026-09-24T10:00:00.000Z", provenance: [JEV], ...over });
}

const F12: Finding = {
  id: "f12",
  severity: "High",
  title: "Ransomware staging without observed impact",
  description:
    "Staging via miparser.vbs and netsh Network Discovery. No encryption or data-destruction impact was observed.",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1486"],
  firstSeen: "2026-08-28T08:00:00Z",
  lastUpdated: "2026-08-28T08:00:00Z",
  status: "open",
  relatedEventIds: ["e-stage"],
};

let cases: CaseStore;
let stateStore: StateStore;
let prompts: string[];
let failNext: boolean;

function pipeline(): AnalysisPipeline {
  const analyze = vi.fn(async (req: { userPrompt?: string }) => {
    prompts.push(req.userPrompt ?? "");
    if (failNext) throw new Error("model down");
    return {
      rawText: JSON.stringify({
        findings: [F12],
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "",
        summary: "",
      }),
    };
  });
  return new AnalysisPipeline({
    stateStore,
    synthMetaStore: new SynthMetaStore(cases),
    synthesisProvider: { name: "fake", analyze } as never,
    retries: 0,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });
}

async function seed(events: ForensicEvent[], findings: Finding[] = [F12]): Promise<void> {
  const s: InvestigationState = emptyState("c1");
  s.forensicTimeline.push(...events);
  s.findings.push(...findings);
  await stateStore.save(s);
}

const lineOf = (prompt: string, id: string): string =>
  prompt.split("\n").find((l) => l.includes(`[${id}]`)) ?? "";

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-promoted-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  prompts = [];
  failNext = false;
});

afterEach(() => {
  delete process.env.DFIR_AI_SYNTH_MAX_EVENTS;
});

const LAB_ROWS = (): ForensicEvent[] => [
  ev("e-stage", { timestamp: "2026-08-28T08:59:00Z", description: "wscript miparser.vbs" }),
  promoted("e-aes", {
    timestamp: "2026-08-28T09:04:47Z",
    severity: "Medium",
    description: "PowerShell script block: $aes.CreateEncryptor() loop over C:\\Users",
  }),
  promoted("e-lubrute", {
    timestamp: "2026-08-28T09:00:10Z",
    severity: "Info",
    description: "Script block starts lubrute.ps1",
  }),
  promoted("e-adbrute", {
    timestamp: "2026-08-28T09:00:47Z",
    severity: "Low",
    description: "Script block starts adbrute.ps1",
  }),
];

describe("newly promoted rows reach the synthesis prompt, marked as new (#1586)", () => {
  it("tags each promoted row and lists the new ones with the instruction to re-check findings", async () => {
    await seed(LAB_ROWS());
    await pipeline().synthesize("c1", { force: true });
    const p = prompts[0];
    expect(lineOf(p, "e-aes")).toContain(NEW_TAG);
    expect(lineOf(p, "e-adbrute")).toContain(NEW_TAG);
    expect(lineOf(p, "e-stage")).not.toContain("⟨promoted");
    expect(p).toMatch(/NEWLY PROMOTED EVIDENCE \(3 rows?/);
    for (const id of ["e-aes", "e-lubrute", "e-adbrute"])
      expect(p).toMatch(new RegExp(`NEWLY PROMOTED[\\s\\S]*\\[${id}\\]`));
    expect(p).toMatch(/contradicts a finding/);
    expect(p).not.toMatch(/timelineNote/); // the system prompt requires timelineNote to be ""
  });

  it("shows a promoted Info row, which the prompt otherwise leaves out", async () => {
    await seed(LAB_ROWS());
    await pipeline().synthesize("c1", { force: true });
    expect(lineOf(prompts[0], "e-lubrute")).toContain(NEW_TAG);
  });

  it("echoes what each existing finding said, so a re-run can keep its details", async () => {
    await seed(LAB_ROWS());
    await pipeline().synthesize("c1", { force: true });
    const p = prompts[0];
    expect(p).toMatch(/said: Staging via miparser\.vbs and netsh Network Discovery\. No encryption/);
    expect(p).toMatch(/cites: e-stage/);
    expect(p).toMatch(/Keep every concrete detail/);
  });

  it("after a run has shown them, the rows stay tagged promoted but are no longer new", async () => {
    await seed(LAB_ROWS());
    const pl = pipeline();
    await pl.synthesize("c1", { force: true });
    await pl.synthesize("c1", { force: true });
    const p = prompts[1];
    expect(lineOf(p, "e-aes")).toContain(OLD_TAG);
    expect(lineOf(p, "e-aes")).not.toContain("NEW");
    expect(p).not.toContain("NEWLY PROMOTED EVIDENCE");
    expect(lineOf(p, "e-lubrute")).toBe(""); // an old promoted Info row gets no seat again
  });

  it("a run that fails does not count its rows as seen", async () => {
    await seed(LAB_ROWS());
    const pl = pipeline();
    failNext = true;
    await pl.synthesize("c1", { force: true }).catch(() => undefined);
    failNext = false;
    await pl.synthesize("c1", { force: true });
    expect(lineOf(prompts[prompts.length - 1], "e-aes")).toContain(NEW_TAG);
  });

  it("a new promoted row keeps its seat when the event cap is tight", async () => {
    process.env.DFIR_AI_SYNTH_MAX_EVENTS = "4";
    const crowd = Array.from({ length: 12 }, (_, i) =>
      ev(`h${i}`, {
        timestamp: `2026-08-28T0${i % 10}:1${i % 6}:00Z`,
        description: `distinct high ${i}`,
        asset: `H${i}`,
      }),
    );
    await seed([
      ...crowd,
      promoted("p-low", {
        severity: "Low",
        timestamp: "2026-08-28T09:59:00Z",
        description: "late promoted low",
      }),
    ]);
    await pipeline().synthesize("c1", { force: true });
    expect(lineOf(prompts[0], "p-low")).toContain(NEW_TAG);
  });

  it("a new promoted row inside a detection burst is shown on its own line", async () => {
    const burst = Array.from({ length: 6 }, (_, i) =>
      ev(`b${i}`, {
        severity: "Medium",
        timestamp: `2026-08-28T09:0${i}:00Z`,
        description: "Sigma: Suspicious PowerShell download cradle",
      }),
    );
    burst[4] = { ...burst[4], promotedAt: "2026-09-24T10:00:00.000Z", provenance: [JEV] };
    await seed(burst);
    await pipeline().synthesize("c1", { force: true });
    expect(lineOf(prompts[0], "b4")).toContain(NEW_TAG);
  });

  it("a later promotion merged into a row the model already saw counts as new again", async () => {
    await seed(LAB_ROWS());
    const pl = pipeline();
    await pl.synthesize("c1", { force: true });
    // Correlation keeps the representative's id and the LATEST member stamp, so a fresh promotion
    // that merges into e-aes arrives as e-aes with a newer promotedAt.
    const s = await stateStore.load("c1");
    await stateStore.save({
      ...s,
      forensicTimeline: s.forensicTimeline.map((e) =>
        e.id === "e-aes" ? { ...e, promotedAt: "2026-09-25T08:00:00.000Z" } : e,
      ),
    });
    await pl.synthesize("c1");
    expect(prompts).toHaveLength(2);
    expect(lineOf(prompts[1], "e-aes")).toContain(NEW_TAG);
  });

  it("new promoted rows beyond the pin cap still take free seats", async () => {
    const WORDS =
      "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar".split(
        " ",
      );
    process.env.DFIR_AI_SYNTH_MAX_EVENTS = "20"; // pin cap = 10
    const many = Array.from({ length: 15 }, (_, i) =>
      promoted(`m${i}`, {
        severity: "Medium",
        timestamp: `2026-08-28T09:${String(10 + i).padStart(2, "0")}:00Z`,
        description: `${WORDS[i]} activity`, // distinct words: digits alone collapse into one burst pattern
        asset: `M${i}`,
      }),
    );
    await seed(many);
    await pipeline().synthesize("c1", { force: true });
    const p = prompts[0];
    for (let i = 0; i < 15; i++) expect(lineOf(p, `m${i}`)).toContain(NEW_TAG);
    expect(p).toMatch(/NEWLY PROMOTED EVIDENCE \(15 rows/);
    expect(p).not.toMatch(/did not fit this prompt/);
  });

  it("stamping a row already in the timeline as promoted triggers a fresh synthesis", async () => {
    await seed([ev("e1"), ev("e2", { timestamp: "2026-08-28T10:00:00Z", description: "second" })]);
    const pl = pipeline();
    await pl.synthesize("c1");
    const s = await stateStore.load("c1");
    await stateStore.save({
      ...s,
      forensicTimeline: s.forensicTimeline.map((e) =>
        e.id === "e2" ? { ...e, promotedAt: "2026-09-24T11:00:00.000Z", provenance: [JEV] } : e,
      ),
    });
    await pl.synthesize("c1");
    expect(prompts).toHaveLength(2);
    expect(lineOf(prompts[1], "e2")).toContain(NEW_TAG);
  });
});

describe("where a promoted row came from", () => {
  it("names the review, the second look and the analyst, and nothing for an incidental copy", () => {
    expect(promotionSource(ev("a", { promotedAt: "x", provenance: [JEV] }))).toBe("missed-evidence review");
    expect(promotionSource(ev("a", { promotedAt: "x", provenance: ["[second-look: h2]"] }))).toBe(
      "second look",
    );
    expect(promotionSource(ev("a", { promotedAt: "x", provenance: ["[promoted]"] }))).toBe("analyst");
    expect(promotionSource(ev("a", { promotedAt: "x" }))).toBeUndefined();
  });
});
