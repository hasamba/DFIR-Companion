import { describe, it, expect } from "vitest";
import { loadSynthesisInputs, type SynthesisInputContext } from "../../src/analysis/ai/synthesisInputs.js";
import { buildSynthesisContext } from "../../src/analysis/synthSelect.js";
import { buildConnectiveIocDigest, type IocAnchor } from "../../src/analysis/iocAnchors.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function hyp(n: number) {
  const day = String(n).padStart(2, "0");
  return {
    id: `h${day}`,
    title: `Hyp ${day}`,
    status: "open",
    source: "analyst",
    analystTouched: true,
    exhausted: false,
    expectedOutcome: "",
    createdAt: `2026-01-${day}T00:00:00Z`,
    updatedAt: `2026-01-${day}T00:00:00Z`,
  };
}

function ctxWith(hyps: unknown[]): SynthesisInputContext {
  return {
    opts: {
      hypothesisStore: {
        load: async () => hyps,
        applyExhaustion: async () => undefined,
      },
    },
  } as unknown as SynthesisInputContext;
}

describe("analyst hypotheses block (#1999)", () => {
  it("keeps the newest 15, in a stable order, and says it cut", async () => {
    const hyps = Array.from({ length: 20 }, (_, i) => hyp(i + 1));
    const a = await loadSynthesisInputs(ctxWith(hyps), "c1");
    const b = await loadSynthesisInputs(ctxWith([...hyps].reverse()), "c1");
    const block = a.blocks.analystHypothesesBlock;
    expect(block).toContain("Hyp 20");
    expect(block).toContain("Hyp 06");
    expect(block).not.toContain("Hyp 05");
    expect(block).toContain("(showing 15 of 20 open analyst hypotheses)");
    expect(b.blocks.analystHypothesesBlock).toBe(block);
  });

  it("adds no disclosure when nothing was cut", async () => {
    const r = await loadSynthesisInputs(ctxWith([hyp(1), hyp(2)]), "c1");
    expect(r.blocks.analystHypothesesBlock).not.toContain("showing");
  });
});

function ev(id: string, asset: string, severity: ForensicEvent["severity"]): ForensicEvent {
  return {
    id,
    timestamp: "2026-05-20T09:00:00Z",
    description: `event ${id}`,
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
  };
}

describe("synthesis context caps (#1999)", () => {
  it("ranks malicious verdicts ahead of suspicious ones and discloses the cut", () => {
    const s = emptyState("c1");
    for (let n = 0; n < 30; n++) {
      s.iocs.push({
        id: `s${n}`,
        type: "domain",
        value: `susp${String(n).padStart(2, "0")}.example.com`,
        firstSeen: "",
        enrichments: [{ source: "VT", verdict: "suspicious", score: "", fetchedAt: "" }],
      });
    }
    s.iocs.push({
      id: "m1",
      type: "domain",
      value: "late-malicious.example.com",
      firstSeen: "",
      enrichments: [{ source: "VT", verdict: "malicious", score: "", fetchedAt: "" }],
    });
    const ctx = buildSynthesisContext(s, []);
    expect(ctx).toContain("late-malicious.example.com = malicious");
    expect(ctx).toContain("(showing 25 of 31 threat-intel verdicts)");
    expect(buildSynthesisContext(s, [])).toBe(ctx);
  });

  it("keeps the most connected compromised hosts and discloses the cut", () => {
    const s = emptyState("c1");
    const events: ForensicEvent[] = [];
    for (let n = 0; n < 30; n++) events.push(ev(`e${n}`, `HOST-${String(n).padStart(2, "0")}`, "Critical"));
    const ctx = buildSynthesisContext(s, events);
    expect(ctx).toContain("(showing 25 of 30 compromised assets)");
  });

  it("adds a count line to the connective digest only when anchors were cut", () => {
    const anchor = (value: string): IocAnchor =>
      ({
        value,
        type: "ip",
        hosts: ["A", "B"],
        accounts: [],
        tools: [],
        malicious: false,
        suspicious: false,
        internalConflict: false,
        mentioned: false,
        score: 8,
      }) as IocAnchor;
    const cutDigest = buildConnectiveIocDigest([anchor("1.1.1.1")], 5);
    expect(cutDigest).toContain("(showing 1 of 5 connective indicators)");
    expect(buildConnectiveIocDigest([anchor("1.1.1.1")])).not.toContain("showing");
  });
});
