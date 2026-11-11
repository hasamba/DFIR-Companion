// #2561: synthesis is told which rows come from an analyst-marked trusted source — a marker on the
// row and a skip-hash input — without changing which rows the model is shown.
import { describe, expect, it } from "vitest";
import { computeSynthHash, type SynthHashInput } from "../../../src/analysis/ai/synthesisInputs.js";
import { createTimelineSelection } from "../../../src/analysis/ai/synthesisPromptEvents.js";
import {
  loadTrustedRows,
  trustedPromptTag,
  type TrustedRows,
} from "../../../src/analysis/ai/synthesisTrust.js";
import { emptyState, type ForensicEvent, type Severity } from "../../../src/analysis/stateTypes.js";

const ev = (id: string, minute: number, severity: Severity, description = `row ${id}`): ForensicEvent => ({
  id,
  timestamp: new Date(Date.parse("2021-07-29T12:00:00Z") + minute * 60_000).toISOString(),
  severity,
  description,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const hashInput = (trusted?: TrustedRows): SynthHashInput => ({
  scopedEvents: [ev("e1", 0, "Medium")],
  iocs: [],
  scope: { mode: "all" } as never,
  markers: [],
  blocks: {} as never,
  observationsBlock: "",
  ...(trusted ? { trusted } : {}),
});

const mark = (value = "203.0.113.10", label: "ours" | "responder" = "responder") => ({ label, value });

describe("computeSynthHash — trusted-source marks", () => {
  it("is unchanged for a case with no mark (no forced re-synthesis on upgrade)", () => {
    expect(computeSynthHash(hashInput(new Map()))).toBe(computeSynthHash(hashInput()));
  });

  it("changes when a row is marked, relabelled, or the value changes", () => {
    const hashes = [
      hashInput(),
      hashInput(new Map([["e1", mark()]])),
      hashInput(new Map([["e1", mark(undefined, "ours")]])),
      hashInput(new Map([["e1", mark("198.51.100.7")]])),
    ].map(computeSynthHash);
    expect(new Set(hashes).size).toBe(4);
  });
});

describe("prompt rendering", () => {
  const rows = [
    ev("a", 0, "High", "attacker grant"),
    ev("b", 5, "Medium", "admin trail setup"),
    ev("c", 9, "Medium"),
  ];
  const state = { ...emptyState("C1"), forensicTimeline: rows };

  it("adds the self-describing marker only to trusted rows and shows the same rows either way", () => {
    const trusted: TrustedRows = new Map([["b", mark()]]);
    const plain = createTimelineSelection(state, rows);
    const marked = createTimelineSelection(state, rows, undefined, undefined, trusted);
    expect(marked.promptEvents.map((e) => e.id)).toEqual(plain.promptEvents.map((e) => e.id));
    const byId = new Map(marked.promptEvents.map((e) => [e.id, marked.renderEvent(e)]));
    expect(byId.get("b")).toContain(
      "[analyst-marked trusted source (responder): 203.0.113.10 — not proven benign]",
    );
    expect(byId.get("a")).not.toContain("trusted source");
    expect(byId.get("c")).not.toContain("trusted source");
  });

  it("the marker wording says it is not proof of benign activity", () => {
    expect(trustedPromptTag(mark())).toMatch(/not proven benign/);
    expect(trustedPromptTag(undefined)).toBe("");
  });

  it("a collapsed burst is marked only when every member is trusted", () => {
    const burst = Array.from({ length: 6 }, (_, i) =>
      ev(`s${i}`, i, "Medium", "Sigma: same detection fired"),
    );
    const st = { ...emptyState("C2"), forensicTimeline: burst };
    const partly: TrustedRows = new Map(burst.slice(0, 5).map((e) => [e.id, mark()]));
    const all: TrustedRows = new Map(burst.map((e) => [e.id, mark()]));
    const render = (t: TrustedRows) => {
      const sel = createTimelineSelection(st, burst, undefined, undefined, t);
      return sel.promptEvents.map((e) => sel.renderEvent(e)).join("\n");
    };
    const grouped = createTimelineSelection(st, burst).grouping.memberIdsByRepresentative.size > 0;
    expect(grouped).toBe(true);
    expect(render(partly)).not.toContain("trusted source");
    expect(render(all)).toContain("trusted source");
  });
});

describe("loadTrustedRows", () => {
  const rows = [ev("e1", 0, "Medium")];
  it("is empty without the stores, and fail-soft on an unreadable label file", async () => {
    expect((await loadTrustedRows({ opts: {} }, "C", rows)).size).toBe(0);
    const warned: string[] = [];
    const ctx = {
      log: { warn: (m: string) => warned.push(m) },
      opts: {
        tagsStore: { taggerTagsFor: async () => [] } as never,
        iocAttributionStore: { load: async () => Promise.reject(new Error("bad json")) } as never,
      },
    };
    expect((await loadTrustedRows(ctx, "C", rows)).size).toBe(0);
    expect(warned[0]).toMatch(/bad json/);
  });
});
