import { describe, it, expect } from "vitest";
import {
  ASK_HYPOTHESES_MAX,
  ASK_HOST_SCOPE_MAX,
  ASK_MARKS_MAX,
  ASK_NOTEBOOK_MAX,
  renderAskHypothesesBlock,
  renderHostScopeBlock,
  renderDwellWindowsBlock,
  renderAnalystMarksBlock,
  renderAskNotebookBlock,
  renderAskHistoryBlock,
} from "../../src/analysis/ai/askContext.js";
import type { Hypothesis } from "../../src/analysis/hypothesis.js";
import type { HostScopeDecision } from "../../src/analysis/hostScopeStore.js";
import type { DwellWindow } from "../../src/analysis/dwellWindow.js";
import type { Tag } from "../../src/analysis/tags.js";
import type { Comment } from "../../src/analysis/comments.js";
import type { NotebookEntry } from "../../src/analysis/notebookStore.js";

// Pure renderers for the analyst-decision blocks the ask prompt carries (#1411). Each returns ""
// when there is nothing to say, else a legend line + bullets ending in a blank line.

function hyp(p: Partial<Hypothesis> & { id: string; title: string }): Hypothesis {
  return {
    description: "",
    expectedOutcome: "",
    status: "open",
    relatedTechniques: [],
    relatedEventIds: [],
    relatedIocIds: [],
    contradictingEventIds: [],
    discriminator: "",
    exhausted: false,
    exhaustedReason: "",
    assignee: "",
    notes: "",
    source: "analyst",
    analystTouched: false,
    needsReview: false,
    reviewReason: "",
    alternativeIds: [],
    excludedEvidence: [],
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    statusHistory: [],
    ...p,
  };
}

function decision(
  p: Partial<HostScopeDecision> & { host: string; to: HostScopeDecision["to"] },
): HostScopeDecision {
  return {
    from: "unknown",
    reason: "",
    analyst: "alice",
    at: "2026-01-02T00:00:00Z",
    basis: { sources: [], windowCovered: true, tacticsCovered: [], evidenceFingerprint: "" },
    ...p,
  };
}

function tag(p: Partial<Tag> & { targetId: string; label: string }): Tag {
  return {
    id: `t-${p.targetId}-${p.label}`,
    targetType: "event",
    author: "alice",
    createdAt: "2026-01-01T00:00:00Z",
    ...p,
  };
}

function comment(p: Partial<Comment> & { targetId: string; text: string }): Comment {
  return {
    id: `c-${p.targetId}`,
    targetType: "event",
    author: "bob",
    mentions: [],
    createdAt: "2026-01-01T00:00:00Z",
    ...p,
  };
}

describe("renderAskHypothesesBlock", () => {
  it("returns '' with no hypotheses", () => {
    expect(renderAskHypothesesBlock([])).toBe("");
  });

  it("lists every status with its expected outcome and evidence counts, exhausted flagged", () => {
    const out = renderAskHypothesesBlock([
      hyp({
        id: "h1",
        title: "Data left via OneDrive",
        status: "open",
        expectedOutcome: "large egress to onedrive.com",
        relatedEventIds: ["e1", "e2"],
        contradictingEventIds: ["e9"],
      }),
      hyp({ id: "h2", title: "Phish was the entry", status: "refuted", notes: "mail logs clean" }),
      hyp({
        id: "h3",
        title: "RDP brute force",
        status: "open",
        exhausted: true,
        exhaustedReason: "3 hunts empty",
      }),
    ]);
    expect(out).toContain("ANALYST HYPOTHESES");
    expect(out).toContain(
      "- [open] Data left via OneDrive — decided by: large egress to onedrive.com (2 supporting, 1 contradicting event)",
    );
    expect(out).toContain("- [refuted] Phish was the entry — mail logs clean");
    expect(out).toContain("- [exhausted] RDP brute force — 3 hunts empty");
    expect(out).toMatch(/refuted or exhausted .* must NOT be re-asserted/i);
    expect(out.endsWith("\n\n")).toBe(true);
  });

  it("caps the list", () => {
    const many = Array.from({ length: ASK_HYPOTHESES_MAX + 5 }, (_, i) =>
      hyp({ id: `h${i}`, title: `H ${i}` }),
    );
    const out = renderAskHypothesesBlock(many);
    expect(out.split("\n").filter((l) => l.startsWith("- ")).length).toBe(ASK_HYPOTHESES_MAX);
  });
});

describe("renderHostScopeBlock", () => {
  it("returns '' with no decisions", () => {
    expect(renderHostScopeBlock([])).toBe("");
  });

  it("keeps only the latest decision per host and drops hosts whose latest is 'unknown'", () => {
    const out = renderHostScopeBlock([
      decision({ host: "WS01", to: "suspected", at: "2026-01-01T00:00:00Z" }),
      decision({
        host: "WS01",
        to: "cleared",
        reason: "full triage, nothing",
        at: "2026-01-03T00:00:00Z",
        analyst: "carol",
      }),
      decision({ host: "DC01", to: "confirmed", reason: "ntds.dit staged" }),
      decision({ host: "PRN01", to: "out-of-scope", reason: "printer" }),
      decision({ host: "FS01", to: "cleared", at: "2026-01-01T00:00:00Z" }),
      decision({ host: "FS01", to: "unknown", at: "2026-01-04T00:00:00Z" }),
    ]);
    expect(out).toContain("ANALYST HOST-SCOPE DECISIONS");
    expect(out).toContain("- WS01: cleared — full triage, nothing (carol, 2026-01-03)");
    expect(out).not.toContain("WS01: suspected");
    expect(out).toContain("- DC01: confirmed — ntds.dit staged (alice, 2026-01-02)");
    expect(out).toContain("- PRN01: out-of-scope — printer");
    expect(out).not.toContain("FS01");
    expect(out).toMatch(/cleared or out-of-scope host must NOT be named as compromised/i);
  });

  it("caps the list", () => {
    const many = Array.from({ length: ASK_HOST_SCOPE_MAX + 3 }, (_, i) =>
      decision({ host: `H${i}`, to: "cleared" }),
    );
    const out = renderHostScopeBlock(many);
    expect(out.split("\n").filter((l) => l.startsWith("- ")).length).toBe(ASK_HOST_SCOPE_MAX);
  });
});

describe("renderDwellWindowsBlock", () => {
  it("returns '' with no windows", () => {
    expect(renderDwellWindowsBlock([])).toBe("");
  });

  it("renders label + start → end", () => {
    const w: DwellWindow[] = [
      {
        id: "d1",
        label: "Session 1",
        start: "2026-01-01T10:00:00Z",
        end: "2026-01-01T12:30:00Z",
        createdAt: "x",
      },
    ];
    const out = renderDwellWindowsBlock(w);
    expect(out).toContain("ANALYST DWELL WINDOWS");
    expect(out).toContain("- Session 1: 2026-01-01T10:00:00Z → 2026-01-01T12:30:00Z");
  });
});

describe("renderAnalystMarksBlock", () => {
  it("returns '' with nothing marked", () => {
    expect(renderAnalystMarksBlock([], [])).toBe("");
  });

  it("groups tags and comments per target, starred first, then newest first", () => {
    const out = renderAnalystMarksBlock(
      [
        tag({ targetId: "e2", label: "needs-review", createdAt: "2026-01-05T00:00:00Z" }),
        tag({ targetId: "e1", label: "starred", createdAt: "2026-01-01T00:00:00Z" }),
        tag({ targetId: "e1", label: "key-evidence", createdAt: "2026-01-01T00:00:00Z" }),
        tag({
          targetId: "f1",
          targetType: "finding",
          label: "confirmed-malicious",
          createdAt: "2026-01-03T00:00:00Z",
        }),
      ],
      [comment({ targetId: "e1", text: "this is the staging archive", author: "bob" })],
    );
    const lines = out.split("\n").filter((l) => l.startsWith("- "));
    expect(lines[0]).toBe('- [event e1] tags: starred, key-evidence · "this is the staging archive" (bob)');
    expect(lines[1]).toBe("- [event e2] tags: needs-review");
    expect(lines[2]).toBe("- [finding f1] tags: confirmed-malicious");
    expect(out).toContain("ANALYST MARKS");
    expect(out).toMatch(/cite .*event ids/i);
  });

  it("caps at ASK_MARKS_MAX targets", () => {
    const tags = Array.from({ length: ASK_MARKS_MAX + 4 }, (_, i) => tag({ targetId: `e${i}`, label: "x" }));
    const out = renderAnalystMarksBlock(tags, []);
    expect(out.split("\n").filter((l) => l.startsWith("- ")).length).toBe(ASK_MARKS_MAX);
  });

  it("flattens newlines in comment text so one comment stays one line", () => {
    const out = renderAnalystMarksBlock([], [comment({ targetId: "e1", text: "line one\nline two" })]);
    expect(out).toContain('"line one line two"');
  });
});

describe("renderAskNotebookBlock", () => {
  const entry = (i: number, text = `note ${i}`): NotebookEntry => ({
    id: `n${i}`,
    timestamp: `2026-01-${String(i + 1).padStart(2, "0")}T00:00:00Z`,
    text,
    type: "note",
  });

  it("returns '' with no entries", () => {
    expect(renderAskNotebookBlock([])).toBe("");
  });

  it("renders newest first and caps", () => {
    const entries = Array.from({ length: ASK_NOTEBOOK_MAX + 2 }, (_, i) => entry(i));
    const out = renderAskNotebookBlock(entries);
    const lines = out.split("\n").filter((l) => l.startsWith("[NOTE]"));
    expect(lines.length).toBe(ASK_NOTEBOOK_MAX);
    expect(lines[0]).toBe(`[NOTE] note ${ASK_NOTEBOOK_MAX + 1}`);
    expect(out).toContain("ANALYST NOTEBOOK");
  });
});

describe("renderAskHistoryBlock", () => {
  it("returns '' with no turns", () => {
    expect(renderAskHistoryBlock([])).toBe("");
  });

  it("renders Q/A pairs in order", () => {
    const out = renderAskHistoryBlock([
      { question: "Was data exfiltrated?", answer: "Partial — a 2 GB archive left WS01." },
      { question: "To where?", answer: "1.2.3.4:443." },
    ]);
    expect(out).toContain("PRIOR Q&A IN THIS SESSION");
    expect(out).toContain("Q: Was data exfiltrated?\nA: Partial — a 2 GB archive left WS01.");
    expect(out).toContain("Q: To where?\nA: 1.2.3.4:443.");
    expect(out).toMatch(/follow-up/i);
  });
});
