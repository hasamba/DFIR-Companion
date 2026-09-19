import { describe, it, expect } from "vitest";
import { buildHandoffBrief, HANDOFF_LIST_MAX, HANDOFF_NOTES_MAX } from "../../src/analysis/handoffBrief.js";
import { renderHandoffMarkdown } from "../../src/reports/handoffMarkdown.js";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #1406: the shift-handoff brief — what the case holds, what is open, what to check next — built
// from state the case already has, plus the outgoing analyst's own note. Counts, never verdicts.

const finding = (over: Partial<Finding>): Finding =>
  ({
    id: "f1",
    title: "t",
    description: "d",
    severity: "Medium",
    status: "open",
    confidence: 50,
    relatedIocs: [],
    relatedEventIds: [],
    mitreTechniques: [],
    ...over,
  }) as unknown as Finding;

function state(over: Partial<InvestigationState> = {}): InvestigationState {
  return { ...emptyState("c1"), updatedAt: "2026-09-19T10:00:00Z", ...over };
}

describe("buildHandoffBrief", () => {
  it("counts findings by severity and status, lists the open ones with their workflow owner, unanswered questions, open hypotheses and threads, and the urgent next steps", () => {
    const s = state({
      findings: [
        finding({ id: "f1", title: "Cobalt Strike beacon on WS-01", severity: "Critical" }),
        finding({ id: "f2", title: "Mimikatz dropped", severity: "High" }),
        finding({ id: "f3", title: "Noise", severity: "Low", status: "dismissed" }),
        finding({ id: "f4", title: "Confirmed lateral move", severity: "High", status: "confirmed" }),
      ],
      keyQuestions: [
        { id: "q1", question: "Initial access?", status: "unknown", answer: "", pointer: "check mail logs" },
        { id: "q2", question: "Scope?", status: "partial", answer: "2 hosts", pointer: "WS-03 pending" },
        { id: "q3", question: "Persistence?", status: "answered", answer: "Run key", pointer: "f2" },
      ],
      openThreads: [
        {
          id: "t1",
          description: "Who owns WS-01?",
          status: "open",
          openedAt: "2026-09-18T09:00:00Z",
          closedAt: null,
        },
        {
          id: "t2",
          description: "done",
          status: "closed",
          openedAt: "2026-09-18T09:00:00Z",
          closedAt: "2026-09-18T10:00:00Z",
        },
      ],
      nextSteps: [
        { id: "n1", priority: "critical", action: "Pull 4624 on DC01", rationale: "r", pointer: "DC01" },
        { id: "n2", priority: "low", action: "Tidy", rationale: "r", pointer: "" },
        { id: "n3", priority: "high", action: "Image WS-03", rationale: "r", pointer: "WS-03" },
      ] as never,
      iocs: [
        { id: "i1", type: "ip", value: "203.0.113.9", enrichedBy: ["vt"] },
        { id: "i2", type: "hash", value: "a".repeat(64) },
      ] as never,
    });
    const b = buildHandoffBrief(s, {
      workflow: [
        { findingId: "f1", assignee: "alice", status: "in_progress" },
        { findingId: "f2", assignee: "", status: "resolved" },
      ],
      hypotheses: [
        { title: "Phishing was the entry", status: "open" },
        { title: "USB drop", status: "refuted" },
      ],
      notebook: [
        { id: "n1", timestamp: "2026-09-19T08:00:00Z", text: "Earlier note", type: "handoff", author: "bob" },
        {
          id: "n2",
          timestamp: "2026-09-19T09:30:00Z",
          text: "Check WS-03 first thing.",
          type: "handoff",
          author: "alice",
        },
        { id: "n3", timestamp: "2026-09-19T09:40:00Z", text: "a plain note", type: "note", author: "alice" },
      ],
      importMeta: {
        lastImportedAt: "2026-09-19T07:00:00Z",
        lastImportKind: "kape",
        lastImportFile: "ws-03.zip",
        lastImportSource: "",
      },
    });
    expect(b.caseId).toBe("c1");
    expect(b.stateUpdatedAt).toBe("2026-09-19T10:00:00Z");
    expect(b.lastImport).toEqual({ at: "2026-09-19T07:00:00Z", kind: "kape", source: "ws-03.zip" });
    expect(b.findings.bySeverity).toEqual({ Critical: 1, High: 2, Medium: 0, Low: 1, Info: 0 });
    expect(b.findings.byStatus).toEqual({ open: 2, confirmed: 1, dismissed: 1 });
    // Open = not dismissed by the AI and not resolved by the analyst; ordered by severity.
    expect(b.findings.open.map((f) => f.id)).toEqual(["f1", "f4"]);
    expect(b.findings.open[0]).toMatchObject({
      severity: "Critical",
      assignee: "alice",
      workflowStatus: "in_progress",
    });
    expect(b.findings.open[1]).toMatchObject({ assignee: "", workflowStatus: null });
    expect(b.findings.inProgress).toBe(1);
    expect(b.findings.unassigned).toBe(1);
    expect(b.questions.map((q) => q.status)).toEqual(["unknown", "partial"]);
    expect(b.hypotheses).toEqual([{ title: "Phishing was the entry" }]);
    expect(b.threads).toEqual([{ description: "Who owns WS-01?", openedAt: "2026-09-18T09:00:00Z" }]);
    expect(b.nextSteps.map((n) => n.priority)).toEqual(["critical", "high"]);
    expect(b.iocs).toEqual({ total: 2, unenriched: 1 });
    // Handoff notes only, newest first.
    expect(b.handoffNotes.map((n) => n.author)).toEqual(["alice", "bob"]);
  });

  it("is bounded and says how many it left out", () => {
    const s = state({
      findings: Array.from({ length: HANDOFF_LIST_MAX + 4 }, (_, i) =>
        finding({ id: `f${i}`, title: `f${i}` }),
      ),
    });
    const notes = Array.from({ length: HANDOFF_NOTES_MAX + 2 }, (_, i) => ({
      id: `n${i}`,
      timestamp: `2026-09-19T0${i % 10}:00:00Z`,
      text: `note ${i}`,
      type: "handoff" as const,
    }));
    const b = buildHandoffBrief(s, { notebook: notes });
    expect(b.findings.open).toHaveLength(HANDOFF_LIST_MAX);
    expect(b.findings.openNotShown).toBe(4);
    expect(b.handoffNotes).toHaveLength(HANDOFF_NOTES_MAX);
    expect(b.handoffNotesNotShown).toBe(2);
  });

  it("an empty case is a brief that says so, not an error", () => {
    const b = buildHandoffBrief(state(), {});
    expect(b.findings.open).toEqual([]);
    expect(b.lastImport).toBeNull();
    expect(b.handoffNotes).toEqual([]);
    const md = renderHandoffMarkdown(b);
    expect(md).toContain("## Handoff Brief — c1");
    expect(md).toContain("_No handoff note recorded yet._");
    expect(md).toContain("a count is not a conclusion");
  });

  it("renders Markdown with every adversary-controlled string escaped", () => {
    const s = state({
      findings: [finding({ id: "f1", title: "evil | <script>alert(1)</script> [x](y)", severity: "High" })],
      keyQuestions: [
        {
          id: "q1",
          question: "Q | pipe",
          status: "unknown",
          answer: "",
          pointer: "see `x`\n# not a heading",
        },
      ],
    });
    const md = renderHandoffMarkdown(
      buildHandoffBrief(s, {
        notebook: [
          {
            id: "n1",
            timestamp: "2026-09-19T09:30:00Z",
            text: "# Not a heading\n| a | b |",
            type: "handoff",
            author: "al|ice",
          },
        ],
      }),
    );
    expect(md).not.toContain("<script>");
    expect(md).not.toMatch(/^# Not a heading/m);
    expect(md).toContain("### From the outgoing analyst");
    expect(md).toContain("### Open");
    expect(md).toContain("### Check next");
    expect(md).toContain("Q \\| pipe");
  });
});
