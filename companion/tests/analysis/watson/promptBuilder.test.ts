import { describe, expect, it } from "vitest";
import { buildWatsonUserPrompt } from "../../../src/analysis/ai/watson/promptBuilder.js";
import { ensureStandardQuestions } from "../../../src/analysis/ai/watson/standardQuestions.js";
import { emptyWatsonChat, type WatsonChat, type WatsonTurn } from "../../../src/analysis/ai/watson/types.js";
import { getWatsonPrompt } from "../../../src/analysis/ai/prompts/index.js";
import type { InvestigationQuestion, InvestigationState } from "../../../src/analysis/stateTypes.js";

function question(id: string, extra: Partial<InvestigationQuestion> = {}): InvestigationQuestion {
  return { id, question: `Question text ${id}?`, status: "unknown", answer: "", pointer: "", ...extra };
}

function stateWith(questions: InvestigationQuestion[]): InvestigationState {
  return { keyQuestions: questions } as unknown as InvestigationState;
}

function turn(n: number, text = `turn text ${n}`): WatsonTurn {
  return { id: `t${n}`, at: "2026-01-01T00:00:00Z", role: n % 2 ? "analyst" : "watson", text };
}

function build(
  over: {
    chat?: Partial<WatsonChat>;
    questions?: InvestigationQuestion[];
    paste?: string;
    truncated?: boolean;
  } = {},
) {
  const chat: WatsonChat = { ...emptyWatsonChat(), ...over.chat };
  return buildWatsonUserPrompt({
    state: stateWith(
      over.questions ?? [question("q-one"), question("q-two", { status: "answered", answer: "Phished." })],
    ),
    chat,
    analystText: "Please continue.",
    caseContext: "CASE-CTX-MARKER host example.com",
    mainLanguages: ["kql", "vql"],
    pasteExcerpt:
      over.paste === undefined
        ? undefined
        : { pasteId: "p1", filename: "out.txt", text: over.paste, truncated: over.truncated ?? false },
  });
}

describe("buildWatsonUserPrompt", () => {
  it("contains every Key Question id, status and answer", () => {
    const out = build();
    expect(out).toContain("q-one");
    expect(out).toContain("q-two");
    expect(out).toContain("answered");
    expect(out).toContain("Phished.");
    expect(out).toContain("CASE-CTX-MARKER");
    expect(out).toContain("kql");
    expect(out).toContain("Please continue.");
  });

  it("keeps only the last 12 turns and caps each at 1200 chars", () => {
    const turns = Array.from({ length: 20 }, (_, i) => turn(i + 1));
    turns[19] = turn(20, "x".repeat(5000));
    const out = build({ chat: { turns } });
    expect(out).not.toContain("turn text 8");
    expect(out).toContain("turn text 9");
    expect(out).not.toContain("x".repeat(1201));
    expect(out).toContain("x".repeat(1000));
  });

  it("includes pendingCaseEvents and memory", () => {
    const out = build({
      chat: { pendingCaseEvents: ["Finding F-9 marked false positive"], memory: "MEM-MARKER" },
    });
    expect(out).toContain("CASE CHANGES SINCE LAST ROUND");
    expect(out).toContain("Finding F-9 marked false positive");
    expect(out).toContain("MEM-MARKER");
  });

  it("omits the PASTE block when there is no paste", () => {
    expect(build()).not.toContain("PASTE");
  });

  it("includes a paste and never more than 24000 chars of it", () => {
    const out = build({ paste: "A".repeat(100000), truncated: true });
    expect(out).toContain("PASTE");
    expect(out).toContain("out.txt");
    expect(out).toContain("A".repeat(24000));
    expect(out).not.toContain("A".repeat(24001));
  });
});

describe("getWatsonPrompt", () => {
  it("describes the reply JSON and the fixed rules", () => {
    const p = getWatsonPrompt();
    for (const s of [
      "Watson",
      "workingOn",
      "questionUpdates",
      "newQuestions",
      "search",
      "memory",
      "unanswerable",
      "4000",
    ]) {
      expect(p).toContain(s);
    }
  });
});

describe("ensureStandardQuestions", () => {
  it("adds six pinned watson questions to an empty list", () => {
    const out = ensureStandardQuestions([]);
    expect(out.map((q) => q.id)).toEqual([
      "wq-std-what",
      "wq-std-who",
      "wq-std-when",
      "wq-std-how",
      "wq-std-scope",
      "wq-std-active",
    ]);
    expect(out.every((q) => q.status === "unknown" && q.pinned === true && q.author === "watson")).toBe(true);
  });

  it("is idempotent", () => {
    const once = ensureStandardQuestions([]);
    expect(ensureStandardQuestions(once)).toEqual(once);
  });

  it("keeps existing questions first and never overwrites a standard id", () => {
    const mine = question("analyst-1");
    const edited = question("wq-std-who", { status: "answered", answer: "Done" });
    const out = ensureStandardQuestions([mine, edited]);
    expect(out[0]).toBe(mine);
    expect(out[1]).toBe(edited);
    expect(out).toHaveLength(2 + 5);
    expect(out.filter((q) => q.id === "wq-std-who")).toHaveLength(1);
  });
});
