import { describe, it, expect } from "vitest";
import { askJev, type JevQuestion } from "../../src/analysis/ai/jev/jevClient.js";
import {
  ATTACK_TYPE_OPTIONS,
  CHOICE_QUESTION_IDS,
  CONTAINMENT_QUESTION_IDS,
  CONTAINMENT_QUESTIONS,
  QUESTION_LABELS,
  REACH_OPTIONS,
  YESNO_QUESTION_IDS,
} from "../../src/analysis/ai/jev/containmentQuestions.js";

// The containment check asks Jev eleven fixed questions (#1925). The question set is the contract
// the rule reads, so its shape is pinned here: nine yes/no, two choices whose option keys the rule
// branches on, and every one of them accepted by the client's own pre-flight validation.

/** A Jev stand-in that answers every question in the shape its type asks for. */
function stubFetch(seen: { body?: string }): typeof fetch {
  return (async (_url: string, init: { body: string }) => {
    seen.body = init.body;
    const questions = JSON.parse(init.body).questions as Record<string, JevQuestion>;
    const answers: Record<string, unknown> = {};
    for (const [id, q] of Object.entries(questions)) {
      answers[id] =
        q.type === "noul"
          ? { type: "noul", noul: 0.5 }
          : {
              type: "choice",
              choice: Object.keys(q.criteria)[0],
              probabilities: {},
              confidence: 0.7,
            };
    }
    return new Response(JSON.stringify({ model: "jev-stub", answers, usage: {} }), { status: 200 });
  }) as unknown as typeof fetch;
}

const CFG = { baseUrl: "http://jev.example.com/decisions", model: "m", apiKey: "k", timeoutMs: 1000 };

describe("the containment question set", () => {
  it("has eleven questions: nine yes/no and two choices", () => {
    expect(CONTAINMENT_QUESTION_IDS).toHaveLength(11);
    expect(Object.keys(CONTAINMENT_QUESTIONS).sort()).toEqual([...CONTAINMENT_QUESTION_IDS].sort());
    const types = Object.values(CONTAINMENT_QUESTIONS).map((q) => q.type);
    expect(types.filter((t) => t === "noul")).toHaveLength(9);
    expect(types.filter((t) => t === "choice")).toHaveLength(2);
    for (const id of YESNO_QUESTION_IDS) expect(CONTAINMENT_QUESTIONS[id].type).toBe("noul");
    for (const id of CHOICE_QUESTION_IDS) expect(CONTAINMENT_QUESTIONS[id].type).toBe("choice");
  });

  it("offers exactly the option keys the rule branches on", () => {
    const reach = CONTAINMENT_QUESTIONS.reach as Extract<JevQuestion, { type: "choice" }>;
    const attack = CONTAINMENT_QUESTIONS.attack_type as Extract<JevQuestion, { type: "choice" }>;
    expect(Object.keys(reach.criteria)).toEqual([...REACH_OPTIONS]);
    expect(Object.keys(attack.criteria)).toEqual([...ATTACK_TYPE_OPTIONS]);
    expect(REACH_OPTIONS).toEqual(["one_entity", "workgroup", "organization"]);
    expect(ATTACK_TYPE_OPTIONS).toEqual([
      "host_compromise",
      "account_takeover",
      "mail_campaign",
      "exfiltration",
    ]);
  });

  it("gives every yes/no question both criteria, and every question a label", () => {
    for (const id of YESNO_QUESTION_IDS) {
      const q = CONTAINMENT_QUESTIONS[id] as Extract<JevQuestion, { type: "noul" }>;
      expect(q.criteria?.true).toMatch(/\S/);
      expect(q.criteria?.false).toMatch(/\S/);
    }
    for (const id of CONTAINMENT_QUESTION_IDS) expect(QUESTION_LABELS[id]).toMatch(/\S/);
  });

  it("says 'in progress' means at the end of the collected evidence, not live", () => {
    expect(CONTAINMENT_QUESTIONS.in_progress.instructions).toContain(
      "still in progress at the end of the collected evidence",
    );
  });

  it("passes the client's own validation and parses a full answer set", async () => {
    const seen: { body?: string } = {};
    const result = await askJev(CFG, { note: "n" }, CONTAINMENT_QUESTIONS, stubFetch(seen));
    expect(Object.keys(result.answers).sort()).toEqual([...CONTAINMENT_QUESTION_IDS].sort());
    expect(JSON.parse(seen.body!).questions.reach.type).toBe("choice");
  });
});
