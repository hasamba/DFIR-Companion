// Task 4 (D4, D6b): one collector over every reply field that can reach the case, and the pure
// settle step that keeps an item only when every raw row it references was promoted.
import { describe, expect, it } from "vitest";
import {
  collectRawRefs,
  earlierShownIds,
  mentionedIds,
  refKey,
  settleRawRefs,
} from "../../../src/analysis/ai/watson/rawReferences.js";
import type { WatsonReply } from "../../../src/analysis/ai/watson/replySchema.js";
import type { WatsonFindingDraft, WatsonStepDraft } from "../../../src/analysis/ai/watson/writesSchema.js";
import type { WatsonChat, WatsonTurn } from "../../../src/analysis/ai/watson/types.js";

const f: WatsonFindingDraft = {
  severity: "High",
  title: "Credential dump",
  description: "",
  mitreTechniques: [],
  eventIds: [],
  pasteLines: [],
};
const s: WatsonStepDraft = { priority: "high", action: "Collect memory", rationale: "", pointer: "" };

function reply(over: Partial<WatsonReply> = {}): WatsonReply {
  return {
    message: "",
    workingOn: "",
    learned: "",
    questionUpdates: [],
    newQuestions: [],
    request: null,
    search: null,
    lookup: null,
    memory: "",
    answer: null,
    writes: { findings: [], nextSteps: [], report: [] },
    ...over,
  };
}

function turn(id: string, shownIds?: string[]): WatsonTurn {
  return {
    id,
    at: "2026-11-14T10:00:00Z",
    role: "watson",
    text: "",
    ...(shownIds
      ? { lookedUp: { shown: shownIds.length, matched: shownIds.length, what: "x", shownIds } }
      : {}),
  };
}

const answer = (
  over: Partial<NonNullable<WatsonReply["answer"]>> = {},
): NonNullable<WatsonReply["answer"]> => ({
  question: "Who logged on?",
  status: "answered",
  answer: "",
  pointer: "",
  relatedEventIds: [],
  ...over,
});

describe("mentionedIds", () => {
  it("matches whole tokens only", () => {
    expect(mentionedIds("rows raw1, raw10 and [raw1]", new Set(["raw1", "raw"]))).toEqual(["raw1"]);
  });
  it("treats an id at a sentence end as a mention, but not an id inside a longer dotted token", () => {
    expect(mentionedIds("It was raw1.", new Set(["raw1"]))).toEqual(["raw1"]);
    expect(mentionedIds("see raw1.5 and raw1:x", new Set(["raw1"]))).toEqual([]);
  });
  it("finds ids at the start and end of the text, and ids with punctuation inside them", () => {
    expect(mentionedIds("ev:1/a then evt-2", new Set(["ev:1/a", "evt-2"]))).toEqual(["ev:1/a", "evt-2"]);
  });
  // Ruling 2 (Task 4 review M1): a model writes ids after a label, after an ellipsis, in a range, and
  // straight against the next sentence.
  it("counts an id after ':' or an ellipsis", () => {
    const ids = new Set(["raw1", "st-row-17"]);
    expect(mentionedIds("row:raw1", ids)).toEqual(["raw1"]);
    expect(mentionedIds("see ...raw1 then", ids)).toEqual(["raw1"]);
    expect(mentionedIds("rows: …st-row-17", ids)).toEqual(["st-row-17"]);
    expect(mentionedIds("event:st-row-17", ids)).toEqual(["st-row-17"]);
  });
  it("counts both ends of a range or a joined pair of ids", () => {
    const ids = new Set(["raw1", "raw2", "raw3", "st-row-17", "st-row-18"]);
    expect(mentionedIds("raw1-raw3", ids)).toEqual(["raw1", "raw3"]);
    expect(mentionedIds("raw1:raw2", ids)).toEqual(["raw1", "raw2"]);
    expect(mentionedIds("rows st-row-17-st-row-18.", ids)).toEqual(["st-row-17", "st-row-18"]);
  });
  it("counts an id at a sentence end with no space after the full stop", () => {
    expect(mentionedIds("It was raw1.Next it ran", new Set(["raw1"]))).toEqual(["raw1"]);
    expect(mentionedIds("It was st-row-17.The", new Set(["st-row-17"]))).toEqual(["st-row-17"]);
  });
  it("still refuses an id inside a longer token", () => {
    const ids = new Set(["raw1"]);
    expect(mentionedIds("raw1.5", ids)).toEqual([]);
    expect(mentionedIds("raw10", ids)).toEqual([]);
    expect(mentionedIds("raw1:x", ids)).toEqual([]);
    expect(mentionedIds("xraw1 and raw1_b", ids)).toEqual([]);
  });
  // Task 5 review I2: a raw id joined to anything that is not a letter, digit or underscore is its own
  // token-part, whatever the other side is (a forensic id, a word) — only "raw1.5" stays a non-match.
  it("finds a raw id joined to a forensic id or a word", () => {
    const ids = new Set(["raw1"]);
    for (const text of ["e1-raw1", "raw1-e1", "e1..raw1", "raw1-related", "Activity spans e1-raw1."]) {
      expect(mentionedIds(text, ids), text).toEqual(["raw1"]);
    }
  });
});

describe("earlierShownIds", () => {
  it("collects every id earlier super-timeline searches showed", () => {
    const chat: Pick<WatsonChat, "turns"> = {
      turns: [turn("t1", ["raw7", "raw8"]), turn("t2"), turn("t3", ["raw9"])],
    };
    expect([...earlierShownIds(chat)].sort()).toEqual(["raw7", "raw8", "raw9"]);
  });
});

describe("collectRawRefs", () => {
  it("finds ids in every case-bound field, not in message, learned or memory", () => {
    const raw = new Set(["raw1"]);
    const r = reply({
      message: "raw1 is benign",
      learned: "raw1",
      memory: "raw1",
      newQuestions: [{ question: "Who ran raw1?", why: "" }],
      writes: {
        findings: [{ ...f, eventIds: ["e1"], description: "see raw1" }],
        nextSteps: [{ ...s, pointer: "raw1" }],
        report: [],
      },
    });
    expect(
      collectRawRefs(r, raw)
        .map((x) => x.item.kind)
        .sort(),
    ).toEqual(["finding", "newQuestion", "nextStep"]);
  });

  it("reads structured ids and every text field of each item", () => {
    const raw = new Set(["a", "b", "c", "d", "e", "g", "h"]);
    const r = reply({
      answer: answer({ relatedEventIds: ["a"], pointer: "b" }),
      questionUpdates: [{ questionId: "q1", status: "answered", answer: "", pointer: "c" }],
      newQuestions: [{ question: "", why: "because d" }],
      writes: {
        findings: [{ ...f, title: "e", eventIds: ["a"] }],
        nextSteps: [{ ...s, rationale: "g" }],
        report: [{ field: "conclusions", text: "h and h" }],
      },
    });
    expect(collectRawRefs(r, raw)).toEqual([
      { item: { kind: "answer" }, ids: ["a", "b"] },
      { item: { kind: "questionUpdate", index: 0 }, ids: ["c"] },
      { item: { kind: "newQuestion", index: 0 }, ids: ["d"] },
      { item: { kind: "finding", index: 0 }, ids: ["a", "e"] },
      { item: { kind: "nextStep", index: 0 }, ids: ["g"] },
      { item: { kind: "report", index: 0 }, ids: ["h"] },
    ]);
  });
});

describe("settleRawRefs", () => {
  it("drops a mixed forensic/raw finding whole when its raw id did not land", () => {
    const r = reply({
      writes: { findings: [{ ...f, eventIds: ["e1", "raw1"] }], nextSteps: [], report: [] },
    });
    const refs = collectRawRefs(r, new Set(["raw1"]));
    const out = settleRawRefs(r, refs, new Map());
    expect(out.reply.writes.findings).toHaveLength(0);
    expect(out.dropped).toBe(1);
  });

  it("drops a question update, new question, next step and report item that name an id from an earlier search", () => {
    const chat = { turns: [turn("t1", ["raw7"])] };
    const r = reply({
      questionUpdates: [
        { questionId: "q1", status: "answered", answer: "raw7 shows it", pointer: "" },
        { questionId: "q2", status: "answered", answer: "clean", pointer: "" },
      ],
      newQuestions: [{ question: "Why raw7?", why: "" }],
      writes: {
        findings: [],
        nextSteps: [{ ...s, action: "Check raw7" }],
        report: [{ field: "conclusions", text: "Per raw7 the host fell." }],
      },
    });
    const out = settleRawRefs(r, collectRawRefs(r, earlierShownIds(chat)), new Map());
    expect(out.dropped).toBe(4);
    expect(out.reply.questionUpdates.map((u) => u.questionId)).toEqual(["q2"]);
    expect(out.reply.newQuestions).toEqual([]);
    expect(out.reply.writes.nextSteps).toEqual([]);
    expect(out.reply.writes.report).toEqual([]);
  });

  it("leaves a fabricated id that was never shown alone (not recognised), and drops nothing for it", () => {
    const r = reply({ writes: { findings: [], nextSteps: [{ ...s, action: "Check fake99" }], report: [] } });
    const refs = collectRawRefs(r, new Set(["raw1"]));
    expect(refs).toEqual([]);
    const out = settleRawRefs(r, refs, new Map());
    expect(out.dropped).toBe(0);
    expect(out.reply).toEqual(r);
  });

  it("works with no search this round and with a zero-row search (earlier ids still checked)", () => {
    const r = reply({
      newQuestions: [
        { question: "Who ran raw7?", why: "" },
        { question: "Any lateral?", why: "" },
      ],
    });
    const noSearch = earlierShownIds({ turns: [turn("t1", ["raw7"]), turn("t2")] });
    const zeroRows = earlierShownIds({ turns: [turn("t1", ["raw7"]), turn("t2", [])] });
    for (const raw of [noSearch, zeroRows]) {
      const out = settleRawRefs(r, collectRawRefs(r, raw), new Map());
      expect(out.dropped).toBe(1);
      expect(out.reply.newQuestions.map((q) => q.question)).toEqual(["Any lateral?"]);
    }
  });

  it("keeps the answer text but removes an unlanded raw id from relatedEventIds", () => {
    const r = reply({ answer: answer({ answer: "raw1 is the logon", relatedEventIds: ["e1", "raw1"] }) });
    const out = settleRawRefs(r, collectRawRefs(r, new Set(["raw1"])), new Map());
    expect(out.dropped).toBe(0);
    expect(out.reply.answer).toEqual(answer({ answer: "raw1 is the logon", relatedEventIds: ["e1"] }));
    expect(out.evidence.size).toBe(0);
  });

  it("rewrites landed ids to their canonical id and reports rawEvidenceIds per surviving item", () => {
    const r = reply({
      answer: answer({ relatedEventIds: ["raw1", "e1"] }),
      writes: {
        findings: [
          { ...f, title: "Dropped", eventIds: ["raw2"] },
          { ...f, title: "Kept", eventIds: ["e1", "raw1"], description: "and raw3" },
        ],
        nextSteps: [{ ...s, action: "Pull raw3" }],
        report: [],
      },
    });
    const landed = new Map([
      ["raw1", "canon1"],
      ["raw3", "canon3"],
    ]);
    const out = settleRawRefs(r, collectRawRefs(r, new Set(["raw1", "raw2", "raw3"])), landed);
    expect(out.dropped).toBe(1);
    expect(out.reply.answer?.relatedEventIds).toEqual(["canon1", "e1"]);
    expect(out.reply.writes.findings.map((x) => [x.title, x.eventIds])).toEqual([["Kept", ["e1", "canon1"]]]);
    expect(out.reply.writes.nextSteps.map((x) => x.action)).toEqual(["Pull raw3"]);
    // Keys use the surviving reply's indices: the kept finding is now findings[0].
    expect(out.evidence).toEqual(
      new Map([
        [refKey({ kind: "answer" }), ["canon1"]],
        [refKey({ kind: "finding", index: 0 }), ["canon1", "canon3"]],
        [refKey({ kind: "nextStep", index: 0 }), ["canon3"]],
      ]),
    );
  });

  it("dedupes a structured citation that maps onto an id the item already cites", () => {
    const r = reply({
      writes: { findings: [{ ...f, eventIds: ["e1", "raw1"] }], nextSteps: [], report: [] },
    });
    const out = settleRawRefs(r, collectRawRefs(r, new Set(["raw1"])), new Map([["raw1", "e1"]]));
    expect(out.reply.writes.findings[0]?.eventIds).toEqual(["e1"]);
  });

  it("does not mutate the reply it was given", () => {
    const r = reply({ writes: { findings: [{ ...f, eventIds: ["raw1"] }], nextSteps: [], report: [] } });
    const before = JSON.stringify(r);
    settleRawRefs(r, collectRawRefs(r, new Set(["raw1"])), new Map([["raw1", "c1"]]));
    expect(JSON.stringify(r)).toBe(before);
  });
});
