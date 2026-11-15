import { describe, expect, it } from "vitest";
import { RAW_CITED_WAIT } from "../../../src/analysis/ai/watson/autoApply.js";
import { LIMIT_NOTE } from "../../../src/analysis/ai/watson/roundHop.js";
import { hopFallback } from "../../../src/analysis/ai/watson/toolStep.js";
import { ThinkingBindingError } from "../../../src/providers/toolCalling.js";
import { errorResponse, geminiWith, req } from "../../providers/toolAdapterHelpers.js";
import { Scripted, calls, forensic, reply, superSearch, toolHarness } from "./roundToolsFixtures.js";
import { lastWatsonTurn, promotionOf, raw } from "./superPromoteFixtures.js";

// Final review F1/F2: when tool mode falls back to the one-step hop, the hop keeps the evidence the
// loop showed (so a cited raw row is promoted and Auto holds what rests on it) and the lookup limit.

const refused = () => new ThinkingBindingError("must start with a thinking block");

describe("a fallback hop keeps the rows the tool loop showed (F1)", () => {
  it("Auto: a question citing raw1 after a fallback promotes raw1 and waits for the analyst", async () => {
    const hopReply = reply({
      newQuestions: [{ question: "Is raw1 exfiltration?", why: "raw1 shows rclone" }],
    });
    const p = new Scripted([calls(superSearch({ text: "rclone" })), refused()], { hop: [hopReply] });
    const h = await toolHarness(p, { mode: "auto", raw: [raw("raw1")] });
    const chat = await h.run();
    expect(p.analyzed).toHaveLength(1);
    expect((await h.row("raw1"))?.promotedAt).toBeTruthy();
    expect(promotionOf(chat)?.status).toBe("applied");
    const q = chat.proposals.find((x) => x.kind === "question_new");
    expect(q?.status).toBe("pending");
    expect(q && "rawEvidenceIds" in q ? q.rawEvidenceIds : []).toEqual(["raw1"]);
    expect(chat.turns.some((t) => t.role === "system" && t.text.includes(RAW_CITED_WAIT))).toBe(true);
    // The saved turn still records what the loop showed, for later rounds.
    expect(lastWatsonTurn(chat).lookups?.flatMap((l) => l.shownIds ?? [])).toEqual(["raw1"]);
  });

  it("a structured cite of a row the loop showed passes the hop's sanitizer", async () => {
    const answer = {
      answer: { question: "q?", status: "answered", answer: "a", pointer: "p", relatedEventIds: ["raw1"] },
    };
    const p = new Scripted([calls(superSearch({ text: "rclone" })), refused()], { hop: [reply(answer)] });
    const h = await toolHarness(p, { raw: [raw("raw1")] });
    const chat = await h.run();
    expect(lastWatsonTurn(chat).answer?.relatedEventIds).toEqual(["raw1"]);
    expect((await h.row("raw1"))?.promotedAt).toBeTruthy();
  });
});

describe("a fallback hop counts against the lookup limit (F2)", () => {
  it("cap 4: four lookups, then a binding refusal, then a hop lookup → no fifth lookup", async () => {
    const four = calls(...["a", "b", "c", "d"].map((text) => forensic({ text })));
    const hopAsk = reply({ lookup: { source: "forensic", text: "e" } });
    const p = new Scripted([four, refused()], { hop: [hopAsk, reply({ message: "should not run" })] });
    const h = await toolHarness(p, { maxToolCalls: 4 });
    const chat = await h.run();
    expect(p.sent).toHaveLength(2);
    expect(p.analyzed).toHaveLength(1);
    const turn = lastWatsonTurn(chat);
    expect(turn.lookups).toHaveLength(4);
    expect(turn.lookedUp).toBeUndefined();
    expect(turn.text).toContain(LIMIT_NOTE);
  });

  it("a fallback hop lookup that may run joins the lookup list, so the card shows it", async () => {
    const hopAsk = reply({ lookup: { source: "forensic", text: "e" } });
    const p = new Scripted([calls(forensic({ text: "a" })), refused()], { hop: [hopAsk, reply()] });
    const h = await toolHarness(p, { maxToolCalls: 4 });
    const turn = lastWatsonTurn(await h.run());
    expect(p.analyzed).toHaveLength(2);
    expect(turn.lookups).toHaveLength(2);
  });
});

describe("Gemini key, size and region 400s are not tool-mode fallbacks (F3)", () => {
  const gErr = (message: string, status: string) => ({ error: { code: 400, message, status } });
  it.each([
    gErr("API key not valid. Please pass a valid API key.", "INVALID_ARGUMENT"),
    gErr(
      "The input token count (1200000) exceeds the maximum number of tokens allowed (1048576).",
      "INVALID_ARGUMENT",
    ),
    gErr("User location is not supported for the API use.", "FAILED_PRECONDITION"),
  ])("%j → an error turn, one send, no hop, no retry", async (body) => {
    const { provider } = geminiWith([errorResponse(400, body)]);
    const err = await provider.converse(req()).catch((e: unknown) => e);
    expect(hopFallback(err)).toBeNull();
    const p = new Scripted([err as Error]);
    const h = await toolHarness(p, { retries: 3 });
    const chat = await h.run();
    expect(chat.turns.at(-1)).toMatchObject({ role: "system", error: true });
    expect(p.sent).toHaveLength(1);
    expect(p.analyzed).toHaveLength(0);
  });
});
