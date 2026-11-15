import { describe, expect, it, vi } from "vitest";
import { PresidioApprovalRequired, type PresidioClient } from "../../../src/analysis/presidio.js";
import { AnonymizationChangedError } from "../../../src/analysis/anonRevision.js";
import type { ConverseResult, ToolTurn } from "../../../src/providers/toolCalling.js";
import {
  converseRestored,
  maskDeep,
  outboundTexts,
  type ConverseSession,
} from "../../../src/analysis/ai/converseRestored.js";
import { AiAnswerParseError, logAiUsage, recordAiCost } from "../../../src/analysis/ai/providerCall.js";
import { runAiPreview, type AiPreviewCapture } from "../../../src/analysis/ai/aiPreviewScope.js";
import {
  FakeConverser,
  HOST,
  NEW_HOST,
  final,
  newSession,
  req,
  setup,
  transcriptWith,
} from "./converseFixtures.js";

// Watson phase 5, Task 4 (D6): the Presidio gate on every send, the outbound field list, and the
// per-send bookkeeping, preview and final answer of the gated multi-turn call.

describe("converseRestored, the Presidio gate on every send", () => {
  const holding = (value: string): PresidioClient => ({
    analyze: async (text: string) =>
      text.includes(value) ? [{ entityType: "PERSON", score: 0.99, value }] : [],
  });

  it("runs over prompt + tool results; a held value throws PresidioApprovalRequired", async () => {
    const h = await setup({ presidio: holding("Zed Quill") });
    const p = new FakeConverser([final()]);
    const t = transcriptWith({ args: {}, result: "owner Zed Quill" });
    await expect(converseRestored(h.ctx, h.caseId, h.st, p, req(t), newSession())).rejects.toBeInstanceOf(
      PresidioApprovalRequired,
    );
    expect(p.sent).toHaveLength(0);
  });

  it("sees argument-only PII (a name only in a tool-call argument leaf)", async () => {
    const h = await setup({ presidio: holding("Zed Quill") });
    const p = new FakeConverser([final()]);
    const t = transcriptWith({ args: { who: { name: "Zed Quill" } }, result: "nothing" });
    await expect(converseRestored(h.ctx, h.caseId, h.st, p, req(t), newSession())).rejects.toBeInstanceOf(
      PresidioApprovalRequired,
    );
    expect(p.sent).toHaveLength(0);
  });

  it("sees thinking-only PII in readable opaque text; the signed block is not changed and the send is held", async () => {
    const h = await setup({ presidio: holding("Zed Quill") });
    const p = new FakeConverser([final()]);
    const opaque = { sig: "SIG" };
    const t: ToolTurn[] = [
      {
        role: "assistant",
        text: "",
        calls: [{ id: "c1", name: "lookup", input: {} }],
        opaque,
        opaqueText: ["maybe Zed Quill"],
      },
      { role: "tool", results: [{ id: "c1", name: "lookup", content: "r" }] },
    ];
    await expect(converseRestored(h.ctx, h.caseId, h.st, p, req(t), newSession())).rejects.toBeInstanceOf(
      PresidioApprovalRequired,
    );
    expect(p.sent).toHaveLength(0);
    expect(t[0]).toMatchObject({ opaque: { sig: "SIG" }, opaqueText: ["maybe Zed Quill"] });
  });

  it("a provider that cannot report its echoed text: readable opaque text the anonymizer would now mask holds the send", async () => {
    const h = await setup();
    const p = new FakeConverser([final()]);
    const t: ToolTurn[] = [
      {
        role: "assistant",
        text: "",
        calls: [{ id: "c1", name: "lookup", input: {} }],
        opaque: { s: 1 },
        opaqueText: [`on ${HOST}`],
      },
      { role: "tool", results: [{ id: "c1", name: "lookup", content: "r" }] },
    ];
    await expect(converseRestored(h.ctx, h.caseId, h.st, p, req(t), newSession())).rejects.toBeInstanceOf(
      AnonymizationChangedError,
    );
    expect(p.sent).toHaveLength(0);
  });
});

describe("outboundTexts and maskDeep", () => {
  it("lists prompt, assistant text, every argument leaf, every result and readable opaque text; never encrypted payloads", () => {
    const texts = outboundTexts({
      userPrompt: "P",
      transcript: [
        {
          role: "assistant",
          text: "A",
          calls: [{ id: "1", name: "n", input: { a: "L1", b: ["L2", { c: "L3" }], d: 4 } }],
          opaque: { enc: "ENCRYPTED" },
          opaqueText: ["T1"],
        },
        {
          role: "tool",
          results: [
            { id: "1", name: "n", content: "R1" },
            { id: "2", name: "n", content: "R2" },
          ],
        },
      ],
    });
    expect(texts[0]).toBe("P");
    expect(texts).toEqual(expect.arrayContaining(["A", "L1", "L2", "L3", "R1", "R2", "T1"]));
    expect(texts.join(" ")).not.toContain("ENCRYPTED");
    expect(texts).not.toContain("1");
  });

  it("maskDeep maps string leaves and keys", () => {
    expect(maskDeep((s) => s.toUpperCase(), { key: "v", n: 1, a: ["x", null, { k: "y" }] })).toEqual({
      KEY: "V",
      N: 1,
      A: ["X", null, { K: "Y" }],
    });
  });
});

describe("converseRestored, bookkeeping, preview, final answer, anonymization off", () => {
  it("records cost and usage once per send in the watson bucket", async () => {
    const h = await setup();
    const usage = { inputTokens: 10, outputTokens: 5 };
    const p = new FakeConverser([
      { text: "", calls: [{ id: "k", name: "lookup", input: {} }], usage },
      { ...final(), usage },
    ]);
    const session = newSession();
    const { result: first, session: s1 } = await converseRestored(
      h.ctx,
      h.caseId,
      h.st,
      p,
      req(),
      session,
      "watson",
    );
    const clear: ToolTurn[] = [
      first.assistant,
      { role: "tool", results: [{ id: "k", name: "lookup", content: "r" }] },
    ];
    await converseRestored(h.ctx, h.caseId, h.st, p, req(clear), s1, "watson");
    expect(h.cost.record).toHaveBeenCalledTimes(2);
    expect(h.cost.record).toHaveBeenCalledWith(h.caseId, "watson", "fake", "fake-model", usage);
  });

  it("recordAiCost and logAiUsage accept a ConverseResult", async () => {
    const h = await setup();
    const r: ConverseResult = { text: "", calls: [], usage: { inputTokens: 1, outputTokens: 2 } };
    const p = new FakeConverser([]);
    logAiUsage(h.ctx, h.caseId, "watson", p, r);
    await recordAiCost(h.ctx, h.caseId, "watson", p, r);
    expect(h.cost.record).toHaveBeenCalledTimes(1);
  });

  it("under an active AI preview it captures the first request through previewCall and calls no provider", async () => {
    const h = await setup();
    const p = new FakeConverser([final()]);
    const preview = await runAiPreview(() =>
      converseRestored(h.ctx, h.caseId, h.st, p, req(), newSession(), "watson"),
    );
    expect(preview.outcome).toBe("captured");
    expect(p.sent).toHaveLength(0);
    expect(h.cost.record).not.toHaveBeenCalled();
    const call = (preview as { call: AiPreviewCapture }).call;
    expect(call.maskedPrompt).not.toContain(HOST);
    expect(call.clearPrompt).toContain(HOST);
  });

  it("final text is parsed and restored like analyzeRestored; non-JSON → AiAnswerParseError", async () => {
    const h = await setup();
    const p = new FakeConverser([final('{"host":"ANON_HOST_1"}'), final("not json ANON_HOST_1")]);
    const { result: out } = await converseRestored(h.ctx, h.caseId, h.st, p, req(), newSession());
    expect(out.answer).toEqual({ host: HOST });
    expect(out.calls).toEqual([]);
    const err = await converseRestored(h.ctx, h.caseId, h.st, p, req(), newSession()).catch((e) => e);
    expect(err).toBeInstanceOf(AiAnswerParseError);
    expect((err as AiAnswerParseError).rawText).toContain(HOST);
  });

  it("anonymization off: clear text, no Presidio, no drift guard", async () => {
    const analyze = vi.fn(async () => []);
    const h = await setup({ anonOff: true, presidio: { analyze } });
    const p = new FakeConverser([final()]);
    const forged: ConverseSession = {
      pairs: [
        { token: "ANON_HOST_1", value: HOST, category: "HOST" },
        { token: "ANON_HOST_1", value: "other", category: "HOST" },
      ],
    };
    const t = transcriptWith({ args: { host: HOST }, result: HOST });
    await converseRestored(h.ctx, h.caseId, h.st, p, req(t), forged);
    expect(JSON.stringify(p.sent[0])).toContain(HOST);
    expect(analyze).not.toHaveBeenCalled();
  });
});

describe("converseRestored, readable reasoning the adapter will echo (controller ruling)", () => {
  const holding = (value: string): PresidioClient => ({
    analyze: async (text: string) =>
      text.includes(value) ? [{ entityType: "PERSON", score: 0.99, value }] : [],
  });
  const thinkingTurn = (thought: string): ToolTurn[] => [
    {
      role: "assistant",
      text: "",
      calls: [{ id: "c1", name: "lookup", input: {} }],
      opaque: { s: 1 },
      opaqueText: [thought],
    },
    { role: "tool", results: [{ id: "c1", name: "lookup", content: "r" }] },
  ];

  it("main path: thinking named a host in clear, a search makes it known, send 2 proceeds with the stale block dropped", async () => {
    const h = await setup();
    const p = new FakeConverser(
      [
        {
          text: "",
          calls: [{ id: "k1", name: "lookup", input: {} }],
          opaque: { s: 1 },
          opaqueText: [`look at ${NEW_HOST}`],
        },
        final(),
      ],
      { echoes: true },
    );
    const prompt = `${NEW_HOST} and ${HOST}`;
    const one = await converseRestored(h.ctx, h.caseId, h.st, p, req([], prompt), newSession());
    const clear: ToolTurn[] = [
      one.result.assistant,
      { role: "tool", results: [{ id: "k1", name: "lookup", content: `row on ${NEW_HOST}` }] },
    ];
    const two = await converseRestored(
      h.ctx,
      h.caseId,
      h.st,
      p,
      { ...req(clear, prompt), promptEntities: { hosts: [NEW_HOST], usernames: [] } },
      one.session,
    );
    expect(two.result.answer).toEqual({ ok: true });
    expect(p.sent).toHaveLength(2);
    expect(p.kept[1]).toEqual([]); // the adapter drops the block; it is never sent
  });

  it("a model-invented 8.8.8.8 in a kept block: that block is dropped and the send proceeds", async () => {
    const h = await setup();
    const p = new FakeConverser([final()], { echoes: true });
    await converseRestored(h.ctx, h.caseId, h.st, p, req(thinkingTurn("beacon to 8.8.8.8")), newSession());
    expect(p.sent).toHaveLength(1);
    expect(p.kept[0]).toEqual([]);
  });

  it("an unchanged clean block is kept", async () => {
    const h = await setup();
    const p = new FakeConverser([final()], { echoes: true });
    await converseRestored(
      h.ctx,
      h.caseId,
      h.st,
      p,
      req(thinkingTurn("thinking about ANON_HOST_1")),
      newSession(),
    );
    expect(p.kept[0]).toEqual(["thinking about ANON_HOST_1"]);
  });

  it("masking off: nothing is dropped", async () => {
    const h = await setup({ anonOff: true });
    const p = new FakeConverser([final()], { echoes: true });
    await converseRestored(h.ctx, h.caseId, h.st, p, req(thinkingTurn("beacon to 8.8.8.8")), newSession());
    expect(p.kept[0]).toEqual(["beacon to 8.8.8.8"]);
  });

  it("Presidio scans only kept text: a dropped block never holds, a kept one still does", async () => {
    const h = await setup({ presidio: holding("Zed Quill") });
    const p = new FakeConverser([final()], { echoes: true });
    await converseRestored(
      h.ctx,
      h.caseId,
      h.st,
      p,
      req(thinkingTurn("Zed Quill used 8.8.8.8")),
      newSession(),
    );
    expect(p.sent).toHaveLength(1);
    await expect(
      converseRestored(h.ctx, h.caseId, h.st, p, req(thinkingTurn("maybe Zed Quill")), newSession()),
    ).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(p.sent).toHaveLength(1);
  });
});
