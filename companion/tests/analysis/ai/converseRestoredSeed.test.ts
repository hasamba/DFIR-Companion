import { describe, expect, it } from "vitest";
import { PresidioApprovalRequired, type PresidioClient } from "../../../src/analysis/presidio.js";
import { AnonymizationChangedError } from "../../../src/analysis/anonRevision.js";
import { ProviderError } from "../../../src/providers/provider.js";
import type { ConverseRequest, ToolTurn } from "../../../src/providers/toolCalling.js";
import {
  converseRestored,
  outboundTexts,
  type ConverseSession,
} from "../../../src/analysis/ai/converseRestored.js";
import {
  FakeConverser,
  HOST,
  final,
  newSession,
  req,
  setup,
  tokenFor,
  transcriptWith,
} from "./converseFixtures.js";
import { assertNoSeedInClear } from "../../../src/analysis/ai/converseMasking.js";

// Task 4 fix round 1 (review I1, I2, I3, M6): a value masked in any earlier send stays masked;
// tool-call argument keys are masked and gated; a billed failure is costed; a parse failure keeps
// the next session.

const tool = (content: string): ToolTurn => ({
  role: "tool",
  results: [{ id: "c1", name: "lookup", content }],
});
const asst: ToolTurn = { role: "assistant", text: "", calls: [{ id: "c1", name: "lookup", input: {} }] };

describe("I1: a value masked in an earlier send stays masked when the known set shrinks", () => {
  it("secret-dc-9: a per-call host in a tool result stays masked on the next send without it", async () => {
    const h = await setup();
    const p = new FakeConverser([final(), final()]);
    const t = [asst, tool("seen secret-dc-9")];
    const one = await converseRestored(
      h.ctx,
      h.caseId,
      h.st,
      p,
      { ...req(t), promptEntities: { hosts: ["secret-dc-9"], usernames: [] } },
      newSession(),
    );
    const token = tokenFor(one.session, "secret-dc-9")!;
    await converseRestored(h.ctx, h.caseId, h.st, p, req(t), one.session);
    expect(JSON.stringify(p.sent[1])).not.toContain("secret-dc-9");
    expect((p.sent[1].transcript[1] as { results: Array<{ content: string }> }).results[0].content).toBe(
      `seen ${token}`,
    );
  });

  it("beacon-srv-77: the prompt keeps the token after the per-call entity is gone", async () => {
    const h = await setup();
    const p = new FakeConverser([final(), final()]);
    const prompt = "Also seen beacon-srv-77";
    const one = await converseRestored(
      h.ctx,
      h.caseId,
      h.st,
      p,
      { ...req([], prompt), promptEntities: { hosts: ["beacon-srv-77"], usernames: [] } },
      newSession(),
    );
    await converseRestored(
      h.ctx,
      h.caseId,
      h.st,
      p,
      req([asst, tool("peer beacon-srv-77")], prompt),
      one.session,
    );
    const token = tokenFor(one.session, "beacon-srv-77")!;
    expect(p.sent[1].userPrompt).toBe(`Also seen ${token}`);
    expect(JSON.stringify(p.sent[1])).not.toContain("beacon-srv-77");
  });

  it("bare alice: a seeded username is masked as a bare word", async () => {
    const h = await setup();
    const p = new FakeConverser([final()]);
    const session: ConverseSession = { pairs: [{ token: "ANON_USER_1", value: "alice", category: "USER" }] };
    await converseRestored(
      h.ctx,
      h.caseId,
      h.st,
      p,
      req([asst, tool("alice ran it")], "Check alice now"),
      session,
    );
    expect(p.sent[0].userPrompt).toBe("Check ANON_USER_1 now");
    expect(JSON.stringify(p.sent[0])).not.toMatch(/\balice\b/);
  });

  it("final outbound check: a seed value that masking would leave clear stops the send", async () => {
    const h = await setup();
    await h.ctx.opts.discoveredStore!.suppress(h.caseId, "alice"); // "Leave visible" for alice
    const p = new FakeConverser([final()]);
    const session: ConverseSession = { pairs: [{ token: "ANON_USER_1", value: "alice", category: "USER" }] };
    await expect(
      converseRestored(h.ctx, h.caseId, h.st, p, req([], "Check alice now"), session),
    ).rejects.toBeInstanceOf(AnonymizationChangedError);
    expect(p.sent).toHaveLength(0);
  });
});

describe("R1-I1: seeded qualifiers keep whole accounts masked", () => {
  it("a resend of CORP\\Administrator, CORP\\admin and guest@corp.local proceeds; nothing seeded goes out in clear", async () => {
    const h = await setup();
    const p = new FakeConverser([final(), final()]);
    const t = [
      asst,
      tool("logon CORP\\admin, CORP\\Administrator, guest@corp.local; Administrator logged on"),
    ];
    const one = await converseRestored(h.ctx, h.caseId, h.st, p, req(t), newSession());
    expect(one.session.pairs.map((x) => x.value)).toEqual(expect.arrayContaining(["CORP", "admin"]));
    const two = await converseRestored(h.ctx, h.caseId, h.st, p, req(t), one.session);
    expect(two.result.answer).toEqual({ ok: true });
    expect(p.sent[1].transcript).toEqual(p.sent[0].transcript);
    const wire = JSON.stringify(p.sent[1]);
    expect(wire).not.toMatch(/CORP|guest@corp\.local|\\\\admin/i);
  });

  it("the outbound check: a guarded name counts only in an account form; other values as any word", () => {
    const seed: ConverseSession["pairs"] = [
      { token: "ANON_USER_1", value: "admin", category: "USER" },
      { token: "ANON_USER_2", value: "jsmith", category: "USER" },
    ];
    expect(() => assertNoSeedInClear(seed, ["Administrator and admin logged on"])).not.toThrow();
    expect(() => assertNoSeedInClear(seed, ["logon CORP\\admin"])).toThrow(AnonymizationChangedError);
    expect(() => assertNoSeedInClear(seed, ["mail admin@corp.local"])).toThrow(AnonymizationChangedError);
    expect(() => assertNoSeedInClear(seed, ["jsmith ran it"])).toThrow(AnonymizationChangedError);
  });
});

describe("I2: tool-call argument keys are masked, gated and restored", () => {
  it("masks a key holding a case value", async () => {
    const h = await setup();
    const p = new FakeConverser([final()]);
    const one = await converseRestored(
      h.ctx,
      h.caseId,
      h.st,
      p,
      req(transcriptWith({ args: { [HOST]: { [HOST]: 1 } }, result: "r" })),
      newSession(),
    );
    const token = tokenFor(one.session, HOST)!;
    const call = (p.sent[0].transcript[0] as { calls: Array<{ input: unknown }> }).calls[0];
    expect(call.input).toEqual({ [token]: { [token]: 1 } });
  });

  it("Presidio sees keys", async () => {
    const client: PresidioClient = {
      analyze: async (t) =>
        t.includes("Zed Quill") ? [{ entityType: "PERSON", score: 0.99, value: "Zed Quill" }] : [],
    };
    const h = await setup({ presidio: client });
    const p = new FakeConverser([final()]);
    await expect(
      converseRestored(
        h.ctx,
        h.caseId,
        h.st,
        p,
        req(transcriptWith({ args: { "Zed Quill": 1 }, result: "r" })),
        newSession(),
      ),
    ).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(
      outboundTexts({
        userPrompt: "p",
        transcript: [
          { role: "assistant", text: "", calls: [{ id: "1", name: "n", input: { k1: { k2: "v" } } }] },
        ],
      }),
    ).toEqual(expect.arrayContaining(["k1", "k2", "v"]));
  });

  it("restores keys in the model's calls", async () => {
    const h = await setup();
    const p = new FakeConverser([
      { text: "", calls: [{ id: "k", name: "lookup", input: { ANON_HOST_1: "ANON_HOST_1" } }] },
    ]);
    const { result } = await converseRestored(h.ctx, h.caseId, h.st, p, req(), newSession());
    expect(result.calls[0].input).toEqual({ [HOST]: HOST });
  });
});

describe("I3 and M6: billed failures and parse failures", () => {
  it("a billed provider failure records its usage", async () => {
    const h = await setup();
    const usage = { inputTokens: 100, outputTokens: 16000 };
    const p = new FakeConverser([]);
    (p as unknown as { converse: (r: ConverseRequest) => Promise<never> }).converse = async () => {
      throw Object.assign(new ProviderError("cut off", "output_limit"), { usage });
    };
    await expect(
      converseRestored(h.ctx, h.caseId, h.st, p, req(), newSession(), "watson"),
    ).rejects.toBeInstanceOf(ProviderError);
    expect(h.cost.record).toHaveBeenCalledWith(h.caseId, "watson", "fake", "fake-model", usage);
  });

  it("a final answer that fails to parse carries the next session", async () => {
    const h = await setup();
    const p = new FakeConverser([final("not json")]);
    const err = await converseRestored(h.ctx, h.caseId, h.st, p, req(), newSession()).catch(
      (e: unknown) => e,
    );
    expect((err as { session?: ConverseSession }).session?.revision).toBeTypeOf("number");
    expect(tokenFor((err as { session: ConverseSession }).session, HOST)).toMatch(/^ANON_HOST_/);
  });
});
