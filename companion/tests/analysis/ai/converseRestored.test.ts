import { describe, expect, it } from "vitest";
import type { PresidioClient } from "../../../src/analysis/presidio.js";
import { AnonymizationChangedError, bumpAnonRevision } from "../../../src/analysis/anonRevision.js";
import type { ConverseResult, ToolTurn } from "../../../src/providers/toolCalling.js";
import { converseRestored, type ConverseSession } from "../../../src/analysis/ai/converseRestored.js";
import {
  FakeConverser,
  HOST,
  NEW_HOST,
  final,
  newSession,
  req,
  setup,
  tokenFor,
  transcriptWith,
} from "./converseFixtures.js";

// Watson phase 5, Task 4 (D6): the gated multi-turn call. Every send masks the whole clear
// transcript with ONE seeded anonymizer and checks the anonymization revision.

describe("converseRestored masks the whole send with ONE anonymizer", () => {
  it("masks the prompt, earlier assistant text, tool-call args (leaf by leaf) and tool results", async () => {
    const h = await setup();
    const p = new FakeConverser([final()]);
    const session = newSession();
    const t = transcriptWith({ args: { host: HOST, list: [HOST, 3] }, result: `user bob on ${HOST}` });
    const next = await converseRestored(h.ctx, h.caseId, h.st, p, req(t), session, "watson");
    expect(session).toEqual({ pairs: [] }); // the input session is never changed
    const sent = p.sent[0];
    expect(JSON.stringify(sent)).not.toContain(HOST);
    const token = tokenFor(next.session, HOST)!;
    expect(token).toMatch(/^ANON_HOST_\d+$/);
    const asst = sent.transcript[0] as Extract<ToolTurn, { role: "assistant" }>;
    expect(asst.calls[0].input).toEqual({ host: token, list: [token, 3] });
    expect(asst.calls[0].id).toBe("c1");
    const tool = sent.transcript[1] as Extract<ToolTurn, { role: "tool" }>;
    expect(tool.results[0].content).toBe(`user bob on ${token}`);
    expect(sent.userPrompt).toBe(`What happened on ${token}?`);
    expect(Object.keys(sent)).not.toContain("promptEntities");
  });

  it("restores the model's tool-call args and text with the anonymizer of the send that produced them", async () => {
    const h = await setup();
    const p = new FakeConverser([
      {
        text: "look at ANON_HOST_1",
        calls: [{ id: "k1", name: "lookup", input: { host: "ANON_HOST_1", n: [{ h: "ANON_HOST_1" }] } }],
        opaque: { sig: "s" },
      },
    ]);
    const { result: out } = await converseRestored(h.ctx, h.caseId, h.st, p, req(), newSession(), "watson");
    expect(out.answer).toBeUndefined();
    expect(out.calls[0].input).toEqual({ host: HOST, n: [{ h: HOST }] });
    expect(out.assistant).toEqual({
      role: "assistant",
      text: `look at ${HOST}`,
      calls: out.calls,
      opaque: { sig: "s" },
    });
  });

  it("echoes opaque blocks unchanged", async () => {
    const h = await setup();
    const p = new FakeConverser([final()]);
    const opaque = { blocks: [{ type: "thinking", thinking: "x", signature: "SIG" }] };
    await converseRestored(
      h.ctx,
      h.caseId,
      h.st,
      p,
      req(transcriptWith({ args: {}, result: "r", opaque })),
      newSession(),
    );
    const asst = p.sent[0].transcript[0] as Extract<ToolTurn, { role: "assistant" }>;
    expect(asst.opaque).toEqual(opaque);
    expect(asst.opaqueText).toEqual(["thinking about ANON_HOST_1"]);
  });

  it("an unchanged prefix is byte-identical on the next send", async () => {
    const h = await setup();
    const reply1: ConverseResult = {
      text: "t ANON_HOST_1",
      calls: [{ id: "k1", name: "lookup", input: { host: "ANON_HOST_1" } }],
    };
    const p = new FakeConverser([reply1, final()]);
    const session = newSession();
    const { result: first, session: s1 } = await converseRestored(h.ctx, h.caseId, h.st, p, req(), session);
    const clear: ToolTurn[] = [
      first.assistant,
      { role: "tool", results: [{ id: "k1", name: "lookup", content: `seen ${HOST}` }] },
    ];
    await converseRestored(h.ctx, h.caseId, h.st, p, req(clear), s1);
    expect(p.sent[1].userPrompt).toBe(p.sent[0].userPrompt);
    expect(p.sent[1].transcript[0]).toEqual({ role: "assistant", text: reply1.text, calls: reply1.calls });
  });
});

describe("converseRestored, the seeded anonymizer across sends (main path)", () => {
  for (const withOpaque of [false, true]) {
    it(`a host first printed clear, then found by a search, gets a new token next send (opaque: ${withOpaque})`, async () => {
      const h = await setup();
      const p = new FakeConverser([
        {
          text: "",
          calls: [{ id: "k1", name: "lookup", input: { q: "x" } }],
          ...(withOpaque ? { opaque: { s: 1 } } : {}),
        },
        final(),
      ]);
      const session = newSession();
      const prompt = `${NEW_HOST} and ${HOST}`;
      const { result: first, session: s1 } = await converseRestored(
        h.ctx,
        h.caseId,
        h.st,
        p,
        req([], prompt),
        session,
      );
      const oldToken = tokenFor(s1, HOST)!;
      expect(p.sent[0].userPrompt).toBe(`${NEW_HOST} and ${oldToken}`);
      const clear: ToolTurn[] = [
        first.assistant,
        { role: "tool", results: [{ id: "k1", name: "lookup", content: `row on ${NEW_HOST}` }] },
      ];
      const { session: s2 } = await converseRestored(
        h.ctx,
        h.caseId,
        h.st,
        p,
        { ...req(clear, prompt), promptEntities: { hosts: [NEW_HOST], usernames: [] } },
        s1,
      );
      const newToken = tokenFor(s2, NEW_HOST)!;
      expect(tokenFor(s2, HOST)).toBe(oldToken);
      // ordering: the new name comes first in the prompt and sorts first, yet takes the higher number
      expect(Number(newToken.split("_").pop())).toBeGreaterThan(Number(oldToken.split("_").pop()));
      expect(p.sent[1].userPrompt).toBe(`${newToken} and ${oldToken}`);
      const tool = p.sent[1].transcript[1] as Extract<ToolTurn, { role: "tool" }>;
      expect(tool.results[0].content).toBe(`row on ${newToken}`);
      if (withOpaque) expect((p.sent[1].transcript[0] as { opaque?: unknown }).opaque).toEqual({ s: 1 });
    });
  }

  it("drift guard: a forged seed mismatch throws AnonymizationChangedError and sends nothing", async () => {
    const h = await setup();
    const p = new FakeConverser([final()]);
    const session: ConverseSession = {
      pairs: [
        { token: "ANON_HOST_1", value: HOST, category: "HOST" },
        { token: "ANON_HOST_1", value: "other-host", category: "HOST" },
      ],
    };
    await expect(converseRestored(h.ctx, h.caseId, h.st, p, req(), session)).rejects.toBeInstanceOf(
      AnonymizationChangedError,
    );
    expect(p.sent).toHaveLength(0);
  });
});

describe("converseRestored, revision changes", () => {
  const cases: Array<[string, { anonOff?: boolean; opaque?: boolean }]> = [
    ["with an opaque block", { opaque: true }],
    ["without one", {}],
    ["with anonymization switched off", { anonOff: true }],
  ];
  for (const [name, o] of cases) {
    it(`a revision change between two sends stops the round (${name})`, async () => {
      const h = await setup({ anonOff: o.anonOff });
      const p = new FakeConverser([
        {
          text: "",
          calls: [{ id: "k1", name: "lookup", input: {} }],
          ...(o.opaque ? { opaque: { s: 1 } } : {}),
        },
        final(),
      ]);
      const session = newSession();
      const { result: first, session: s1 } = await converseRestored(h.ctx, h.caseId, h.st, p, req(), session);
      expect(s1.revision).toBeTypeOf("number");
      bumpAnonRevision(h.caseId);
      const clear: ToolTurn[] = [
        first.assistant,
        { role: "tool", results: [{ id: "k1", name: "lookup", content: "r" }] },
      ];
      await expect(converseRestored(h.ctx, h.caseId, h.st, p, req(clear), s1)).rejects.toBeInstanceOf(
        AnonymizationChangedError,
      );
      expect(p.sent).toHaveLength(1);
    });
  }

  it("a revision change during continuation preparation (after masking, before the send) stops the round", async () => {
    let caseId = "";
    let calls = 0;
    const client: PresidioClient = {
      analyze: async () => {
        calls++;
        if (calls === 2) bumpAnonRevision(caseId);
        return [];
      },
    };
    const h = await setup({ presidio: client });
    caseId = h.caseId;
    const p = new FakeConverser([{ text: "", calls: [{ id: "k1", name: "lookup", input: {} }] }, final()]);
    const session = newSession();
    const { result: first, session: s1 } = await converseRestored(h.ctx, h.caseId, h.st, p, req(), session);
    const clear: ToolTurn[] = [
      first.assistant,
      { role: "tool", results: [{ id: "k1", name: "lookup", content: "r" }] },
    ];
    await expect(converseRestored(h.ctx, h.caseId, h.st, p, req(clear), s1)).rejects.toBeInstanceOf(
      AnonymizationChangedError,
    );
    expect(p.sent).toHaveLength(1);
  });

  it("the first send re-masks when the revision changes during preparation; gives up after 3", async () => {
    let caseId = "";
    let calls = 0;
    let bumpUntil = 1;
    const client: PresidioClient = {
      analyze: async () => {
        calls++;
        if (calls <= bumpUntil) bumpAnonRevision(caseId);
        return [];
      },
    };
    const h = await setup({ presidio: client });
    caseId = h.caseId;
    const p = new FakeConverser([final(), final()]);
    await converseRestored(h.ctx, h.caseId, h.st, p, req(), newSession());
    expect(calls).toBe(2);
    expect(p.sent).toHaveLength(1);
    calls = 0;
    bumpUntil = 99;
    await expect(converseRestored(h.ctx, h.caseId, h.st, p, req(), newSession())).rejects.toBeInstanceOf(
      AnonymizationChangedError,
    );
    expect(calls).toBe(3);
    expect(p.sent).toHaveLength(1);
  });
});

describe("converseRestored applies the Watson mask roster on every send", () => {
  it("a roster host found only in a tool result is tokenized in the sent transcript", async () => {
    const h = await setup({ roster: ["roster-only-host"] });
    const p = new FakeConverser([final()]);
    const session = newSession();
    const t = transcriptWith({ args: {}, result: "seen on roster-only-host" });
    const next = await converseRestored(h.ctx, h.caseId, h.st, p, req(t), session);
    expect(JSON.stringify(p.sent[0])).not.toContain("roster-only-host");
    expect(tokenFor(next.session, "roster-only-host")).toMatch(/^ANON_HOST_\d+$/);
  });
});
